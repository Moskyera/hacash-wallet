use std::ffi::c_void;
use std::fs::File;
use std::mem::{offset_of, size_of};
use std::os::windows::io::{AsRawHandle, FromRawHandle};
#[cfg(feature = "listener")]
use std::ptr::null;
use std::ptr::null_mut;
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};
#[cfg(feature = "listener")]
use windows_sys::Win32::Foundation::GENERIC_READ;
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_IO_PENDING, ERROR_PIPE_CONNECTED, GetLastError, HANDLE,
    INVALID_HANDLE_VALUE, LocalFree, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
    ConvertStringSidToSidW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{
    GetTokenInformation, IsValidSid, PSECURITY_DESCRIPTOR, PSID, SECURITY_ATTRIBUTES,
    SID_AND_ATTRIBUTES, TOKEN_GROUPS, TOKEN_QUERY, TOKEN_USER, TokenGroups, TokenUser,
};
#[cfg(feature = "listener")]
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, OPEN_EXISTING, SECURITY_IMPERSONATION, SECURITY_SQOS_PRESENT,
};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED, FILE_GENERIC_READ, FILE_WRITE_DATA,
    PIPE_ACCESS_DUPLEX, ReadFile, WriteFile,
};
use windows_sys::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, ImpersonateNamedPipeClient,
    PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_WAIT,
};
use windows_sys::Win32::System::SystemServices::SE_GROUP_LOGON_ID;
use windows_sys::Win32::System::Threading::{
    CreateEventW, GetCurrentProcess, GetCurrentThread, INFINITE, OpenProcessToken, OpenThreadToken,
    WaitForSingleObject,
};

use crate::error::{ConnectorError, ConnectorResult};
use crate::framing::FrameCodec;
use crate::transport::ListenerPolicy;

pub const PIPE_NAMESPACE_PREFIX: &str = r"\\.\pipe\hpay-agent-v1-";
const PIPE_BUFFER_BYTES: u32 = 64 * 1024;
const PIPE_DEFAULT_TIMEOUT_MS: u32 = 5_000;
const MAX_PIPE_IO_TIMEOUT: Duration = Duration::from_secs(30);
const CANCEL_SETTLE_TIMEOUT_MS: u32 = 5_000;
const CLIENT_ACCESS_MASK: u32 = FILE_GENERIC_READ | FILE_WRITE_DATA;

#[derive(Debug, Clone)]
pub struct WindowsNamedPipeConfig {
    pub policy: ListenerPolicy,
    pipe_name: String,
    owner_sid: String,
    logon_sid: String,
}

impl WindowsNamedPipeConfig {
    pub fn for_current_process(instance_suffix: &str) -> ConnectorResult<Self> {
        validate_instance_suffix(instance_suffix)?;
        let identity = current_process_identity()?;
        Ok(Self {
            policy: ListenerPolicy::default(),
            pipe_name: format!(
                "{PIPE_NAMESPACE_PREFIX}{}",
                instance_suffix.to_ascii_lowercase()
            ),
            owner_sid: identity.user_sid,
            logon_sid: identity.logon_sid,
        })
    }

    pub fn pipe_name(&self) -> &str {
        &self.pipe_name
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ListenerState {
    Listening,
    Connected,
    Poisoned,
}

#[derive(Debug)]
pub struct WindowsNamedPipeListener {
    config: WindowsNamedPipeConfig,
    pipe: File,
    state: ListenerState,
}

impl WindowsNamedPipeListener {
    pub fn bind(config: &WindowsNamedPipeConfig) -> ConnectorResult<Self> {
        config.policy.require_enabled()?;
        if !config.pipe_name.starts_with(PIPE_NAMESPACE_PREFIX) {
            return Err(ConnectorError::InsecureLocalEndpoint);
        }
        let current = current_process_identity()?;
        if current.user_sid != config.owner_sid || current.logon_sid != config.logon_sid {
            return Err(ConnectorError::InsecureLocalEndpoint);
        }
        Ok(Self {
            pipe: create_first_pipe(config)?,
            config: config.clone(),
            state: ListenerState::Listening,
        })
    }

    pub fn accept(&mut self) -> ConnectorResult<WindowsNamedPipeConnection<'_>> {
        self.accept_until(None)
    }

    /// Waits for one client without allowing a disabled connector worker to
    /// remain stuck forever in accept. A timeout leaves the protected first
    /// pipe instance reusable and never closes the endpoint name.
    pub fn accept_timeout(
        &mut self,
        timeout: Duration,
    ) -> ConnectorResult<WindowsNamedPipeConnection<'_>> {
        self.accept_until(Some(io_deadline(timeout)?))
    }

    fn accept_until(
        &mut self,
        deadline: Option<Instant>,
    ) -> ConnectorResult<WindowsNamedPipeConnection<'_>> {
        if self.state != ListenerState::Listening {
            return Err(ConnectorError::InsecureLocalEndpoint);
        }
        let handle = self.pipe.as_raw_handle() as HANDLE;
        if let Err(error) = connect_pipe(handle, deadline) {
            if error == ConnectorError::Expired {
                // SAFETY: cancellation has settled before connect_pipe returns.
                // Disconnecting is harmless when no client won the race and
                // fail-closed if one arrived at the timeout boundary.
                unsafe {
                    DisconnectNamedPipe(handle);
                }
                return Err(error);
            }
            self.state = ListenerState::Poisoned;
            return Err(error);
        }
        let peer_identity_sha256 = match verify_connected_client(handle, &self.config) {
            Ok(peer_identity_sha256) => peer_identity_sha256,
            Err(error) => {
                if !disconnect_pipe(handle) {
                    self.state = ListenerState::Poisoned;
                }
                return Err(error);
            }
        };
        self.state = ListenerState::Connected;
        Ok(WindowsNamedPipeConnection {
            listener: self,
            peer_identity_sha256,
        })
    }

    pub fn pipe_name(&self) -> &str {
        &self.config.pipe_name
    }
}

pub struct WindowsNamedPipeConnection<'listener> {
    listener: &'listener mut WindowsNamedPipeListener,
    peer_identity_sha256: String,
}

impl std::fmt::Debug for WindowsNamedPipeConnection<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("WindowsNamedPipeConnection")
            .field("pipe_name", &self.listener.config.pipe_name)
            .finish_non_exhaustive()
    }
}

impl WindowsNamedPipeConnection<'_> {
    /// SHA-256 commitment to the OS-authenticated user and logon-session SIDs.
    /// Raw SIDs are never exposed outside this transport module.
    pub fn peer_identity_sha256(&self) -> &str {
        &self.peer_identity_sha256
    }

    /// Reads one bounded protocol frame using one deadline for the complete
    /// prefix and payload. Raw blocking reads are deliberately not exposed.
    pub fn read_frame(
        &mut self,
        codec: &FrameCodec,
        timeout: Duration,
    ) -> ConnectorResult<Vec<u8>> {
        let deadline = io_deadline(timeout)?;
        let mut prefix = [0_u8; 4];
        read_exact_until(
            self.listener.pipe.as_raw_handle() as HANDLE,
            &mut prefix,
            deadline,
        )?;
        let payload_bytes = u32::from_be_bytes(prefix) as usize;
        if payload_bytes == 0 {
            return Err(ConnectorError::InvalidFrame);
        }
        if payload_bytes > codec.max_frame_bytes() {
            return Err(ConnectorError::FrameTooLarge);
        }
        let mut payload = vec![0_u8; payload_bytes];
        read_exact_until(
            self.listener.pipe.as_raw_handle() as HANDLE,
            &mut payload,
            deadline,
        )?;
        Ok(payload)
    }

    /// Writes one bounded protocol frame using one deadline for the complete
    /// frame. Raw blocking writes are deliberately not exposed.
    pub fn write_frame(
        &mut self,
        codec: &FrameCodec,
        payload: &[u8],
        timeout: Duration,
    ) -> ConnectorResult<()> {
        let deadline = io_deadline(timeout)?;
        let frame = codec.encode(payload)?;
        write_all_until(
            self.listener.pipe.as_raw_handle() as HANDLE,
            &frame,
            deadline,
        )
    }
}

impl Drop for WindowsNamedPipeConnection<'_> {
    fn drop(&mut self) {
        let handle = self.listener.pipe.as_raw_handle() as HANDLE;
        self.listener.state = if disconnect_pipe(handle) {
            ListenerState::Listening
        } else {
            ListenerState::Poisoned
        };
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct WindowsTokenIdentity {
    user_sid: String,
    logon_sid: String,
}

pub fn current_process_user_sid() -> ConnectorResult<String> {
    Ok(current_process_identity()?.user_sid)
}

pub fn current_process_logon_sid() -> ConnectorResult<String> {
    Ok(current_process_identity()?.logon_sid)
}

fn current_process_identity() -> ConnectorResult<WindowsTokenIdentity> {
    let mut token: HANDLE = null_mut();
    // SAFETY: the pseudo process handle is valid for this process and token is
    // writable HANDLE storage.
    let opened =
        unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token as *mut HANDLE) };
    if opened == 0 || token.is_null() {
        return Err(ConnectorError::Io);
    }
    let token = OwnedHandle(token);
    token_identity(token.0)
}

fn create_first_pipe(config: &WindowsNamedPipeConfig) -> ConnectorResult<File> {
    let descriptor = SecurityDescriptor::session_only(&config.logon_sid)?;
    let security_attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.0.cast(),
        bInheritHandle: 0,
    };
    let pipe_name = wide_null(&config.pipe_name);
    // SAFETY: all pointers remain valid for the call. The descriptor is
    // self-relative storage allocated by LocalAlloc.
    let handle = unsafe {
        CreateNamedPipeW(
            pipe_name.as_ptr(),
            PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_OVERLAPPED,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            1,
            PIPE_BUFFER_BYTES,
            PIPE_BUFFER_BYTES,
            PIPE_DEFAULT_TIMEOUT_MS,
            &security_attributes,
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(ConnectorError::InsecureLocalEndpoint);
    }
    // SAFETY: CreateNamedPipeW returned a unique owned HANDLE which is
    // compatible with File and must be closed exactly once.
    Ok(unsafe { File::from_raw_handle(handle.cast()) })
}

fn verify_connected_client(
    handle: HANDLE,
    expected: &WindowsNamedPipeConfig,
) -> ConnectorResult<String> {
    // SAFETY: handle is a connected server-side named-pipe handle.
    if unsafe { ImpersonateNamedPipeClient(handle) } == 0 {
        return Err(ConnectorError::UnauthorizedPeer);
    }
    let guard = ImpersonationGuard { active: true };
    let mut token: HANDLE = null_mut();
    // SAFETY: after successful impersonation, the current thread has a client
    // token. The output points to writable HANDLE storage.
    let opened = unsafe {
        OpenThreadToken(
            GetCurrentThread(),
            TOKEN_QUERY,
            1,
            &mut token as *mut HANDLE,
        )
    };
    if opened == 0 || token.is_null() {
        return Err(ConnectorError::UnauthorizedPeer);
    }
    let token = OwnedHandle(token);
    let actual = token_identity(token.0)?;
    guard.revert();
    if actual.user_sid != expected.owner_sid || actual.logon_sid != expected.logon_sid {
        return Err(ConnectorError::UnauthorizedPeer);
    }
    Ok(windows_peer_identity_sha256(&actual))
}

fn windows_peer_identity_sha256(identity: &WindowsTokenIdentity) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"HPAY/LOCAL-PEER/WINDOWS-SID-LOGON/V1");
    hasher.update((identity.user_sid.len() as u64).to_be_bytes());
    hasher.update(identity.user_sid.as_bytes());
    hasher.update((identity.logon_sid.len() as u64).to_be_bytes());
    hasher.update(identity.logon_sid.as_bytes());
    hex::encode(hasher.finalize())
}

fn token_identity(token: HANDLE) -> ConnectorResult<WindowsTokenIdentity> {
    let user_storage = query_token_information(token, TokenUser)?;
    // SAFETY: query_token_information returns aligned storage containing a
    // complete TOKEN_USER value for the requested class.
    let token_user = unsafe { &*(user_storage.as_ptr().cast::<TOKEN_USER>()) };
    let user_sid = sid_to_string(token_user.User.Sid)?;

    let groups_storage = query_token_information(token, TokenGroups)?;
    // SAFETY: the aligned storage contains a complete TOKEN_GROUPS header.
    let groups = unsafe { &*(groups_storage.as_ptr().cast::<TOKEN_GROUPS>()) };
    let group_count =
        usize::try_from(groups.GroupCount).map_err(|_| ConnectorError::UnauthorizedPeer)?;
    let required = offset_of!(TOKEN_GROUPS, Groups)
        .checked_add(
            group_count
                .checked_mul(size_of::<SID_AND_ATTRIBUTES>())
                .ok_or(ConnectorError::UnauthorizedPeer)?,
        )
        .ok_or(ConnectorError::UnauthorizedPeer)?;
    if group_count == 0 || required > groups_storage.len() * size_of::<usize>() {
        return Err(ConnectorError::UnauthorizedPeer);
    }
    // SAFETY: the variable-length array bound was checked against the returned
    // token-information allocation above.
    let entries = unsafe { std::slice::from_raw_parts(groups.Groups.as_ptr(), group_count) };
    let logon_mask = SE_GROUP_LOGON_ID as u32;
    let mut logon_sids = entries
        .iter()
        .filter(|entry| entry.Attributes & logon_mask == logon_mask)
        .map(|entry| sid_to_string(entry.Sid));
    let logon_sid = logon_sids
        .next()
        .ok_or(ConnectorError::UnauthorizedPeer)??;
    if logon_sids.next().is_some() {
        return Err(ConnectorError::UnauthorizedPeer);
    }
    Ok(WindowsTokenIdentity {
        user_sid,
        logon_sid,
    })
}

fn query_token_information(token: HANDLE, information_class: i32) -> ConnectorResult<Vec<usize>> {
    let mut required = 0_u32;
    // SAFETY: the null-buffer call obtains the required byte length.
    unsafe {
        GetTokenInformation(token, information_class, null_mut(), 0, &mut required);
    }
    if required == 0 {
        return Err(ConnectorError::UnauthorizedPeer);
    }
    let required_usize = usize::try_from(required).map_err(|_| ConnectorError::UnauthorizedPeer)?;
    let words = required_usize
        .checked_add(size_of::<usize>() - 1)
        .ok_or(ConnectorError::UnauthorizedPeer)?
        / size_of::<usize>();
    let mut storage = vec![0_usize; words];
    let available = u32::try_from(storage.len() * size_of::<usize>())
        .map_err(|_| ConnectorError::UnauthorizedPeer)?;
    // SAFETY: storage is aligned and writable for available bytes, and token
    // is open with TOKEN_QUERY.
    let read = unsafe {
        GetTokenInformation(
            token,
            information_class,
            storage.as_mut_ptr().cast(),
            available,
            &mut required,
        )
    };
    if read == 0 || required > available {
        return Err(ConnectorError::UnauthorizedPeer);
    }
    Ok(storage)
}

fn sid_to_string(sid: PSID) -> ConnectorResult<String> {
    if sid.is_null() {
        return Err(ConnectorError::UnauthorizedPeer);
    }
    // SAFETY: the SID came from a successful token-information query.
    if unsafe { IsValidSid(sid) } == 0 {
        return Err(ConnectorError::UnauthorizedPeer);
    }
    let mut string_sid = null_mut();
    // SAFETY: sid is valid and the output points to writable PWSTR storage.
    if unsafe { ConvertSidToStringSidW(sid, &mut string_sid) } == 0 || string_sid.is_null() {
        return Err(ConnectorError::UnauthorizedPeer);
    }
    Ok(LocalWideString(string_sid).decode())
}

fn canonical_sid(value: &str) -> ConnectorResult<String> {
    if value.is_empty() || value.len() > 256 || value.contains('\0') {
        return Err(ConnectorError::InvalidIdentifier);
    }
    let encoded = wide_null(value);
    let mut sid = null_mut();
    // SAFETY: encoded is null-terminated and sid is writable PSID storage.
    if unsafe { ConvertStringSidToSidW(encoded.as_ptr(), &mut sid) } == 0 || sid.is_null() {
        return Err(ConnectorError::InvalidIdentifier);
    }
    let sid = LocalSid(sid);
    sid_to_string(sid.0).map_err(|_| ConnectorError::InvalidIdentifier)
}

fn validate_instance_suffix(value: &str) -> ConnectorResult<()> {
    if value.len() != 32 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(ConnectorError::InvalidIdentifier);
    }
    Ok(())
}

fn disconnect_pipe(handle: HANDLE) -> bool {
    // SAFETY: handle is an owned server-side named-pipe handle.
    unsafe { DisconnectNamedPipe(handle) != 0 }
}

fn connect_pipe(handle: HANDLE, deadline: Option<Instant>) -> ConnectorResult<()> {
    let mut operation = OverlappedOperation::new()?;
    // SAFETY: handle is an open server-side pipe and operation remains alive
    // until completion. This handle was created with FILE_FLAG_OVERLAPPED.
    let connected = unsafe { ConnectNamedPipe(handle, &mut operation.overlapped) };
    if connected != 0 {
        return Ok(());
    }
    // SAFETY: GetLastError immediately follows the failed call.
    match unsafe { GetLastError() } {
        ERROR_PIPE_CONNECTED => Ok(()),
        ERROR_IO_PENDING => operation.finish(handle, deadline).map(|_| ()),
        _ => Err(ConnectorError::Io),
    }
}

fn io_deadline(timeout: Duration) -> ConnectorResult<Instant> {
    if timeout.is_zero() || timeout > MAX_PIPE_IO_TIMEOUT {
        return Err(ConnectorError::InvalidTimeWindow);
    }
    Instant::now()
        .checked_add(timeout)
        .ok_or(ConnectorError::InvalidTimeWindow)
}

fn read_exact_until(handle: HANDLE, buffer: &mut [u8], deadline: Instant) -> ConnectorResult<()> {
    let mut offset = 0;
    while offset < buffer.len() {
        let read = read_once_until(handle, &mut buffer[offset..], deadline)?;
        if read == 0 {
            return Err(ConnectorError::Io);
        }
        offset = offset.checked_add(read).ok_or(ConnectorError::Io)?;
    }
    Ok(())
}

fn write_all_until(handle: HANDLE, buffer: &[u8], deadline: Instant) -> ConnectorResult<()> {
    let mut offset = 0;
    while offset < buffer.len() {
        let written = write_once_until(handle, &buffer[offset..], deadline)?;
        if written == 0 {
            return Err(ConnectorError::Io);
        }
        offset = offset.checked_add(written).ok_or(ConnectorError::Io)?;
    }
    Ok(())
}

fn read_once_until(handle: HANDLE, buffer: &mut [u8], deadline: Instant) -> ConnectorResult<usize> {
    let length = u32::try_from(buffer.len()).map_err(|_| ConnectorError::FrameTooLarge)?;
    let mut operation = OverlappedOperation::new()?;
    // SAFETY: buffer and operation remain valid until the operation completes
    // or cancellation has been observed.
    let started = unsafe {
        ReadFile(
            handle,
            buffer.as_mut_ptr(),
            length,
            null_mut(),
            &mut operation.overlapped,
        )
    };
    if started == 0 {
        // SAFETY: GetLastError immediately follows the failed call.
        let error = unsafe { GetLastError() };
        if error != ERROR_IO_PENDING {
            return Err(ConnectorError::Io);
        }
    }
    operation
        .finish(handle, Some(deadline))
        .and_then(|read| usize::try_from(read).map_err(|_| ConnectorError::Io))
}

fn write_once_until(handle: HANDLE, buffer: &[u8], deadline: Instant) -> ConnectorResult<usize> {
    let length = u32::try_from(buffer.len()).map_err(|_| ConnectorError::FrameTooLarge)?;
    let mut operation = OverlappedOperation::new()?;
    // SAFETY: buffer and operation remain valid until the operation completes
    // or cancellation has been observed.
    let started = unsafe {
        WriteFile(
            handle,
            buffer.as_ptr(),
            length,
            null_mut(),
            &mut operation.overlapped,
        )
    };
    if started == 0 {
        // SAFETY: GetLastError immediately follows the failed call.
        let error = unsafe { GetLastError() };
        if error != ERROR_IO_PENDING {
            return Err(ConnectorError::Io);
        }
    }
    operation
        .finish(handle, Some(deadline))
        .and_then(|written| usize::try_from(written).map_err(|_| ConnectorError::Io))
}

struct OverlappedOperation {
    event: OwnedHandle,
    overlapped: OVERLAPPED,
}

impl OverlappedOperation {
    fn new() -> ConnectorResult<Self> {
        // SAFETY: no security attributes or name are supplied. The event is
        // manual-reset and initially nonsignaled.
        let event = unsafe { CreateEventW(null_mut(), 1, 0, null_mut()) };
        if event.is_null() {
            return Err(ConnectorError::Io);
        }
        let event = OwnedHandle(event);
        // SAFETY: OVERLAPPED is a plain C structure whose documented initial
        // state is all zeroes except for the event handle.
        let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };
        overlapped.hEvent = event.0;
        Ok(Self { event, overlapped })
    }

    fn finish(&mut self, handle: HANDLE, deadline: Option<Instant>) -> ConnectorResult<u32> {
        let wait_ms = match deadline {
            Some(deadline) => deadline_wait_ms(deadline)?,
            None => INFINITE,
        };
        // SAFETY: event is a live event handle owned by self.
        let wait = unsafe { WaitForSingleObject(self.event.0, wait_ms) };
        if wait == WAIT_TIMEOUT {
            self.cancel_and_settle(handle);
            return Err(ConnectorError::Expired);
        }
        if wait != WAIT_OBJECT_0 {
            self.cancel_and_settle(handle);
            return Err(ConnectorError::Io);
        }
        let mut transferred = 0_u32;
        // SAFETY: the event signaled completion and the OVERLAPPED storage is
        // still alive. No blocking wait is requested.
        if unsafe { GetOverlappedResult(handle, &self.overlapped, &mut transferred, 0) } == 0 {
            return Err(ConnectorError::Io);
        }
        Ok(transferred)
    }

    fn cancel_and_settle(&mut self, handle: HANDLE) {
        // SAFETY: the OVERLAPPED belongs to this handle. Cancellation may race
        // with completion, so its return value is intentionally not trusted.
        unsafe {
            CancelIoEx(handle, &self.overlapped);
        }
        // The buffer and OVERLAPPED must never be dropped while kernel I/O is
        // pending. A local named-pipe cancellation should settle immediately;
        // fail fast if the kernel does not signal within the bounded window.
        // SAFETY: event is a live event handle owned by self.
        if unsafe { WaitForSingleObject(self.event.0, CANCEL_SETTLE_TIMEOUT_MS) } != WAIT_OBJECT_0 {
            std::process::abort();
        }
        let mut ignored = 0_u32;
        // SAFETY: cancellation/completion is settled; this consumes the final
        // operation status without waiting.
        unsafe {
            GetOverlappedResult(handle, &self.overlapped, &mut ignored, 0);
        }
    }
}

fn deadline_wait_ms(deadline: Instant) -> ConnectorResult<u32> {
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .ok_or(ConnectorError::Expired)?;
    let millis = remaining.as_millis().max(1);
    u32::try_from(millis).map_err(|_| ConnectorError::InvalidTimeWindow)
}

fn wide_null(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

struct SecurityDescriptor(PSECURITY_DESCRIPTOR);

impl SecurityDescriptor {
    fn session_only(logon_sid: &str) -> ConnectorResult<Self> {
        let logon_sid = canonical_sid(logon_sid)?;
        let sddl = wide_null(&format!("D:P(A;;0x{CLIENT_ACCESS_MASK:08x};;;{logon_sid})"));
        let mut descriptor = null_mut();
        // SAFETY: sddl is null-terminated and descriptor is writable output.
        let converted = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                null_mut(),
            )
        };
        if converted == 0 || descriptor.is_null() {
            return Err(ConnectorError::InsecureLocalEndpoint);
        }
        Ok(Self(descriptor))
    }
}

impl Drop for SecurityDescriptor {
    fn drop(&mut self) {
        // SAFETY: allocated by LocalAlloc through the SDDL conversion API.
        unsafe {
            LocalFree(self.0.cast());
        }
    }
}

struct OwnedHandle(HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        // SAFETY: this token handle is owned and closed exactly once.
        unsafe {
            CloseHandle(self.0);
        }
    }
}

struct ImpersonationGuard {
    active: bool,
}

impl ImpersonationGuard {
    fn revert(mut self) {
        self.revert_or_abort();
    }

    fn revert_or_abort(&mut self) {
        if !self.active {
            return;
        }
        // SAFETY: the current thread is impersonating after a successful
        // ImpersonateNamedPipeClient call.
        if unsafe { windows_sys::Win32::Security::RevertToSelf() } == 0 {
            std::process::abort();
        }
        self.active = false;
    }
}

impl Drop for ImpersonationGuard {
    fn drop(&mut self) {
        self.revert_or_abort();
    }
}

struct LocalWideString(*mut u16);

impl LocalWideString {
    fn decode(&self) -> String {
        let mut length = 0;
        // SAFETY: pointer is a null-terminated LocalAlloc string.
        unsafe {
            while *self.0.add(length) != 0 {
                length += 1;
            }
            String::from_utf16_lossy(std::slice::from_raw_parts(self.0, length))
        }
    }
}

impl Drop for LocalWideString {
    fn drop(&mut self) {
        // SAFETY: allocated by LocalAlloc and released exactly once.
        unsafe {
            LocalFree(self.0.cast::<c_void>());
        }
    }
}

struct LocalSid(PSID);

impl Drop for LocalSid {
    fn drop(&mut self) {
        // SAFETY: allocated by LocalAlloc and released exactly once.
        unsafe {
            LocalFree(self.0.cast::<c_void>());
        }
    }
}

/// Opens the protected HPAY pipe with the exact least-privilege access
/// mask accepted by the server ACL. Generic write is intentionally forbidden.
#[cfg(feature = "listener")]
pub fn open_protocol_client(pipe_name: &str) -> ConnectorResult<File> {
    let encoded = wide_null(pipe_name);
    // Request read plus write-data only. Generic write is intentionally absent
    // because it maps to FILE_CREATE_PIPE_INSTANCE for named pipes.
    // SAFETY: encoded is null-terminated and all optional pointers are null.
    let handle = unsafe {
        CreateFileW(
            encoded.as_ptr(),
            GENERIC_READ | FILE_WRITE_DATA,
            0,
            null(),
            OPEN_EXISTING,
            SECURITY_SQOS_PRESENT | SECURITY_IMPERSONATION,
            null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(ConnectorError::Io);
    }
    // SAFETY: CreateFileW returned one uniquely owned file handle.
    Ok(unsafe { File::from_raw_handle(handle.cast()) })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "listener")]
    use std::sync::mpsc;
    #[cfg(feature = "listener")]
    use std::thread;

    #[cfg(feature = "listener")]
    fn enabled_config() -> WindowsNamedPipeConfig {
        let suffix = uuid::Uuid::new_v4().simple().to_string();
        let mut config = WindowsNamedPipeConfig::for_current_process(&suffix).unwrap();
        config.policy = ListenerPolicy { enabled: true };
        config
    }

    #[test]
    fn named_pipe_listener_is_disabled_by_default() {
        let config =
            WindowsNamedPipeConfig::for_current_process("0123456789abcdef0123456789abcdef")
                .unwrap();
        assert!(matches!(
            WindowsNamedPipeListener::bind(&config),
            Err(ConnectorError::ListenerDisabled)
        ));
        assert!(WindowsNamedPipeConfig::for_current_process("too-short").is_err());
        assert!(canonical_sid("not-a-sid").is_err());
    }

    #[cfg(feature = "listener")]
    #[test]
    fn owner_logon_session_can_connect_exchange_and_reuse_one_instance() {
        let config = enabled_config();
        let mut listener = WindowsNamedPipeListener::bind(&config).unwrap();
        let codec = FrameCodec::default();
        for round in 0..3_u8 {
            let pipe_name = listener.pipe_name().to_owned();
            let client = thread::spawn(move || {
                let mut pipe = open_protocol_client(&pipe_name).unwrap();
                let codec = FrameCodec::default();
                codec
                    .write_to(&mut pipe, &[b'p', b'i', b'n', round])
                    .unwrap();
                codec.read_from(&mut pipe).unwrap()
            });
            let mut connection = listener.accept().unwrap();
            let expected_peer = windows_peer_identity_sha256(&current_process_identity().unwrap());
            assert_eq!(connection.peer_identity_sha256(), expected_peer);
            let debug = format!("{connection:?}");
            assert!(!debug.contains(&config.owner_sid));
            assert!(!debug.contains(&config.logon_sid));
            let request = connection
                .read_frame(&codec, Duration::from_secs(1))
                .unwrap();
            assert_eq!(request, [b'p', b'i', b'n', round]);
            connection
                .write_frame(&codec, b"pong", Duration::from_secs(1))
                .unwrap();
            assert_eq!(client.join().unwrap(), b"pong");
            drop(connection);
        }
    }

    #[cfg(feature = "listener")]
    #[test]
    fn accept_timeout_keeps_the_first_instance_reusable() {
        let config = enabled_config();
        let mut listener = WindowsNamedPipeListener::bind(&config).unwrap();
        assert_eq!(
            listener
                .accept_timeout(Duration::from_millis(20))
                .unwrap_err(),
            ConnectorError::Expired
        );

        let pipe_name = listener.pipe_name().to_owned();
        let client = thread::spawn(move || {
            let mut pipe = open_protocol_client(&pipe_name).unwrap();
            FrameCodec::default().write_to(&mut pipe, b"ready").unwrap();
        });
        let mut connection = listener.accept_timeout(Duration::from_secs(1)).unwrap();
        assert_eq!(
            connection
                .read_frame(&FrameCodec::default(), Duration::from_secs(1))
                .unwrap(),
            b"ready"
        );
        client.join().unwrap();
        drop(connection);
    }

    #[cfg(feature = "listener")]
    #[test]
    fn silent_client_times_out_and_listener_remains_reusable() {
        let config = enabled_config();
        let mut listener = WindowsNamedPipeListener::bind(&config).unwrap();
        let pipe_name = listener.pipe_name().to_owned();
        let (connected_tx, connected_rx) = mpsc::channel();
        let client = thread::spawn(move || {
            let pipe = open_protocol_client(&pipe_name).unwrap();
            connected_tx.send(()).unwrap();
            thread::sleep(Duration::from_millis(100));
            drop(pipe);
        });
        let mut connection = listener.accept().unwrap();
        connected_rx.recv().unwrap();
        assert_eq!(
            connection.read_frame(&FrameCodec::default(), Duration::from_millis(25)),
            Err(ConnectorError::Expired)
        );
        drop(connection);
        client.join().unwrap();

        let pipe_name = listener.pipe_name().to_owned();
        let client = thread::spawn(move || {
            let mut pipe = open_protocol_client(&pipe_name).unwrap();
            FrameCodec::default().write_to(&mut pipe, b"ok").unwrap();
        });
        let mut connection = listener.accept().unwrap();
        assert_eq!(
            connection
                .read_frame(&FrameCodec::default(), Duration::from_secs(1))
                .unwrap(),
            b"ok"
        );
        drop(connection);
        client.join().unwrap();
    }

    #[cfg(feature = "listener")]
    #[test]
    fn first_instance_rejects_prebound_or_second_server() {
        let config = enabled_config();
        let pipe_name = wide_null(config.pipe_name());
        // SAFETY: arguments are valid for a temporary rogue test instance.
        let rogue = unsafe {
            CreateNamedPipeW(
                pipe_name.as_ptr(),
                PIPE_ACCESS_DUPLEX,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                1,
                PIPE_BUFFER_BYTES,
                PIPE_BUFFER_BYTES,
                PIPE_DEFAULT_TIMEOUT_MS,
                null(),
            )
        };
        assert_ne!(rogue, INVALID_HANDLE_VALUE);
        // SAFETY: rogue is a unique owned HANDLE.
        let rogue = unsafe { File::from_raw_handle(rogue.cast()) };
        assert!(matches!(
            WindowsNamedPipeListener::bind(&config),
            Err(ConnectorError::InsecureLocalEndpoint)
        ));
        drop(rogue);

        let listener = WindowsNamedPipeListener::bind(&config).unwrap();
        // SAFETY: attempts a second server instance while the protected first
        // instance remains alive.
        let second = unsafe {
            CreateNamedPipeW(
                pipe_name.as_ptr(),
                PIPE_ACCESS_DUPLEX,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                1,
                PIPE_BUFFER_BYTES,
                PIPE_BUFFER_BYTES,
                PIPE_DEFAULT_TIMEOUT_MS,
                null(),
            )
        };
        assert_eq!(second, INVALID_HANDLE_VALUE);
        drop(listener);
    }

    #[cfg(feature = "listener")]
    #[test]
    fn bind_rejects_identity_from_another_logon_session() {
        let mut config = enabled_config();
        config.logon_sid = canonical_sid("S-1-5-5-0-0").unwrap();
        assert_eq!(
            WindowsNamedPipeListener::bind(&config).unwrap_err(),
            ConnectorError::InsecureLocalEndpoint
        );
    }

    #[test]
    fn client_acl_excludes_create_pipe_instance() {
        assert_eq!(CLIENT_ACCESS_MASK, 0x0012_008b);
        assert_eq!(CLIENT_ACCESS_MASK & 0x0000_0004, 0);
    }
}

use std::fs;
use std::io::{Read, Write};
use std::net::Shutdown;
#[cfg(any(
    target_os = "linux",
    target_os = "macos",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly"
))]
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

use crate::error::{ConnectorError, ConnectorResult};
use crate::framing::FrameCodec;
use crate::transport::ListenerPolicy;

const MAX_SOCKET_PATH_BYTES: usize = 100;
const ACCEPT_POLL_INTERVAL: Duration = Duration::from_millis(2);
const MAX_IO_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Clone)]
pub struct UnixTransportConfig {
    pub policy: ListenerPolicy,
    pub socket_path: PathBuf,
    pub expected_uid: u32,
}

impl UnixTransportConfig {
    pub fn for_current_user(socket_path: impl Into<PathBuf>) -> Self {
        Self {
            policy: ListenerPolicy::default(),
            socket_path: socket_path.into(),
            expected_uid: current_uid(),
        }
    }
}

#[derive(Debug)]
pub struct UnixConnectorListener {
    listener: UnixListener,
    socket_path: PathBuf,
    socket_device: u64,
    socket_inode: u64,
    expected_uid: u32,
}

impl UnixConnectorListener {
    pub fn bind(config: UnixTransportConfig) -> ConnectorResult<Self> {
        config.policy.require_enabled()?;
        validate_socket_path(&config.socket_path, config.expected_uid)?;
        remove_owned_stale_socket(&config.socket_path, config.expected_uid)?;

        let listener = UnixListener::bind(&config.socket_path).map_err(|_| ConnectorError::Io)?;
        listener
            .set_nonblocking(true)
            .map_err(|_| ConnectorError::Io)?;
        fs::set_permissions(&config.socket_path, fs::Permissions::from_mode(0o600))
            .map_err(|_| ConnectorError::InsecureLocalEndpoint)?;
        let metadata = fs::symlink_metadata(&config.socket_path)
            .map_err(|_| ConnectorError::InsecureLocalEndpoint)?;
        if !metadata.file_type().is_socket()
            || metadata.uid() != config.expected_uid
            || metadata.mode() & 0o077 != 0
        {
            let _ = fs::remove_file(&config.socket_path);
            return Err(ConnectorError::InsecureLocalEndpoint);
        }
        Ok(Self {
            listener,
            socket_path: config.socket_path,
            socket_device: metadata.dev(),
            socket_inode: metadata.ino(),
            expected_uid: config.expected_uid,
        })
    }

    pub fn accept(&self) -> ConnectorResult<UnixConnectorConnection> {
        self.accept_until(None)
    }

    pub fn accept_timeout(&self, timeout: Duration) -> ConnectorResult<UnixConnectorConnection> {
        self.accept_until(Some(io_deadline(timeout)?))
    }

    fn accept_until(&self, deadline: Option<Instant>) -> ConnectorResult<UnixConnectorConnection> {
        loop {
            match self.listener.accept() {
                Ok((stream, _)) => {
                    stream
                        .set_nonblocking(false)
                        .map_err(|_| ConnectorError::Io)?;
                    let peer_uid = peer_uid(&stream)?;
                    if peer_uid != self.expected_uid {
                        return Err(ConnectorError::UnauthorizedPeer);
                    }
                    return Ok(UnixConnectorConnection {
                        stream,
                        peer_identity_sha256: unix_peer_identity_sha256(peer_uid),
                    });
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
                        return Err(ConnectorError::Expired);
                    }
                    std::thread::sleep(ACCEPT_POLL_INTERVAL);
                }
                Err(_) => return Err(ConnectorError::Io),
            }
        }
    }

    pub fn local_path(&self) -> &Path {
        &self.socket_path
    }
}

pub struct UnixConnectorConnection {
    stream: UnixStream,
    peer_identity_sha256: String,
}

impl std::fmt::Debug for UnixConnectorConnection {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("UnixConnectorConnection")
            .finish_non_exhaustive()
    }
}

impl UnixConnectorConnection {
    /// SHA-256 commitment to the kernel-authenticated peer UID.
    /// The raw UID is never exposed outside this transport module.
    pub fn peer_identity_sha256(&self) -> &str {
        &self.peer_identity_sha256
    }

    pub fn read_frame(
        &mut self,
        codec: &FrameCodec,
        timeout: Duration,
    ) -> ConnectorResult<Vec<u8>> {
        let deadline = io_deadline(timeout)?;
        let mut prefix = [0_u8; 4];
        read_exact_until(&self.stream, &mut prefix, deadline)?;
        let payload_bytes = u32::from_be_bytes(prefix) as usize;
        if payload_bytes == 0 {
            return Err(ConnectorError::InvalidFrame);
        }
        if payload_bytes > codec.max_frame_bytes() {
            return Err(ConnectorError::FrameTooLarge);
        }
        let mut payload = vec![0_u8; payload_bytes];
        read_exact_until(&self.stream, &mut payload, deadline)?;
        Ok(payload)
    }

    pub fn write_frame(
        &mut self,
        codec: &FrameCodec,
        payload: &[u8],
        timeout: Duration,
    ) -> ConnectorResult<()> {
        let deadline = io_deadline(timeout)?;
        let frame = codec.encode(payload)?;
        write_all_until(&self.stream, &frame, deadline)
    }
}

impl Drop for UnixConnectorConnection {
    fn drop(&mut self) {
        let _ = self.stream.shutdown(Shutdown::Both);
    }
}

impl Drop for UnixConnectorListener {
    fn drop(&mut self) {
        // Never unlink an attacker-replaced path during cleanup.
        if let Ok(metadata) = fs::symlink_metadata(&self.socket_path)
            && metadata.file_type().is_socket()
            && metadata.uid() == self.expected_uid
            && metadata.dev() == self.socket_device
            && metadata.ino() == self.socket_inode
        {
            let _ = fs::remove_file(&self.socket_path);
        }
    }
}

fn io_deadline(timeout: Duration) -> ConnectorResult<Instant> {
    if timeout.is_zero() || timeout > MAX_IO_TIMEOUT {
        return Err(ConnectorError::InvalidTimeWindow);
    }
    Instant::now()
        .checked_add(timeout)
        .ok_or(ConnectorError::InvalidTimeWindow)
}

fn read_exact_until(
    mut stream: &UnixStream,
    buffer: &mut [u8],
    deadline: Instant,
) -> ConnectorResult<()> {
    let mut offset = 0;
    while offset < buffer.len() {
        stream
            .set_read_timeout(Some(remaining_timeout(deadline)?))
            .map_err(|_| ConnectorError::Io)?;
        match stream.read(&mut buffer[offset..]) {
            Ok(0) => return Err(ConnectorError::Io),
            Ok(read) => offset = offset.checked_add(read).ok_or(ConnectorError::Io)?,
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                return Err(ConnectorError::Expired);
            }
            Err(_) => return Err(ConnectorError::Io),
        }
    }
    Ok(())
}

fn write_all_until(
    mut stream: &UnixStream,
    buffer: &[u8],
    deadline: Instant,
) -> ConnectorResult<()> {
    let mut offset = 0;
    while offset < buffer.len() {
        stream
            .set_write_timeout(Some(remaining_timeout(deadline)?))
            .map_err(|_| ConnectorError::Io)?;
        match stream.write(&buffer[offset..]) {
            Ok(0) => return Err(ConnectorError::Io),
            Ok(written) => offset = offset.checked_add(written).ok_or(ConnectorError::Io)?,
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                return Err(ConnectorError::Expired);
            }
            Err(_) => return Err(ConnectorError::Io),
        }
    }
    Ok(())
}

fn remaining_timeout(deadline: Instant) -> ConnectorResult<Duration> {
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .ok_or(ConnectorError::Expired)?;
    Ok(remaining.max(Duration::from_millis(1)))
}

fn validate_socket_path(path: &Path, expected_uid: u32) -> ConnectorResult<()> {
    if path.as_os_str().as_encoded_bytes().len() > MAX_SOCKET_PATH_BYTES {
        return Err(ConnectorError::InsecureLocalEndpoint);
    }
    let parent = path.parent().ok_or(ConnectorError::InsecureLocalEndpoint)?;
    let metadata =
        fs::symlink_metadata(parent).map_err(|_| ConnectorError::InsecureLocalEndpoint)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != expected_uid
        || metadata.mode() & 0o077 != 0
    {
        return Err(ConnectorError::InsecureLocalEndpoint);
    }
    Ok(())
}

fn remove_owned_stale_socket(path: &Path, expected_uid: u32) -> ConnectorResult<()> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err(ConnectorError::Io),
    };
    if metadata.file_type().is_symlink()
        || !metadata.file_type().is_socket()
        || metadata.uid() != expected_uid
    {
        return Err(ConnectorError::InsecureLocalEndpoint);
    }
    match UnixStream::connect(path) {
        Ok(_) => Err(ConnectorError::Io),
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::ConnectionRefused | std::io::ErrorKind::NotFound
            ) =>
        {
            fs::remove_file(path).map_err(|_| ConnectorError::Io)
        }
        Err(_) => Err(ConnectorError::Io),
    }
}

fn current_uid() -> u32 {
    // SAFETY: geteuid has no arguments and no failure mode.
    unsafe { libc::geteuid() }
}

fn unix_peer_identity_sha256(uid: u32) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"HPAY/LOCAL-PEER/UNIX-UID/V1");
    hasher.update(uid.to_be_bytes());
    hex::encode(hasher.finalize())
}

#[cfg(target_os = "linux")]
fn peer_uid(stream: &UnixStream) -> ConnectorResult<u32> {
    let mut credentials = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: pointers reference initialized storage of the exact length passed
    // to getsockopt, and the stream owns a valid Unix socket descriptor.
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut credentials as *mut libc::ucred).cast(),
            &mut length,
        )
    };
    if result != 0 || length as usize != std::mem::size_of::<libc::ucred>() {
        return Err(ConnectorError::UnauthorizedPeer);
    }
    Ok(credentials.uid)
}

#[cfg(any(
    target_os = "macos",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly"
))]
fn peer_uid(stream: &UnixStream) -> ConnectorResult<u32> {
    let mut uid: libc::uid_t = 0;
    let mut gid: libc::gid_t = 0;
    // SAFETY: getpeereid writes the two supplied scalar outputs for a valid
    // connected Unix-domain socket descriptor.
    let result = unsafe { libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) };
    if result != 0 {
        return Err(ConnectorError::UnauthorizedPeer);
    }
    Ok(uid)
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "macos",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly"
)))]
fn peer_uid(_stream: &UnixStream) -> ConnectorResult<u32> {
    Err(ConnectorError::PlatformUnavailable)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insecure_runtime_directory_is_rejected_before_bind() {
        let root = std::env::temp_dir().join(format!(
            "hpay-agent-connector-test-{}",
            uuid::Uuid::new_v4().simple()
        ));
        fs::create_dir_all(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();
        let config = UnixTransportConfig {
            policy: ListenerPolicy { enabled: true },
            socket_path: root.join("agent.sock"),
            expected_uid: current_uid(),
        };
        assert_eq!(
            validate_socket_path(&config.socket_path, config.expected_uid),
            Err(ConnectorError::InsecureLocalEndpoint)
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(feature = "listener")]
    #[test]
    fn accept_and_frame_deadlines_fail_closed_and_recover() {
        let root = std::env::temp_dir().join(format!(
            "hpay-agent-connector-test-{}",
            uuid::Uuid::new_v4().simple()
        ));
        fs::create_dir_all(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let path = root.join("agent.sock");
        let listener = UnixConnectorListener::bind(UnixTransportConfig {
            policy: ListenerPolicy { enabled: true },
            socket_path: path.clone(),
            expected_uid: current_uid(),
        })
        .unwrap();
        assert_eq!(
            listener
                .accept_timeout(Duration::from_millis(20))
                .unwrap_err(),
            ConnectorError::Expired
        );

        let silent_path = path.clone();
        let silent = std::thread::spawn(move || {
            let _stream = UnixStream::connect(silent_path).unwrap();
            std::thread::sleep(Duration::from_millis(80));
        });
        let mut connection = listener.accept_timeout(Duration::from_secs(1)).unwrap();
        assert_eq!(
            connection.peer_identity_sha256(),
            unix_peer_identity_sha256(current_uid())
        );
        assert!(!format!("{connection:?}").contains(&current_uid().to_string()));
        assert_eq!(
            connection.read_frame(&FrameCodec::default(), Duration::from_millis(20)),
            Err(ConnectorError::Expired)
        );
        drop(connection);
        silent.join().unwrap();

        let client_path = path.clone();
        let client = std::thread::spawn(move || {
            let mut stream = UnixStream::connect(client_path).unwrap();
            FrameCodec::default()
                .write_to(&mut stream, b"ready")
                .unwrap();
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
        drop(listener);
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(feature = "listener")]
    #[test]
    fn socket_is_owner_only_and_cleanup_checks_identity() {
        let root = std::env::temp_dir().join(format!(
            "hpay-agent-connector-test-{}",
            uuid::Uuid::new_v4().simple()
        ));
        fs::create_dir_all(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let path = root.join("agent.sock");
        let listener = UnixConnectorListener::bind(UnixTransportConfig {
            policy: ListenerPolicy { enabled: true },
            socket_path: path.clone(),
            expected_uid: current_uid(),
        })
        .unwrap();
        let metadata = fs::metadata(&path).unwrap();
        assert_eq!(metadata.mode() & 0o777, 0o600);
        drop(listener);
        assert!(!path.exists());
        fs::remove_dir_all(root).unwrap();
    }
}

use std::future::Future;
use std::pin::Pin;

use hpay_companion_protocol::{
    CompanionConnection, CompanionMessage, DeviceId, EstablishedSession, ReplayMetadata,
    SessionChallenge, SessionCipher, SessionConfirmation, SessionResponse,
};

use crate::error::LanRuntimeResult;

pub type RuntimeFuture<'a, T> = Pin<Box<dyn Future<Output = LanRuntimeResult<T>> + Send + 'a>>;

/// Runtime-owned authenticated state. The session key remains inside the
/// protocol cipher and is never exposed through this crate's public API.
pub struct AuthenticatedSession {
    pub connection: CompanionConnection,
    pub(crate) cipher: SessionCipher,
}

impl std::fmt::Debug for AuthenticatedSession {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AuthenticatedSession")
            .field("connection", &self.connection)
            .field("cipher", &"<memory-only>")
            .finish()
    }
}

impl AuthenticatedSession {
    pub fn from_desktop(established: EstablishedSession, now: u64) -> LanRuntimeResult<Self> {
        let connection = CompanionConnection {
            connection_version: 1,
            session_id: established.session_id.clone(),
            local_device_id: established.desktop_device_id.clone(),
            remote_device_id: established.mobile_device_id.clone(),
            established_at: now,
            expires_at: established.expires_at,
        };
        connection.validate_at(now)?;
        let cipher = established.into_desktop_cipher()?;
        Ok(Self { connection, cipher })
    }

    pub fn from_mobile(established: EstablishedSession, now: u64) -> LanRuntimeResult<Self> {
        let connection = CompanionConnection {
            connection_version: 1,
            session_id: established.session_id.clone(),
            local_device_id: established.mobile_device_id.clone(),
            remote_device_id: established.desktop_device_id.clone(),
            established_at: now,
            expires_at: established.expires_at,
        };
        connection.validate_at(now)?;
        let cipher = established.into_mobile_cipher()?;
        Ok(Self { connection, cipher })
    }
}

pub trait DesktopHandshake: Send {
    fn challenge(&self) -> &SessionChallenge;

    /// The backend must durably consume the reconnect response replay state
    /// before this future returns an established session.
    fn accept(
        self: Box<Self>,
        response: SessionResponse,
        now: u64,
    ) -> RuntimeFuture<'static, (SessionConfirmation, EstablishedSession)>;
}

pub struct HandleMessageResult {
    pub response: Option<CompanionMessage>,
}

/// Narrow Agent-domain backend. It intentionally has no generic wallet send,
/// vault export, settings, Personal Wallet or L2 method.
pub trait DesktopSessionBackend: Send + Sync + 'static {
    fn begin<'a>(
        &'a self,
        mobile_device_id: DeviceId,
        now: u64,
    ) -> RuntimeFuture<'a, Box<dyn DesktopHandshake>>;

    /// Implementations must durably commit `replay` before returning success.
    fn handle_message<'a>(
        &'a self,
        connection: &'a CompanionConnection,
        message: CompanionMessage,
        replay: ReplayMetadata,
        now: u64,
    ) -> RuntimeFuture<'a, HandleMessageResult>;
}

pub trait MobileHandshake: Send {
    fn response(&self) -> &SessionResponse;

    fn verify(
        self: Box<Self>,
        confirmation: SessionConfirmation,
        now: u64,
    ) -> RuntimeFuture<'static, EstablishedSession>;
}

/// Android/native companion backend. It can create only the typed reconnect
/// response; the wallet private key never exists on mobile.
pub trait MobileSessionBackend: Send + Sync + 'static {
    fn respond<'a>(
        &'a self,
        challenge: SessionChallenge,
        now: u64,
    ) -> RuntimeFuture<'a, Box<dyn MobileHandshake>>;

    /// The native backend must durably consume `replay` before returning the
    /// authenticated message to the UI-facing caller.
    fn accept_message<'a>(
        &'a self,
        connection: &'a CompanionConnection,
        message: CompanionMessage,
        replay: ReplayMetadata,
        now: u64,
    ) -> RuntimeFuture<'a, CompanionMessage>;
}

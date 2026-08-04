use std::future::Future;
use std::pin::Pin;

use serde::{Deserialize, Serialize};

use crate::envelope::EncryptedCompanionFrame;
use crate::error::{CompanionError, CompanionResult};
use crate::identity::DeviceId;

pub type TransportFuture<'a, T> = Pin<Box<dyn Future<Output = CompanionResult<T>> + Send + 'a>>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompanionConnection {
    #[serde(with = "crate::serde_decimal_u64")]
    pub connection_version: u64,
    pub session_id: String,
    pub local_device_id: DeviceId,
    pub remote_device_id: DeviceId,
    #[serde(with = "crate::serde_decimal_u64")]
    pub established_at: u64,
    #[serde(with = "crate::serde_decimal_u64")]
    pub expires_at: u64,
}

impl CompanionConnection {
    pub fn validate_at(&self, now: u64) -> CompanionResult<()> {
        if self.connection_version != 1
            || self.session_id.is_empty()
            || self.expires_at <= self.established_at
            || self.expires_at <= now
        {
            return Err(CompanionError::InvalidSession);
        }
        Ok(())
    }
}

/// Boundary implemented by a future authenticated LAN transport.
///
/// Implementations must carry only encrypted frames after pairing, enforce
/// frame/rate/session limits, and must never expose a wallet signing surface.
pub trait CompanionTransport: Send + Sync {
    fn transport_name(&self) -> &'static str;

    fn connect<'a>(
        &'a self,
        connection: &'a CompanionConnection,
    ) -> TransportFuture<'a, CompanionConnection>;

    fn send<'a>(
        &'a self,
        connection: &'a CompanionConnection,
        frame: EncryptedCompanionFrame,
    ) -> TransportFuture<'a, ()>;

    fn receive<'a>(
        &'a self,
        connection: &'a CompanionConnection,
    ) -> TransportFuture<'a, EncryptedCompanionFrame>;

    fn disconnect<'a>(&'a self, connection: &'a CompanionConnection) -> TransportFuture<'a, ()>;
}

/// Explicitly disabled relay boundary. It is intentionally not a network
/// implementation and prevents accidental production fallback to a relay.
#[derive(Debug, Clone, Copy, Default)]
pub struct DisabledRelayCompanionTransport;

impl CompanionTransport for DisabledRelayCompanionTransport {
    fn transport_name(&self) -> &'static str {
        "disabled-relay"
    }

    fn connect<'a>(
        &'a self,
        _connection: &'a CompanionConnection,
    ) -> TransportFuture<'a, CompanionConnection> {
        Box::pin(async { Err(CompanionError::TransportUnavailable) })
    }

    fn send<'a>(
        &'a self,
        _connection: &'a CompanionConnection,
        _frame: EncryptedCompanionFrame,
    ) -> TransportFuture<'a, ()> {
        Box::pin(async { Err(CompanionError::TransportUnavailable) })
    }

    fn receive<'a>(
        &'a self,
        _connection: &'a CompanionConnection,
    ) -> TransportFuture<'a, EncryptedCompanionFrame> {
        Box::pin(async { Err(CompanionError::TransportUnavailable) })
    }

    fn disconnect<'a>(&'a self, _connection: &'a CompanionConnection) -> TransportFuture<'a, ()> {
        Box::pin(async { Err(CompanionError::TransportUnavailable) })
    }
}

#[cfg(test)]
mod tests {
    use std::task::{Context, Poll, Wake, Waker};

    use super::*;

    struct NoopWake;
    impl Wake for NoopWake {
        fn wake(self: std::sync::Arc<Self>) {}
    }

    fn poll_ready<T>(mut future: TransportFuture<'_, T>) -> CompanionResult<T> {
        let waker = Waker::from(std::sync::Arc::new(NoopWake));
        let mut context = Context::from_waker(&waker);
        match Future::poll(future.as_mut(), &mut context) {
            Poll::Ready(value) => value,
            Poll::Pending => panic!("disabled transport future must be immediately ready"),
        }
    }

    #[test]
    fn connection_json_u64_fields_are_strict_decimal_strings() {
        let connection = CompanionConnection {
            connection_version: u64::MAX,
            session_id: "session_one".to_owned(),
            local_device_id: DeviceId::parse("desktop_one").unwrap(),
            remote_device_id: DeviceId::parse("mobile_one").unwrap(),
            established_at: u64::MAX,
            expires_at: u64::MAX,
        };
        let value = serde_json::to_value(&connection).unwrap();
        for field in ["connection_version", "established_at", "expires_at"] {
            assert_eq!(value[field], serde_json::json!(u64::MAX.to_string()));
        }
        assert_eq!(
            serde_json::from_value::<CompanionConnection>(value.clone()).unwrap(),
            connection
        );

        let mut numeric = value;
        numeric["established_at"] = serde_json::json!(1);
        assert!(serde_json::from_value::<CompanionConnection>(numeric).is_err());
    }

    #[test]
    fn relay_placeholder_is_fail_closed() {
        let transport = DisabledRelayCompanionTransport;
        let connection = CompanionConnection {
            connection_version: 1,
            session_id: "session_one".to_owned(),
            local_device_id: DeviceId::parse("desktop_one").unwrap(),
            remote_device_id: DeviceId::parse("mobile_one").unwrap(),
            established_at: 100,
            expires_at: 200,
        };
        assert_eq!(transport.transport_name(), "disabled-relay");
        assert_eq!(
            poll_ready(transport.connect(&connection)),
            Err(CompanionError::TransportUnavailable)
        );
        assert_eq!(
            poll_ready(transport.disconnect(&connection)),
            Err(CompanionError::TransportUnavailable)
        );
    }
}

#[cfg(unix)]
use std::path::PathBuf;
use std::time::Duration;

use hpay_agent_connector::{ConnectorError, ConnectorResult, Nonce, TransportBinding};

use crate::error::{RuntimeError, RuntimeResult};

const MAX_RUNTIME_TIMEOUT: Duration = Duration::from_secs(30);
const SHUTDOWN_SCHEDULING_MARGIN: Duration = Duration::from_millis(50);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocalEndpoint {
    #[cfg(windows)]
    WindowsNamedPipe { instance_suffix: String },
    #[cfg(unix)]
    UnixDomainSocket { socket_path: PathBuf },
}

impl LocalEndpoint {
    pub(crate) fn transport_kind(&self) -> &'static str {
        match self {
            #[cfg(windows)]
            Self::WindowsNamedPipe { .. } => "windows_named_pipe",
            #[cfg(unix)]
            Self::UnixDomainSocket { .. } => "unix_domain_socket",
        }
    }
}

#[derive(Debug, Clone)]
pub struct RuntimeConfig {
    pub desktop_instance_id: String,
    pub endpoint: LocalEndpoint,
    pub max_frame_bytes: usize,
    pub accept_timeout: Duration,
    pub read_timeout: Duration,
    pub write_timeout: Duration,
    pub dispatch_timeout: Duration,
    pub startup_timeout: Duration,
    pub shutdown_timeout: Duration,
}

impl RuntimeConfig {
    pub fn validate(&self) -> RuntimeResult<()> {
        let timeouts = [
            self.accept_timeout,
            self.read_timeout,
            self.write_timeout,
            self.dispatch_timeout,
            self.startup_timeout,
            self.shutdown_timeout,
        ];
        if self.max_frame_bytes < hpay_agent_connector::server::MIN_CONNECTION_FRAME_BYTES
            || self.max_frame_bytes > hpay_agent_connector::MAX_FRAME_BYTES
            || timeouts
                .iter()
                .any(|timeout| timeout.is_zero() || *timeout > MAX_RUNTIME_TIMEOUT)
            || self.shutdown_timeout
                < self
                    .accept_timeout
                    .max(self.read_timeout)
                    .max(self.write_timeout)
                    .max(self.dispatch_timeout)
                    .saturating_add(SHUTDOWN_SCHEDULING_MARGIN)
        {
            return Err(RuntimeError::InvalidConfiguration);
        }

        Ok(())
    }
}

/// Context supplied to a trusted channel-binding implementation after the
/// local transport has authenticated its operating-system peer.
pub struct LocalTransportContext {
    transport_kind: &'static str,
    endpoint: String,
    connection_id: Nonce,
    peer_identity_sha256: String,
}

impl LocalTransportContext {
    pub fn transport_kind(&self) -> &'static str {
        self.transport_kind
    }

    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    pub fn connection_id(&self) -> &Nonce {
        &self.connection_id
    }

    /// Digest of the OS-authenticated peer identity. Raw SID/UID values never
    /// cross the transport boundary.
    pub fn peer_identity_sha256(&self) -> &str {
        &self.peer_identity_sha256
    }
}

/// Required channel-binding boundary. There is intentionally no default or
/// static fallback. Desktop integration must bind the OS-authenticated peer
/// and this connection instance into the returned SHA-256 values.
pub trait TransportBindingFactory: Send + Sync {
    fn create_binding(&self, context: &LocalTransportContext) -> ConnectorResult<TransportBinding>;
}

/// Production binding factory shared by desktop server integration and local
/// agent client tooling. It has no configurable transcript or static fallback.
#[derive(Debug, Default, Clone, Copy)]
pub struct CanonicalTransportBindingFactory;

impl TransportBindingFactory for CanonicalTransportBindingFactory {
    fn create_binding(&self, context: &LocalTransportContext) -> ConnectorResult<TransportBinding> {
        TransportBinding::for_local_transport(
            context.transport_kind(),
            context.endpoint(),
            context.connection_id().clone(),
            context.peer_identity_sha256(),
        )
    }
}

pub(crate) fn create_transport_binding(
    factory: &dyn TransportBindingFactory,
    endpoint: &LocalEndpoint,
    endpoint_label: String,
    peer_identity_sha256: String,
) -> ConnectorResult<TransportBinding> {
    let context = LocalTransportContext {
        transport_kind: endpoint.transport_kind(),
        endpoint: endpoint_label,
        connection_id: Nonce::random(),
        peer_identity_sha256,
    };
    let binding = factory.create_binding(&context)?;
    binding.validate()?;
    if binding.transport_kind != context.transport_kind
        || binding.connection_id != context.connection_id
        || binding.peer_identity_sha256 != context.peer_identity_sha256
    {
        return Err(ConnectorError::SessionMismatch);
    }
    Ok(binding)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct StaticPeerFactory;

    impl TransportBindingFactory for StaticPeerFactory {
        fn create_binding(
            &self,
            context: &LocalTransportContext,
        ) -> ConnectorResult<TransportBinding> {
            Ok(TransportBinding {
                binding_version: 1,
                transport_kind: context.transport_kind().to_owned(),
                connection_id: context.connection_id().clone(),
                peer_identity_sha256: "ab".repeat(32),
                transport_transcript_sha256: "cd".repeat(32),
            })
        }
    }

    fn valid_config() -> RuntimeConfig {
        RuntimeConfig {
            desktop_instance_id: "desktop-test".to_owned(),
            endpoint: {
                #[cfg(windows)]
                {
                    LocalEndpoint::WindowsNamedPipe {
                        instance_suffix: "0123456789abcdef0123456789abcdef".to_owned(),
                    }
                }
                #[cfg(unix)]
                {
                    LocalEndpoint::UnixDomainSocket {
                        socket_path: std::env::temp_dir().join("runtime-config-test.sock"),
                    }
                }
            },
            max_frame_bytes: hpay_agent_connector::MAX_FRAME_BYTES,
            accept_timeout: Duration::from_millis(20),
            read_timeout: Duration::from_millis(100),
            write_timeout: Duration::from_millis(100),
            dispatch_timeout: Duration::from_millis(500),
            startup_timeout: Duration::from_secs(1),
            shutdown_timeout: Duration::from_millis(550),
        }
    }

    #[test]
    fn shutdown_budget_covers_every_blocking_phase_plus_margin() {
        let valid = valid_config();
        valid.validate().unwrap();

        let mut too_short = valid;
        too_short.shutdown_timeout = too_short.dispatch_timeout;
        assert_eq!(
            too_short.validate(),
            Err(RuntimeError::InvalidConfiguration)
        );
    }

    #[test]
    fn canonical_factory_binds_the_exact_runtime_context() {
        let endpoint = {
            #[cfg(windows)]
            {
                LocalEndpoint::WindowsNamedPipe {
                    instance_suffix: "0123456789abcdef0123456789abcdef".to_owned(),
                }
            }
            #[cfg(unix)]
            {
                LocalEndpoint::UnixDomainSocket {
                    socket_path: std::env::temp_dir().join("canonical-binding-test.sock"),
                }
            }
        };
        let peer = "ef".repeat(32);
        let binding = create_transport_binding(
            &CanonicalTransportBindingFactory,
            &endpoint,
            "canonical-local-endpoint".to_owned(),
            peer.clone(),
        )
        .unwrap();
        assert_eq!(binding.transport_kind, endpoint.transport_kind());
        assert_eq!(binding.peer_identity_sha256, peer);
        assert_ne!(binding.transport_transcript_sha256, "00".repeat(32));
    }

    #[test]
    fn static_or_cross_peer_binding_is_rejected() {
        let endpoint = {
            #[cfg(windows)]
            {
                LocalEndpoint::WindowsNamedPipe {
                    instance_suffix: "0123456789abcdef0123456789abcdef".to_owned(),
                }
            }
            #[cfg(unix)]
            {
                LocalEndpoint::UnixDomainSocket {
                    socket_path: std::env::temp_dir().join("peer-binding-test.sock"),
                }
            }
        };
        assert_eq!(
            create_transport_binding(
                &StaticPeerFactory,
                &endpoint,
                "local-endpoint".to_owned(),
                "ef".repeat(32),
            ),
            Err(ConnectorError::SessionMismatch)
        );
    }
}

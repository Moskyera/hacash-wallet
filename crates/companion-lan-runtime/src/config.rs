use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use tokio::sync::watch;

use crate::error::{LanRuntimeError, LanRuntimeResult};

pub const DEFAULT_COMPANION_PORT: u16 = 42492;
pub const MAX_WIRE_FRAME_BYTES: usize = 256 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeStartupGate {
    pub agent_space_active: bool,
    pub connectivity_enabled: bool,
    pub active_paired_devices: usize,
}

impl RuntimeStartupGate {
    pub fn validate(self) -> LanRuntimeResult<()> {
        if self.agent_space_active && self.connectivity_enabled && self.active_paired_devices > 0 {
            Ok(())
        } else {
            Err(LanRuntimeError::StartupGateClosed)
        }
    }
}

/// Watched authorization state owned by the desktop shell. Closing any gate
/// stops the listener and every active companion connection.
#[derive(Debug, Clone)]
pub struct RuntimeGateController {
    sender: watch::Sender<RuntimeStartupGate>,
}

impl RuntimeGateController {
    pub fn new(initial: RuntimeStartupGate) -> Self {
        let (sender, _) = watch::channel(initial);
        Self { sender }
    }

    pub fn update(&self, current: RuntimeStartupGate) -> LanRuntimeResult<()> {
        self.sender
            .send(current)
            .map_err(|_| LanRuntimeError::Shutdown)
    }

    pub fn current(&self) -> RuntimeStartupGate {
        *self.sender.borrow()
    }

    pub(crate) fn subscribe(&self) -> watch::Receiver<RuntimeStartupGate> {
        self.sender.subscribe()
    }
}

#[derive(Debug, Clone)]
pub struct LanRuntimeConfig {
    bind_addr: SocketAddr,
    handshake_timeout: Duration,
    human_response_timeout: Duration,
    io_timeout: Duration,
    idle_timeout: Duration,
    shutdown_timeout: Duration,
    max_connections: usize,
    max_connections_per_peer: usize,
    max_attempts_per_minute: usize,
    max_global_attempts_per_minute: usize,
    allow_test_loopback: bool,
}

impl LanRuntimeConfig {
    pub fn production(bind_addr: SocketAddr) -> LanRuntimeResult<Self> {
        let value = Self {
            bind_addr,
            handshake_timeout: Duration::from_secs(10),
            human_response_timeout: Duration::from_secs(60),
            io_timeout: Duration::from_secs(10),
            idle_timeout: Duration::from_secs(60),
            shutdown_timeout: Duration::from_secs(5),
            max_connections: 8,
            max_connections_per_peer: 2,
            max_attempts_per_minute: 20,
            max_global_attempts_per_minute: 64,
            allow_test_loopback: false,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn bind_addr(&self) -> SocketAddr {
        self.bind_addr
    }
    pub fn handshake_timeout(&self) -> Duration {
        self.handshake_timeout
    }
    pub fn human_response_timeout(&self) -> Duration {
        self.human_response_timeout
    }
    pub fn io_timeout(&self) -> Duration {
        self.io_timeout
    }
    pub fn idle_timeout(&self) -> Duration {
        self.idle_timeout
    }
    pub fn shutdown_timeout(&self) -> Duration {
        self.shutdown_timeout
    }
    pub fn max_connections(&self) -> usize {
        self.max_connections
    }
    pub fn max_connections_per_peer(&self) -> usize {
        self.max_connections_per_peer
    }
    pub fn max_attempts_per_minute(&self) -> usize {
        self.max_attempts_per_minute
    }
    pub fn max_global_attempts_per_minute(&self) -> usize {
        self.max_global_attempts_per_minute
    }
    pub(crate) fn allow_test_loopback(&self) -> bool {
        self.allow_test_loopback
    }

    pub(crate) fn validate(&self) -> LanRuntimeResult<()> {
        let ip_allowed = is_private_lan_ip(self.bind_addr.ip())
            || (self.allow_test_loopback && self.bind_addr.ip().is_loopback());
        if !ip_allowed
            || (!self.allow_test_loopback && self.bind_addr.port() == 0)
            || self.handshake_timeout.is_zero()
            || self.human_response_timeout.is_zero()
            || self.io_timeout.is_zero()
            || self.idle_timeout.is_zero()
            || self.shutdown_timeout.is_zero()
            || self.max_connections == 0
            || self.max_connections_per_peer == 0
            || self.max_connections_per_peer > self.max_connections
            || self.max_attempts_per_minute == 0
            || self.max_global_attempts_per_minute < self.max_attempts_per_minute
        {
            return Err(LanRuntimeError::NonPrivateAddress);
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn loopback_for_tests() -> Self {
        Self {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            handshake_timeout: Duration::from_secs(2),
            human_response_timeout: Duration::from_secs(5),
            io_timeout: Duration::from_secs(2),
            idle_timeout: Duration::from_millis(250),
            shutdown_timeout: Duration::from_secs(2),
            max_connections: 4,
            max_connections_per_peer: 2,
            max_attempts_per_minute: 8,
            max_global_attempts_per_minute: 16,
            allow_test_loopback: true,
        }
    }
}

pub(crate) fn validate_remote_endpoint(
    address: SocketAddr,
    allow_test_loopback: bool,
) -> LanRuntimeResult<()> {
    if address.port() == 0 {
        return Err(LanRuntimeError::NonPrivateAddress);
    }
    validate_peer_ip(address.ip(), allow_test_loopback)
}

pub(crate) fn validate_peer_ip(ip: IpAddr, allow_test_loopback: bool) -> LanRuntimeResult<()> {
    if is_private_lan_ip(ip) || (allow_test_loopback && ip.is_loopback()) {
        Ok(())
    } else {
        Err(LanRuntimeError::NonPrivateAddress)
    }
}

fn is_private_lan_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(value) => is_private_v4(value),
        IpAddr::V6(value) => is_private_v6(value),
    }
}

fn is_private_v4(value: Ipv4Addr) -> bool {
    value.is_private() || value.is_link_local()
}

fn is_private_v6(value: Ipv6Addr) -> bool {
    // IPv6 ULA fc00::/7. Link-local endpoints require a scope id and are
    // deliberately rejected until the typed endpoint can preserve that scope.
    value.segments()[0] & 0xfe00 == 0xfc00
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open_gate() -> RuntimeStartupGate {
        RuntimeStartupGate {
            agent_space_active: true,
            connectivity_enabled: true,
            active_paired_devices: 1,
        }
    }

    #[test]
    fn startup_gate_requires_all_three_conditions_and_is_watchable() {
        let open = open_gate();
        assert!(open.validate().is_ok());
        let controller = RuntimeGateController::new(open);
        let receiver = controller.subscribe();
        controller
            .update(RuntimeStartupGate {
                connectivity_enabled: false,
                ..open
            })
            .unwrap();
        assert!(matches!(
            receiver.borrow().validate(),
            Err(LanRuntimeError::StartupGateClosed)
        ));
        for closed in [
            RuntimeStartupGate {
                agent_space_active: false,
                ..open
            },
            RuntimeStartupGate {
                connectivity_enabled: false,
                ..open
            },
            RuntimeStartupGate {
                active_paired_devices: 0,
                ..open
            },
        ] {
            assert!(matches!(
                closed.validate(),
                Err(LanRuntimeError::StartupGateClosed)
            ));
        }
    }

    #[test]
    fn production_rejects_public_loopback_unspecified_and_ephemeral_bind() {
        for value in [
            "8.8.8.8:42492",
            "127.0.0.1:42492",
            "0.0.0.0:42492",
            "192.168.1.2:0",
            "[fe80::1]:42492",
        ] {
            assert!(matches!(
                LanRuntimeConfig::production(value.parse().unwrap()),
                Err(LanRuntimeError::NonPrivateAddress)
            ));
        }
        let production =
            LanRuntimeConfig::production("192.168.1.2:42492".parse().unwrap()).unwrap();
        assert_eq!(production.handshake_timeout(), Duration::from_secs(10));
        assert_eq!(production.human_response_timeout(), Duration::from_secs(60));
        assert!(production.human_response_timeout() > production.handshake_timeout());
        assert!(LanRuntimeConfig::production("[fd00::1]:42492".parse().unwrap()).is_ok());
        assert!(validate_peer_ip("8.8.8.8".parse().unwrap(), false).is_err());
        assert!(validate_peer_ip("192.168.1.9".parse().unwrap(), false).is_ok());
    }
}

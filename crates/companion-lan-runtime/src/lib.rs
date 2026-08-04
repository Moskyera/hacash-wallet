//! Bounded, private-LAN transport for the HPAY mobile companion.
//!
//! This crate owns sockets, framing, timeouts and task lifecycles only. It has
//! no Personal Wallet, blockchain signing, Fast Pay/L2, relay, HTTP or WebSocket
//! surface. Cryptographic session authority stays in `hpay-companion-protocol`
//! and the Agent Wallet manager supplied through the backend traits.

mod backend;
mod config;
mod error;
mod framing;
mod limits;
mod mobile;
mod pairing;
mod server;
mod wire;

pub use backend::{
    AuthenticatedSession, DesktopHandshake, DesktopSessionBackend, HandleMessageResult,
    MobileHandshake, MobileSessionBackend, RuntimeFuture,
};
pub use config::{
    DEFAULT_COMPANION_PORT, LanRuntimeConfig, RuntimeGateController, RuntimeStartupGate,
};
pub use error::{LanRuntimeError, LanRuntimeResult};
pub use mobile::MobileLanSession;
pub use pairing::{DesktopPairingBackend, MobilePairingTransport, PairingLanServer};
pub use server::DesktopLanServer;

//! Authenticated reconnect handshake for devices that are already paired.
//!
//! This module owns no transport and persists no secret. Each attempt creates
//! fresh X25519 material, authenticates the complete transcript with the
//! devices' pinned P-256 identities, and returns a zeroizing in-memory key.

mod desktop;
mod kdf;
mod mobile;
mod sequence;
mod types;
mod validation;

#[cfg(test)]
mod tests;

pub use desktop::{DesktopSessionAttempt, EstablishedSession};
pub use mobile::MobileSessionAttempt;
pub use sequence::DesktopChallengeSequence;
pub use types::{SESSION_PROTOCOL_VERSION, SessionChallenge, SessionConfirmation, SessionResponse};
pub use validation::MAX_REQUESTED_SESSION_LIFETIME_SECS;

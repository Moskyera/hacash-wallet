//! Compatibility imports for the canonical cross-crate agent vocabulary.
//!
//! Identity and scope types live in `hpay-agent-types` so the connector and
//! wallet core cannot silently drift.

pub use hpay_agent_types::{AgentId, AgentWalletId, OperationId, WalletScope};

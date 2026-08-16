//! Hacash CSP / Fast Pay hub. Wallet Hub API v7 reference server.
//!
//! Endpoints:
//! - `GET /v1/health`
//! - `POST /v1/fast-pay`
//! - `GET /v1/fast-pay/{payment_id}`
//! - `GET /v1/fast-pay/inbox/{payee}`

pub mod amount;
pub mod api;
pub mod channel_id;
pub mod error;
pub mod fee_payer;
pub mod hub_signer;
pub mod hvm_channel;
pub mod hvm_ledger;
#[cfg(feature = "local-pilot-tools")]
pub mod hvm_pilot;
pub mod hvm_registry;
pub mod hvm_registry_ledger;
#[cfg(feature = "local-pilot-tools")]
pub mod hvm_registry_pilot;
#[cfg(feature = "local-pilot-tools")]
pub mod hvm_registry_pilot_state;
pub mod hvm_registry_watchtower;
pub mod hvm_scheduler;
pub mod hvm_watchtower;
mod idempotency;
pub mod inadmissible;
pub mod journal;
pub mod l1_channel;
pub mod l1_channel_close;
mod ledger;
pub mod node;
pub mod operation;
pub mod protocol_registry;
pub mod readiness;
pub mod routing;
mod sealed_state;
pub mod server;
pub mod state;
mod storage;
#[cfg(windows)]
pub mod windows_identity;
pub mod wire;

pub use api::{
    ConfirmFastPayRequest, FastPayInboxItem, FastPayRequest, FastPayResponse, HUB_API_VERSION,
    HubHealth,
};
pub use channel_id::derive_channel_id;
pub use error::{HubError, HubResult};
pub use hub_signer::HubSigner;
pub use journal::{
    AuthenticatedJournal, JournalBinding, JournalEvent, JournalHead, JournalOperationType,
    JournalPhase, JournalRecord,
};
pub use operation::{IdempotencyRecord, ReservationStatus, request_commitment};
pub use routing::{PayeeRoute, resolve_payee_route};
pub use sealed_state::migrate_plaintext_state_to_sealed;
pub use server::{build_router, serve};
pub use state::HubState;
pub use wire::ChannelPayCompleteDocuments;

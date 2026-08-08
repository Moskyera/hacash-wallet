//! Hacash CSP / Fast Pay hub. Wallet Hub API v4 reference server.
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
mod idempotency;
pub mod journal;
mod ledger;
pub mod node;
pub mod operation;
pub mod routing;
pub mod server;
pub mod state;
mod storage;
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
pub use server::{build_router, serve};
pub use state::HubState;
pub use wire::ChannelPayCompleteDocuments;

//! Hacash CSP / Fast Pay hub — Wallet Hub API v1 reference server.
//!
//! Endpoints:
//! - `GET /v1/health`
//! - `POST /v1/fast-pay`
//! - `GET /v1/fast-pay/{payment_id}`

pub mod amount;
pub mod api;
pub mod channel_id;
pub mod error;
pub mod hub_signer;
pub mod node;
pub mod routing;
pub mod server;
pub mod state;
pub mod wire;

pub use api::{FastPayRequest, FastPayResponse, HubHealth, HUB_API_VERSION};
pub use channel_id::derive_channel_id;
pub use error::{HubError, HubResult};
pub use hub_signer::HubSigner;
pub use routing::{resolve_payee_route, PayeeRoute};
pub use server::{build_router, serve};
pub use state::HubState;
pub use wire::ChannelPayCompleteDocuments;
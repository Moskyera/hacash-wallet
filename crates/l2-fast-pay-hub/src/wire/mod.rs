//! Hacash channel payment wire (`github.com/hacash/core/channel`).

mod build;
mod chain_payment;
mod documents;
mod hash;
mod prove_body;
mod satoshi_var;
mod sign;

pub use build::{address_for_wire, build_cross_channel_bill, build_same_channel_bill, ChannelWireInput};
pub use chain_payment::OffChainChannelTransfer;
pub use documents::ChannelPayCompleteDocuments;
pub use prove_body::TransferProveBody;
pub use hash::{half_checker, sha3_hash};
//! The external monotonic rollback anchor.
//!
//! # What this is for
//!
//! Every safety property in this Hub rests on its durable state being *the
//! latest* state. The channel ledger refuses a bill whose serial is not
//! exactly `previous + 1`, refuses a commit when the ledger head moved, and
//! keeps at most one unresolved progression per channel. All of that is
//! enforced against the state file.
//!
//! None of it survives the state file going backwards. Restore a Hub from a
//! backup taken ten bills ago and every one of those checks passes again,
//! against a stale head. The Hub will co-sign serial 4 a second time with
//! different balances; both signed bills are valid to the contract; the one
//! that reaches `finalize` first wins and the other party's money is gone. No
//! amount of in-file validation catches this, because the file is the thing
//! that lied.
//!
//! An anchor is a counter that lives **outside** the state and only ever goes
//! up. Before the Hub uses its signing key it reserves its next position with
//! the anchor, and refuses if the state it holds is behind what the anchor has
//! already seen.
//!
//! # Layout
//!
//! - [`protocol`] - the wire messages, their canonical encoding and their
//!   verification. Lifted in shape from `companion-protocol`'s witness.
//! - [`client`] - the Hub's only witness client, plus the degradation guard.
//! - `witness` - the witness service itself, behind the `rollback-witness`
//!   feature and absent from a default Hub build.
//!
//! Design: `docs/l2/ADR-001-EXTERNAL-ROLLBACK-ANCHOR.md`,
//! `docs/l2/ROLLBACK-ANCHOR-PROTOCOL.md`.
//! Operator procedure: `docs/l2/ROLLBACK-ANCHOR-RECOVERY.md`.

pub mod client;
mod codec;
pub mod protocol;
#[cfg(feature = "rollback-witness")]
pub mod witness;

/// The two witness routes. Shared so the client and the service cannot drift.
pub const ANCHOR_RESERVE_PATH: &str = "/witness/v1/anchor";
pub const ANCHOR_STATUS_PATH: &str = "/witness/v1/status";

pub use client::{
    ROLLBACK_ANCHOR_EVIDENCE_SCHEMA, RollbackAnchorClient, RollbackAnchorConfig,
    RollbackAnchorEvidenceV1, RollbackAnchorPin, VerifiedAnchorReceipt, VerifiedWitnessStatus,
    WitnessEndpointPosture,
};
pub use protocol::{
    HubAnchorRequestV1, HubWitnessAnswerV1, HubWitnessReceiptV1, HubWitnessRefusalV1,
    HubWitnessStatusRequestV1, HubWitnessStatusV1, MAX_ANCHOR_LIFETIME_SECS,
    SignedHubAnchorRequestV1, SignedHubWitnessReceiptV1, SignedHubWitnessRefusalV1,
    SignedHubWitnessStatusV1, SignedWitnessDeploymentAttestationV1, WitnessDeploymentAttestationV1,
    WitnessPosture, WitnessRefusalReason,
};

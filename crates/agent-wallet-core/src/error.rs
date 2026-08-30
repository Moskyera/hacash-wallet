#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AgentWalletError {
    #[error("Agent Wallet was not found")]
    AgentWalletNotFound,
    #[error("Agent Wallet is locked")]
    AgentWalletLocked,
    #[error("Agent Wallet already exists")]
    AgentWalletAlreadyExists,
    #[error("AI agent is not paired")]
    AgentNotPaired,
    #[error("AI agent is revoked")]
    AgentRevoked,
    #[error("AI agent authentication failed")]
    AgentAuthenticationFailed,
    #[error("AI agent session expired")]
    AgentSessionExpired,
    #[error("AI agent permission denied")]
    AgentPermissionDenied,
    #[error("wallet scope does not match this Agent Wallet")]
    InvalidWalletScope,
    #[error("payment amount is invalid")]
    InvalidAmount,
    #[error("identifier is invalid")]
    InvalidIdentifier,
    #[error("payment limit exceeded")]
    PaymentLimitExceeded,
    #[error("daily spending limit exceeded")]
    DailyLimitExceeded,
    #[error("recipient is not allowed")]
    RecipientNotAllowed,
    #[error("all Agent Wallet payments are suspended")]
    AgentPaymentsSuspended,
    #[error("Agent Wallet balance is insufficient")]
    InsufficientAgentBalance,
    #[error("idempotency key conflicts with a different request")]
    IdempotencyConflict,
    #[error("approval is required")]
    ApprovalRequired,
    // The narrow remainder of the old blanket "this desktop cannot approve".
    // Approving signs the transaction and then stops for the paired phone's
    // rollback witness, and only a phone holding the witness permission can
    // supply it. Approving with no such phone would sign a real transaction
    // into a status nothing could move, so this refuses first.
    //
    // Shown verbatim in the desktop UI, so it names the one control that
    // resolves it and states plainly that nothing was signed.
    #[error(
        "This payment cannot be approved yet, because no paired phone can witness it. Approving signs the transaction and then waits for a paired phone to confirm it, and no phone that can do that is available. Witnessing stays bound to the one phone that was set up for it, so a phone you paired afterwards does not take that role on its own. Use Pair a phone, or Replace the paired phone, on the Security page. Nothing was signed, nothing was spent, and this payment is still waiting for a decision."
    )]
    WitnessPhoneRequiredForApproval,
    #[error("approval expired")]
    ApprovalExpired,
    #[error("approval was rejected")]
    ApprovalRejected,
    #[error("approval does not match the exact transaction commitment")]
    ApprovalCommitmentMismatch,
    #[error("companion device authorization failed")]
    CompanionAuthorizationFailed,
    // Phone-pairing refusals. Every message below names the next thing the
    // owner can do. None of them may ever carry a code, nonce, fingerprint,
    // key, device identifier or any other secret: they are shown verbatim in
    // the desktop UI.
    #[error(
        "This pairing is already open on this desktop. Choose Cancel pairing, then run Pair a phone again."
    )]
    PairingAlreadyRegistered,
    #[error(
        "This pairing was started for something else. Choose Cancel pairing, then start the pairing you want from its own screen."
    )]
    PairingPurposeMismatch,
    #[error(
        "The phone has not finished its part of this pairing yet. Wait for the phone, or choose Cancel pairing and run Pair a phone again."
    )]
    PairingPhoneRecordMissing,
    #[error(
        "This pairing already used all 5 tries. Choose Cancel pairing, run Pair a phone again, and scan the new QR code."
    )]
    PairingAttemptsExhausted,
    #[error(
        "This desktop's signing session changed since the pairing started, usually after a lock, unlock or restart. Nothing was paired. Run Pair a phone again."
    )]
    PairingSignerAuthorityChanged,
    #[error(
        "This desktop is no longer holding this pairing. Nothing was paired. Run Pair a phone again from the start."
    )]
    PairingUnknownToSession,
    #[error(
        "The Agent Wallet changed since this pairing started, usually after an emergency stop or a pause and resume. Nothing was paired. Run Pair a phone again."
    )]
    PairingStateChangedSinceStart,
    #[error(
        "This pairing no longer matches the offer on screen. Choose Cancel pairing and run Pair a phone again."
    )]
    PairingOfferBindingMismatch,
    #[error(
        "That code does not match the code on this desktop. Compare the six digits on both devices and enter them again."
    )]
    PairingVerificationCodeMismatch,
    #[error(
        "The phone's identity could not be verified. Make sure this is your phone, then choose Cancel pairing and pair it again."
    )]
    PairingIdentityMismatch,
    #[error(
        "The phone answered a different pairing. Choose Cancel pairing, run Pair a phone again, and scan the new QR code with this phone."
    )]
    PairingTranscriptMismatch,
    #[error(
        "This pairing was already used or cancelled. Run Pair a phone again to get a new QR code."
    )]
    PairingAlreadyUsed,
    // Never send an owner to Revoke device to fix a pairing problem. Revocation
    // is permanent for that handset's identity, so the advice that used to be
    // here turned a recoverable phone into an unusable one.
    #[error(
        "This phone is already authorized on this Agent Wallet. Revoking it is permanent for this phone's identity, so never revoke a working phone to fix a pairing problem. Run Pair a phone again and finish every step on this desktop to refresh it."
    )]
    PairingDeviceAlreadyRegistered,
    // The old copy said "Reset the companion app on the phone, then pair it
    // again". That can never work: the phone deliberately keeps its hardware
    // companion identity across a reset, so it presents the same revoked
    // identity forever. Name the permanence and the two routes that do work.
    #[error(
        "This phone was revoked on this Agent Wallet. Revocation is permanent for this phone's identity, so this phone can never be paired again while it presents that identity. Resetting the companion app does not help, because the phone deliberately keeps the same identity across a reset. Use the companion app on the phone to create a new mobile identity, or pair a different phone instead."
    )]
    PairingDeviceRevoked,
    #[error(
        "The phone's pairing record was refused by this Agent Wallet. Choose Cancel pairing and pair the phone again."
    )]
    PairingDeviceRecordRejected,
    // Witness-rotation refusals, phrased for the owner replacing a phone.
    #[error(
        "This phone is not part of the phone replacement in progress. Use the phone being replaced, or the new phone you are adding."
    )]
    RotationDeviceNotInRotation,
    #[error(
        "The phone being replaced is no longer registered on this Agent Wallet. Refresh the phone replacement screen and start again."
    )]
    RotationOldDeviceNotRegistered,
    #[error(
        "The phone being replaced is not authorized to witness this Agent Wallet. Reconnect that phone, or use lost-phone recovery instead."
    )]
    RotationOldDeviceNotAuthorized,
    #[error(
        "The phone being replaced could not be revoked. Open Authorized mobile devices, revoke it there, then start the phone replacement again."
    )]
    RotationOldDeviceRevokeFailed,
    #[error(
        "Approve this phone replacement on the phone being replaced before adding the new phone."
    )]
    RotationOldDeviceApprovalMissing,
    #[error(
        "That approval is for a different phone replacement. Start the phone replacement again on both devices."
    )]
    RotationAuthorizationMismatch,
    #[error(
        "The approval from the phone being replaced could not be verified. Approve the phone replacement again on that phone."
    )]
    RotationAuthorizationSignatureInvalid,
    #[error(
        "The replacement phone must not be the phone that is already paired. Choose a different phone."
    )]
    RotationCandidateIsCurrentDevice,
    #[error(
        "The new phone sent a pairing record this Agent Wallet cannot use. Restart the companion app on the new phone and pair it again."
    )]
    RotationCandidateRecordInvalid,
    #[error(
        "The new phone cannot join this Agent Wallet. Use a phone that is not revoked and that belongs to this Agent Wallet."
    )]
    RotationCandidateNotEligible,
    #[error(
        "That phone is already registered on this Agent Wallet. Choose a phone that is not paired yet."
    )]
    RotationCandidateAlreadyRegistered,
    #[error(
        "The new phone is not authorized to witness this Agent Wallet yet. Finish the pairing steps on the new phone first."
    )]
    RotationCandidateNotAuthorized,
    #[error(
        "The new phone's acceptance could not be verified. Repeat the pairing step on the new phone."
    )]
    RotationCandidateAcceptanceInvalid,
    #[error(
        "The new phone could not be recorded as this Agent Wallet's companion. Start the phone replacement again from the phone replacement screen."
    )]
    RotationCandidateRegistrationFailed,
    #[error(
        "The pairing ticket for this phone replacement is no longer valid. Start the phone replacement again."
    )]
    RotationTicketInvalid,
    #[error(
        "The new phone's first witness receipt could not be verified. Repeat the confirmation step on the new phone."
    )]
    RotationBaselineReceiptInvalid,
    #[error(
        "A different first witness receipt was already recorded for this phone replacement. Start the phone replacement again."
    )]
    RotationBaselineAlreadyRecorded,
    #[error("companion message was already consumed")]
    CompanionReplayRejected,
    #[error("request has expired")]
    RequestExpired,
    #[error("unsupported asset")]
    UnsupportedAsset,
    #[error("payment request is invalid")]
    InvalidPaymentRequest,
    #[error("operation was not found")]
    OperationNotFound,
    #[error("operation cannot transition from its current state")]
    InvalidOperationState,
    // The unilateral exit is the one path where a generic refusal is itself a
    // harm. Every other failure on this rail has an ordinary remedy; this one
    // is reached by an owner whose provider has vanished, on the screen that
    // decides whether they get their deposit back, and the driver already
    // knows precisely what is wrong - which step, which half of the lease,
    // which block the window ends at, whether a fee was spent. Collapsing all
    // of that into "operation cannot transition from its current state"
    // spends the one window they have.
    //
    // So the driver's own sentence is carried verbatim. Everything that can
    // reach here is written in this workspace for a person to read, and none
    // of it carries a key, a nonce, a device identifier or any other secret:
    // it is block heights, step names, serials and public transaction hashes.
    #[error("{0}")]
    RegistryExitRefused(String),
    // A fullnode that will not answer, said in the fullnode's own words.
    //
    // Four unrelated conditions - no network at all, a tip a day old, a node
    // thousands of blocks behind, and the network vanishing mid-exit with
    // signed bytes already on the wire - all reached the owner as the single
    // sentence "node or network rejected the operation". They have different
    // remedies and only one of them is "check your internet".
    //
    // The node named here is the owner's own pinned fullnode, which the exit
    // screen already quotes verbatim when a lease read fails, so its words are
    // not new information being disclosed.
    #[error("your fullnode did not answer, so nothing was signed and nothing new was sent: {0}")]
    RegistryExitNodeUnavailable(String),
    #[error("integer arithmetic overflow")]
    IntegerOverflow,
    #[error("secure persistence failed")]
    PersistenceFailed,
    #[error("authenticated Agent Wallet journal is invalid")]
    JournalAuthenticationFailed,
    #[error("Agent Wallet state requires manual recovery")]
    RecoveryRequired,
    // The Fast Pay Hub refused a channel open, in the Hub's own words.
    //
    // This variant exists because of one night. An owner opened their first
    // mainnet Fast Pay channel, the wallet signed, the Hub refused, and
    // `channel_setup.rs` mapped the `HubError` to `Err(_)` and returned a bare
    // `RecoveryRequired`. The Hub does not log route refusals, so the sentence
    // the wallet threw away was the only copy that ever existed. The owner
    // pressed the button twice more and got the same five words twice more.
    //
    // The Hub's message is written in this workspace, for a person to read,
    // and carries no key, nonce or device identifier: it is amounts, caps,
    // addresses the owner already knows, and the name of the rule that fired.
    // It is carried verbatim for exactly the same reason `RegistryExitRefused`
    // is, and it is a distinct variant from `RecoveryRequired` because its
    // remedy is not recovery. Recovery re-runs the confirm, and the confirm is
    // what refused.
    #[error(
        "The Fast Pay Hub refused to open this channel, so nothing was sent to the chain and nothing was spent. The Hub said: {0}"
    )]
    ChannelSetupHubRefused(String),
    // The Fast Pay Hub could not be reached, or says it is not in a state to
    // take a channel open, in the Hub's own words.
    //
    // Same defect, one step earlier. Both `prepare` and the re-verification
    // inside `confirm` collapsed `require_channel_open_ready` into
    // `SigningBlocked` - "transaction signing is blocked" - which names
    // neither the Hub nor the unmet clause. The Hub client builds that
    // sentence with `describe_unmet_contract` specifically so a person can
    // read which part of the provider contract is unmet, and it was being
    // deleted one line later.
    #[error(
        "The Fast Pay Hub is not ready to open a channel, so nothing was signed and nothing was spent. The Hub said: {0}"
    )]
    ChannelSetupHubNotReady(String),
    #[error("transaction signing is blocked")]
    SigningBlocked,
    // Shown verbatim in the desktop UI, so it says what was not done rather
    // than naming a phase. Discarding is only ever offered for a review that
    // provably never reached the signer; anything past that point keeps its
    // recovery path, because forgetting a setup a signature could exist for is
    // how an owner funds the same channel twice.
    // The last sentence used to be "Use Check or recover setup." That named a
    // way out that does not exist for the state this error is about. Recovery
    // for any non-Confirmed phase just re-runs the confirm, and the confirm is
    // what already refused, so the button would fail the same way. Pointing at
    // it swapped one dead end for a politer one.
    //
    // What is true, and is worth more than a button: the refusal changed
    // nothing, and no signature means no money moved. The wallet is stuck, not
    // spent, and saying that plainly is better than sending someone in a
    // circle.
    #[error(
        "This channel setup cannot be discarded, because a signature for it may already exist. Only a review that was never confirmed can be discarded. Nothing was changed and nothing was spent. This wallet cannot clear this state on its own; the deposit was never sent, so the funds are still in your wallet."
    )]
    ChannelSetupNotDiscardable,
    #[error("transaction broadcast result is uncertain")]
    BroadcastUncertain,
    #[error("node or network rejected the operation")]
    NodeRejected,
    #[error("configured node does not match the Agent Wallet network")]
    NodeNetworkMismatch,
    #[error("pinned Agent Wallet node capability contract is not satisfied")]
    NodeCapabilityMismatch,
    #[error("mobile rollback witness receipt is required before broadcast")]
    RollbackWitnessRequired,
    #[error(
        "this payment can still be witnessed by the paired phone, so it cannot be abandoned yet"
    )]
    WitnessRecoveryNotAvailable,
    #[error("Agent Wallet rollback or witness chain mismatch detected")]
    RollbackDetected,
    // The counterparty rollback-anchor ratchet found that this Hub has stopped
    // using a witness that signed an earlier bill on this channel, and a human
    // has to answer before the channel can advance.
    //
    // It is its own variant and never `RecoveryRequired`, for one blunt
    // reason: `RecoveryRequired` is answered by reconciling, and reconciling
    // is how the bill gets committed. Folding a decision that is waiting for a
    // person into the value whose remedy commits the bill routes the owner
    // into the door the refusal exists to keep shut.
    //
    // Shown verbatim in the desktop UI. It names the choice and does not
    // pretend to make it: an innocent witness rotation and a Hub swapping its
    // witness to re-sign history look identical from here, and only the owner
    // knows whether the operator announced a change.
    #[error(
        "This Hub has stopped using a rollback witness that signed an earlier bill on this channel. Nothing was accepted and nothing was spent. This is what an operator changing witnesses looks like, and it is also what a Hub trying to re-use a serial it already spent looks like; from here they are the same. Review the witness change and either accept the new set, or close this channel on its last accepted bill."
    )]
    AnchorWitnessDecisionRequired,
    // The wallet's own rollback-anchor memory for a channel is missing or
    // behind the wallet's own payment history for that channel. Distinct from
    // `RollbackDetected`, which is about the Hub: this one is about this
    // machine's own files.
    #[error(
        "This wallet's record of the rollback witnesses for this channel is missing or older than its own payment history, so it cannot check whether this Hub went backwards. Nothing was accepted. Restore this wallet's L2 store from the same backup as the rest of the wallet, or close this channel."
    )]
    AnchorMemoryBehindWallet,
    // The provider would not, or could not, countersign the serial-1 refund
    // that this wallet must hold before its money may enter a channel.
    //
    // Its own variant, and deliberately not `NodeRejected`. "node or network
    // rejected the operation" reads as a transient network problem and invites
    // a retry loop, when what actually happened is that a provider declined to
    // guarantee the user a way out. The user's correct next move is to pick a
    // different provider, and the only thing that must be unambiguous is that
    // no money moved: this refusal happens strictly before any funding is
    // built or broadcast, so there is no half-open channel to clean up.
    #[error(
        "This provider would not countersign the refund that lets you close this channel on your own, so no channel was opened. Nothing was funded and nothing was spent. You can try again, or use a different provider."
    )]
    RegistryOpenHubRefused,
    // Funding was asked for on a channel this wallet does not hold a validated
    // Hub-countersigned refund for. This is the gate, not a warning.
    #[error(
        "This wallet has no countersigned refund for this channel, so it will not put money into it. A channel is only funded after the provider has signed a bill that returns your whole deposit."
    )]
    RegistryOpenRefundNotCountersigned,
    // The binding a caller asked to open, or to fund, does not match what this
    // wallet's own pinned fullnode says is actually deployed and initialised.
    // Every field of a binding is a claim; this is the refusal that arrives
    // before the owner is told a provider has guaranteed anything.
    #[error(
        "The channel this provider described is not the one on the chain this wallet is connected to. This wallet checked the contract itself and it is not the reviewed channel registry, or not on this chain, or not carrying the exact channel that was described. Nothing was funded and nothing was spent."
    )]
    RegistryOpenChainMismatch,
    // Funding bytes exist and durably so, and the node has not been seen
    // holding them in a block yet. Nothing is lost; the answer is to press
    // again, and the stored bytes are re-submitted rather than re-signed.
    #[error(
        "Your deposit transaction has been signed and sent, and this wallet has not yet seen it in a block. Nothing else will happen until it confirms. Check again in a moment."
    )]
    RegistryFundingNotConfirmed,
    #[error("Agent Wallet block 1 fingerprint is invalid")]
    InvalidNodeAnchor,
    #[error("secure vault operation failed")]
    Vault,
    #[error("cryptographic operation failed")]
    Crypto,
    #[error("operation rate limit exceeded")]
    RateLimited,
    #[error("too many pending operations")]
    TooManyPendingOperations,
    #[error("too many paired companion devices")]
    TooManyCompanionDevices,
    #[error("pilot diagnostics confirmation does not match the preview")]
    DiagnosticConfirmationMismatch,
    #[error("pilot diagnostics exceeds the local export size limit")]
    DiagnosticTooLarge,
    // A backup's four files only mean anything together. This is the refusal
    // that keeps a restore from writing three of them.
    #[error("this backup's four files do not agree with each other, so nothing was restored")]
    BackupInconsistent,
    #[error("the backup warning has not been read and acknowledged in full")]
    BackupWarningNotAcknowledged,
    // A backup written by a different version of this wallet. Said by name and
    // not folded into `Vault`, because an owner told only "vault error" retypes
    // a passphrase that was never wrong. The three fields this rests on -
    // format kind, backup version, state schema version - are non-secret and
    // are in the clear in the file the reader is already holding, so naming the
    // mismatch reveals nothing that opening the file would not.
    #[error(
        "this backup was written by a different version of the Agent Wallet and cannot be restored by this one"
    )]
    BackupUnsupportedVersion,
}

pub type AgentWalletResult<T> = Result<T, AgentWalletError>;

impl From<hpay_agent_types::TypeError> for AgentWalletError {
    fn from(error: hpay_agent_types::TypeError) -> Self {
        match error {
            hpay_agent_types::TypeError::InvalidIdentifier => Self::InvalidIdentifier,
            hpay_agent_types::TypeError::ScopeMismatch => Self::InvalidWalletScope,
        }
    }
}

impl From<hacash_wallet_core::WalletError> for AgentWalletError {
    fn from(error: hacash_wallet_core::WalletError) -> Self {
        match error {
            hacash_wallet_core::WalletError::Vault(_)
            | hacash_wallet_core::WalletError::InvalidPassphrase => Self::Vault,
            hacash_wallet_core::WalletError::Policy(_) => Self::SigningBlocked,
            _ => Self::NodeRejected,
        }
    }
}

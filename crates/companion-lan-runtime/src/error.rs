use hpay_companion_protocol::CompanionError;

#[derive(Debug, thiserror::Error)]
pub enum LanRuntimeError {
    #[error("companion LAN runtime startup gate is closed")]
    StartupGateClosed,
    #[error("companion LAN bind or endpoint is not a private address")]
    NonPrivateAddress,
    #[error("companion LAN frame is malformed")]
    MalformedFrame,
    #[error("companion LAN frame exceeds the size limit")]
    FrameTooLarge,
    #[error("companion LAN operation timed out")]
    Timeout,
    #[error("companion LAN connection or rate limit was reached")]
    Capacity,
    #[error("plaintext or protocol downgrade received after authentication")]
    DowngradeAttempt,
    #[error("companion LAN runtime was shut down")]
    Shutdown,
    #[error("companion LAN I/O failed: {0}")]
    Io(#[from] std::io::Error),
    /// The desktop closes the socket without writing a byte whenever it refuses
    /// a device before the first reply: an unknown or stale device id, a pairing
    /// that was never finalized on the desktop, or a rejected begin(). Every one
    /// of those reached the phone as a bare "early eof", which is
    /// indistinguishable from a network fault and told the owner nothing. The
    /// stage is known locally at each read, so it is recorded here.
    #[error(
        "the paired desktop closed the connection during device authentication without replying, \
         which means it refused this device. Finish pairing on the desktop, or pair again."
    )]
    EofDuringDeviceAuthentication,
    #[error(
        "the paired desktop closed the connection while confirming the session key. \
         Both applications must come from the same HPAY build checkpoint."
    )]
    EofDuringSessionKeyConfirmation,
    #[error("the paired desktop closed the authenticated companion session")]
    EofDuringAuthenticatedSession,
    #[error("companion protocol rejected the message: {0}")]
    Protocol(#[from] CompanionError),
    #[error("encrypted frame encoding failed")]
    FrameEncoding,
    // ---------------------------------------------------------------------
    // Why the phone's own backend refused the desktop.
    //
    // Every one of these used to be flattened into `Backend`, whose Display,
    // "companion backend rejected the operation", named no cause, no remedy and
    // no time bound, and was indistinguishable from a permanent refusal. That
    // single string cost a full hardware forensics pass to resolve, which is the
    // same failure mode the EOF stages above were introduced to end.
    // ---------------------------------------------------------------------
    /// The decisive one. The desktop's `challenge_sequence` is a strictly
    /// increasing anti-replay counter for the `companion_session_challenge`
    /// scope, and this challenge did not clear the mark the last accepted one
    /// left. The mark expires with that challenge, so the condition clears
    /// itself; nothing about the pairing is wrong and nothing needs resetting.
    //
    // These strings name actions, never buttons. The phone's control labels
    // live in apps/mobile/src/agent/companionStatus.ts and have already been
    // renamed once ("Connect and sync" -> "Connect to the desktop", "Reset
    // mobile companion" -> "Reset this phone's pairing only"). A Rust string
    // that hard-codes a label cannot be kept in step with that file and turns
    // into an instruction the owner cannot follow, so it describes the action
    // instead and lets the phone name its own control.
    #[error(
        "this phone has already accepted a newer session challenge from HPAY Desktop, so this \
         one was refused as a replay. The pairing is fine and nothing needs to be reset. Try \
         connecting again, and if it keeps failing wait up to five minutes for the previous \
         challenge to expire and try once more."
    )]
    StaleDesktopChallengeSequence,
    /// The desktop reused a challenge nonce this phone already consumed.
    #[error(
        "HPAY Desktop reused a session challenge this phone has already answered. Try connecting \
         again to ask for a fresh one."
    )]
    ReusedDesktopChallengeNonce,
    /// `CompanionError::Expired` only: `expires_at` has passed on this phone's
    /// own clock. One cause, one instruction, and the instruction resolves it -
    /// connecting again makes the desktop issue a new challenge.
    ///
    /// This used to be the sink for `InvalidIssuedAt` as well, and its text
    /// named only a clock cause. That was wrong in both directions: it told an
    /// owner whose challenge had simply gone stale to go and audit two clocks,
    /// and it told an owner whose clocks really were far apart the same thing
    /// while calling the challenge expired when it was not. The two causes are
    /// now two errors.
    #[error(
        "the session challenge from HPAY Desktop had already expired by the time this phone \
         read it. Nothing about the pairing is wrong. Try connecting again to get a fresh one."
    )]
    DesktopChallengeExpired,
    /// `CompanionError::InvalidIssuedAt` only: the challenge is still live, but
    /// it is stamped further into this phone's future than the protocol's
    /// bounded skew budget allows, so this phone cannot confirm it is fresh.
    ///
    /// A one or two second offset is normal and is accepted; reaching this means
    /// a genuinely mis-set clock, so unlike the expiry above, connecting again
    /// on its own will not clear it and the error does not claim otherwise.
    #[error(
        "HPAY Desktop's clock is more than a minute ahead of this phone's, so this phone could \
         not confirm the session challenge is still fresh. Nothing about the pairing is wrong. \
         Set the date and time automatically on both devices, then try connecting again."
    )]
    DesktopChallengeClockOffsetTooLarge,
    /// The desktop still answers, but its device records no longer admit this
    /// phone. This one really is permanent and really does need a re-pair.
    #[error(
        "HPAY Desktop no longer authorizes this phone: its device record was revoked, replaced \
         or moved to another Agent Wallet. Pair this phone again from HPAY Desktop."
    )]
    DeviceNoLongerAuthorized,
    #[error(
        "the session challenge was not signed by the desktop this phone is paired with. Make \
         sure you are on the same private network as your own HPAY Desktop."
    )]
    DesktopChallengeSignatureRejected,
    #[error(
        "HPAY Desktop answered with a session challenge addressed to a different phone. Connect \
         to the desktop that lists this phone under Authorized mobile devices."
    )]
    ChallengeAddressedToAnotherDevice,
    #[error(
        "the agent companion is unavailable on this phone: its stored companion state could not \
         be read. Reopen the agent space, and reset this phone's pairing if this repeats."
    )]
    CompanionStateUnavailable,
    #[error(
        "this phone is not paired with an Agent Wallet yet. Pair it from HPAY Desktop before \
         connecting."
    )]
    CompanionNotPaired,
    #[error(
        "the desktop that answered is not the desktop this phone is paired with. Connect to the \
         HPAY Desktop that holds this Agent Wallet."
    )]
    CompanionScopeMismatch,
    #[error(
        "this phone's hardware companion identity is unavailable. Unlock the phone, confirm the \
         fingerprint or face prompt, and open the agent space again."
    )]
    CompanionIdentityUnavailable,
    #[error(
        "this phone could not durably record the companion session before using it, so the \
         connection was refused rather than left unrecorded. Free some storage on the phone and \
         try connecting again."
    )]
    CompanionStatePersistFailed,
    #[error("companion backend rejected the operation")]
    Backend,
    #[error("companion runtime task failed")]
    Task,
}

impl LanRuntimeError {
    /// Reclassify a read failure that was only an end of stream into the
    /// handshake stage it happened at. Anything else is returned unchanged, so
    /// a timeout stays a timeout and a malformed frame stays malformed.
    pub(crate) fn at_stage(self, stage: LanRuntimeError) -> Self {
        match &self {
            Self::Io(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => stage,
            _ => self,
        }
    }

    /// Names why the phone refused a session challenge from its paired desktop.
    ///
    /// This changes no decision: the refusal has already happened and every
    /// input to it is unchanged. It only stops the reason being discarded on
    /// the way out. Anything without a specific owner-facing meaning keeps the
    /// protocol error's own text rather than falling back to a blank string.
    pub fn from_challenge_refusal(error: CompanionError) -> Self {
        match error {
            CompanionError::SequenceReplay => Self::StaleDesktopChallengeSequence,
            CompanionError::NonceReplay => Self::ReusedDesktopChallengeNonce,
            CompanionError::Expired => Self::DesktopChallengeExpired,
            CompanionError::InvalidIssuedAt => Self::DesktopChallengeClockOffsetTooLarge,
            CompanionError::DeviceRevoked
            | CompanionError::UnknownDevice
            | CompanionError::AuthorizationEpochMismatch
            | CompanionError::WalletScopeMismatch => Self::DeviceNoLongerAuthorized,
            CompanionError::InvalidSignature | CompanionError::FingerprintMismatch => {
                Self::DesktopChallengeSignatureRejected
            }
            CompanionError::PlatformSignerUnavailable => Self::CompanionIdentityUnavailable,
            other => Self::Protocol(other),
        }
    }

    /// Whether trying to connect again can succeed on its own, with no re-pair,
    /// reset or desktop change. Used by the phone to decide whether to offer a
    /// retry, so a transient refusal is never presented as permanent.
    ///
    /// `DesktopChallengeClockOffsetTooLarge` is deliberately absent: retrying
    /// re-runs the same comparison against the same two clocks and refuses
    /// again. Its text names the action that does clear it instead.
    pub const fn is_retryable_by_the_owner(&self) -> bool {
        matches!(
            self,
            Self::StaleDesktopChallengeSequence
                | Self::ReusedDesktopChallengeNonce
                | Self::DesktopChallengeExpired
                | Self::Timeout
                | Self::Capacity
                | Self::EofDuringAuthenticatedSession
        )
    }
}

pub type LanRuntimeResult<T> = Result<T, LanRuntimeError>;

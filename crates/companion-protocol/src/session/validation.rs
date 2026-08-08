use crate::error::{CompanionError, CompanionResult};
use crate::identity::{
    DeviceId, DevicePublicRecord, DeviceRegistry, DeviceRole, PlatformDeviceSigner,
};
use crate::replay::MAX_CLOCK_SKEW_SECS;

/// The longest handshake message a verifier will accept, measured from the
/// message's own `issued_at` to its own `expires_at`. Unchanged.
pub(super) const MAX_HANDSHAKE_LIFETIME_SECS: u64 = 5 * 60;

/// The longest session lifetime a desktop may *ask* for.
///
/// This is not the same bound as [`MAX_HANDSHAKE_LIFETIME_SECS`] and must not be
/// equal to it. The phone does not restate the challenge's window; it pins
/// `expires_at` to the challenge's and stamps `issued_at` with its own clock
/// (`MobileSessionAttempt::respond`), so the response it derives is
/// `requested_lifetime + (desktop_clock - phone_clock)` seconds long. With the
/// two equal, a desktop one second ahead produced a 301-second response against
/// a 300-second cap and the handshake was refused as malformed - the refusal
/// simply moved one step further in.
///
/// Reserving the whole skew budget as headroom makes that arithmetic impossible:
/// any offset this crate tolerates at all leaves the derived response inside the
/// cap. This *tightens* what a desktop may request (240s, was 300s) and loosens
/// no verification bound.
pub const MAX_REQUESTED_SESSION_LIFETIME_SECS: u64 =
    MAX_HANDSHAKE_LIFETIME_SECS - MAX_CLOCK_SKEW_SECS;
const MAX_WALLET_ID_BYTES: usize = 256;
const SESSION_PREFIX: &str = "session_";
pub(super) const SESSION_RANDOM_BYTES: usize = 16;
pub(super) const NONCE_BYTES: usize = 32;
pub(super) const PUBLIC_KEY_BYTES: usize = 32;
pub(super) const FINGERPRINT_BYTES: usize = 32;
pub(super) const SIGNATURE_BYTES: usize = 64;

pub(super) fn current_record<'a>(
    registry: &'a DeviceRegistry,
    device_id: &DeviceId,
    agent_wallet_id: &str,
    role: DeviceRole,
    authorization_epoch: Option<u64>,
    fingerprint: Option<&str>,
) -> CompanionResult<&'a DevicePublicRecord> {
    let record = registry
        .records()
        .find(|record| &record.device_id == device_id)
        .ok_or(CompanionError::UnknownDevice)?;
    record.validate()?;
    if record.is_revoked() {
        return Err(CompanionError::DeviceRevoked);
    }
    if record.agent_wallet_id != agent_wallet_id || record.role != role {
        return Err(CompanionError::WalletScopeMismatch);
    }
    if authorization_epoch.is_some_and(|epoch| epoch != record.authorization_epoch) {
        return Err(CompanionError::AuthorizationEpochMismatch);
    }
    if fingerprint.is_some_and(|value| value != record.identity_fingerprint) {
        return Err(CompanionError::FingerprintMismatch);
    }
    Ok(record)
}

pub(super) fn signer_matches(
    signer: &dyn PlatformDeviceSigner,
    record: &DevicePublicRecord,
    role: DeviceRole,
) -> CompanionResult<()> {
    if signer.identity().role() != role || signer.identity().device_id() != &record.device_id {
        return Err(CompanionError::WalletScopeMismatch);
    }
    if signer.identity().fingerprint()? != record.identity_fingerprint {
        return Err(CompanionError::FingerprintMismatch);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(super) fn validate_common(
    protocol_version: u64,
    session_id: &str,
    agent_wallet_id: &str,
    desktop_epoch: u64,
    desktop_fingerprint: &str,
    mobile_epoch: u64,
    mobile_fingerprint: &str,
    issued_at: u64,
    expires_at: u64,
) -> CompanionResult<()> {
    require_version(protocol_version)?;
    if !valid_session_id(session_id)
        || agent_wallet_id.is_empty()
        || agent_wallet_id.len() > MAX_WALLET_ID_BYTES
        || agent_wallet_id.chars().any(char::is_control)
        || desktop_epoch == 0
        || mobile_epoch == 0
        || expires_at <= issued_at
        || expires_at.saturating_sub(issued_at) > MAX_HANDSHAKE_LIFETIME_SECS
    {
        return Err(CompanionError::MalformedMessage);
    }
    lower_hex(desktop_fingerprint, FINGERPRINT_BYTES)?;
    lower_hex(mobile_fingerprint, FINGERPRINT_BYTES)
}

/// Freshness of one handshake message against the verifier's own clock.
///
/// Expiry is enforced first and absolutely: `expires_at <= now` is refused with
/// no budget of any kind, so no expired challenge, response or confirmation can
/// be admitted by anything below.
///
/// What follows is a *freshness* bound on the peer's own stamp, and it is the
/// only part of this function that concerns two clocks. It carries the same
/// bounded, forward-only [`MAX_CLOCK_SKEW_SECS`] the replay guard has always
/// granted these identical timestamps (`ReplayMetadata::validate_at`); this
/// module was the lone outlier at zero, which refused live, correctly signed,
/// unreplayed handshakes between two ordinary consumer devices whose clocks
/// differed by a second. Nothing else moves: the signature still covers
/// `issued_at`, so a hostile peer cannot choose it, and the lifetime cap below
/// still bounds how far `expires_at` may sit from it.
pub(super) fn validate_time(issued_at: u64, expires_at: u64, now: u64) -> CompanionResult<()> {
    if expires_at <= now {
        return Err(CompanionError::Expired);
    }
    // Shape, not freshness, and already refused as MalformedMessage by
    // `validate_common` on every path that reaches here. Kept as depth, and
    // reported as what it is, so that `InvalidIssuedAt` out of this function
    // means one thing only: the peer's stamp is further ahead than the budget.
    // The owner-facing text for it (LanRuntimeError) depends on that.
    if expires_at <= issued_at || expires_at.saturating_sub(issued_at) > MAX_HANDSHAKE_LIFETIME_SECS
    {
        return Err(CompanionError::MalformedMessage);
    }
    if issued_at > now.saturating_add(MAX_CLOCK_SKEW_SECS) {
        return Err(CompanionError::InvalidIssuedAt);
    }
    Ok(())
}

/// The lifetime a desktop asks for when it opens a handshake.
///
/// Capped at [`MAX_REQUESTED_SESSION_LIFETIME_SECS`], which reserves the skew
/// budget as headroom below the verification cap so that the response the phone
/// derives from this window cannot exceed [`MAX_HANDSHAKE_LIFETIME_SECS`].
pub(super) fn validate_requested_lifetime(now: u64, lifetime_secs: u64) -> CompanionResult<()> {
    if lifetime_secs == 0 || lifetime_secs > MAX_REQUESTED_SESSION_LIFETIME_SECS {
        return Err(CompanionError::InvalidSession);
    }
    now.checked_add(lifetime_secs)
        .ok_or(CompanionError::InvalidSession)
        .map(|_| ())
}

pub(super) fn lower_hex(value: &str, expected_bytes: usize) -> CompanionResult<()> {
    if value.len() != expected_bytes * 2 || !is_lower_hex(value) {
        return Err(CompanionError::MalformedMessage);
    }
    Ok(())
}

pub(super) fn require_version(version: u64) -> CompanionResult<()> {
    if version != super::types::SESSION_PROTOCOL_VERSION {
        return Err(CompanionError::UnsupportedVersion);
    }
    Ok(())
}

fn valid_session_id(value: &str) -> bool {
    value
        .strip_prefix(SESSION_PREFIX)
        .is_some_and(|suffix| suffix.len() == SESSION_RANDOM_BYTES * 2 && is_lower_hex(suffix))
}

fn is_lower_hex(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

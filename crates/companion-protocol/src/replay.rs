use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::error::{CompanionError, CompanionResult};
use crate::identity::DeviceId;

/// The one clock-skew budget in this crate.
///
/// Two consumer devices on the same LAN routinely disagree by a second or more:
/// they take their time from different NTP servers, at different intervals, and
/// a phone re-syncs on its own schedule. A peer's `issued_at` that sits slightly
/// ahead of the verifier's own second is therefore normal operation, not a
/// fault, and refusing it is not expiry enforcement: expiry is `expires_at`, and
/// that bound is never given any budget anywhere in this crate.
///
/// This number is the budget every freshness check that compares a *peer's*
/// stamp against the local clock must use, so the handshake, the encrypted
/// frames and the replay guard all agree on what "slightly ahead" means. It is
/// bounded and it is forward-only.
pub const MAX_CLOCK_SKEW_SECS: u64 = 60;
const MAX_LIFETIME_SECS: u64 = 15 * 60;
const LEGACY_REPLAY_SNAPSHOT_VERSION: u64 = 1;
const REPLAY_SNAPSHOT_VERSION: u64 = 2;
const MAX_REPLAY_SCOPES: usize = 1_024;
const MAX_REPLAY_NONCES: usize = 4_096;
const MAX_CONTEXT_BYTES: usize = 128;
const MIN_NONCE_BYTES: usize = 24;
const MAX_NONCE_BYTES: usize = 128;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplayMetadata {
    pub context: String,
    pub sender_device_id: DeviceId,
    pub sequence: u64,
    pub nonce: String,
    pub issued_at: u64,
    pub expires_at: u64,
}

impl ReplayMetadata {
    pub fn validate_at(&self, now: u64) -> CompanionResult<()> {
        validate_scope(&self.context, &self.sender_device_id)?;
        if self.sequence == 0 {
            return Err(CompanionError::SequenceReplay);
        }
        validate_nonce(&self.nonce)?;
        if self.expires_at <= now {
            return Err(CompanionError::Expired);
        }
        if self.issued_at > now.saturating_add(MAX_CLOCK_SKEW_SECS)
            || self.expires_at <= self.issued_at
            || self.expires_at.saturating_sub(self.issued_at) > MAX_LIFETIME_SECS
        {
            return Err(CompanionError::InvalidIssuedAt);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplayHighWaterMark {
    pub context: String,
    pub sender_device_id: DeviceId,
    pub last_sequence: u64,
    /// Latest cryptographic expiry of any accepted message in this scope.
    /// V1 snapshots did not persist this bound and migrate to a fail-closed,
    /// non-prunable sentinel.
    #[serde(default = "legacy_scope_expiry")]
    pub expires_at: u64,
}

const fn legacy_scope_expiry() -> u64 {
    u64::MAX
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplayNonceRecord {
    pub context: String,
    pub sender_device_id: DeviceId,
    pub nonce: String,
    pub issued_at: u64,
    pub expires_at: u64,
}

/// Caller-persisted replay state. The embedding wallet must store this snapshot
/// in authenticated, rollback-protected storage alongside the durable action
/// that consumed the corresponding permit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplayGuardSnapshot {
    pub snapshot_version: u64,
    pub high_water_marks: Vec<ReplayHighWaterMark>,
    pub used_nonces: Vec<ReplayNonceRecord>,
}

impl ReplayGuardSnapshot {
    pub fn validate_at(&self, now: u64) -> CompanionResult<()> {
        if !matches!(
            self.snapshot_version,
            LEGACY_REPLAY_SNAPSHOT_VERSION | REPLAY_SNAPSHOT_VERSION
        ) {
            return Err(CompanionError::UnsupportedVersion);
        }
        if self.high_water_marks.len() > MAX_REPLAY_SCOPES
            || self.used_nonces.len() > MAX_REPLAY_NONCES
        {
            return Err(CompanionError::MessageTooLarge);
        }

        let mut scopes = BTreeMap::new();
        for mark in &self.high_water_marks {
            validate_scope(&mark.context, &mark.sender_device_id)?;
            if mark.last_sequence == 0
                || mark.expires_at == 0
                || scopes
                    .insert(
                        (mark.context.clone(), mark.sender_device_id.clone()),
                        mark.expires_at,
                    )
                    .is_some()
            {
                return Err(CompanionError::MalformedMessage);
            }
        }

        let mut nonces = BTreeMap::new();
        for record in &self.used_nonces {
            validate_scope(&record.context, &record.sender_device_id)?;
            validate_nonce(&record.nonce)?;
            let scope = (record.context.clone(), record.sender_device_id.clone());
            if !scopes.contains_key(&scope)
                || scopes
                    .get(&scope)
                    .is_none_or(|scope_expires_at| record.expires_at > *scope_expires_at)
                || record.issued_at > now.saturating_add(MAX_CLOCK_SKEW_SECS)
                || record.expires_at <= record.issued_at
                || record.expires_at.saturating_sub(record.issued_at) > MAX_LIFETIME_SECS
                || nonces
                    .insert(
                        (scope.0, scope.1, record.nonce.clone()),
                        NonceWindow {
                            issued_at: record.issued_at,
                            expires_at: record.expires_at,
                        },
                    )
                    .is_some()
            {
                return Err(CompanionError::MalformedMessage);
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayPermit {
    key: (String, DeviceId),
    sequence: u64,
    nonce: String,
    nonce_issued_at: u64,
    nonce_expires_at: u64,
    observed_sequence: u64,
    checked_at: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct NonceWindow {
    issued_at: u64,
    expires_at: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ScopeWindow {
    last_sequence: u64,
    expires_at: u64,
}

#[derive(Debug, Clone, Default)]
pub struct ReplayGuard {
    scopes: BTreeMap<(String, DeviceId), ScopeWindow>,
    used_nonces: BTreeMap<(String, DeviceId, String), NonceWindow>,
}

impl ReplayGuard {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_snapshot(snapshot: ReplayGuardSnapshot, now: u64) -> CompanionResult<Self> {
        snapshot.validate_at(now)?;
        let scopes = snapshot
            .high_water_marks
            .into_iter()
            .filter(|mark| mark.expires_at > now)
            .map(|mark| {
                (
                    (mark.context, mark.sender_device_id),
                    ScopeWindow {
                        last_sequence: mark.last_sequence,
                        expires_at: mark.expires_at,
                    },
                )
            })
            .collect();
        let used_nonces = snapshot
            .used_nonces
            .into_iter()
            .filter(|record| record.expires_at > now)
            .map(|record| {
                (
                    (record.context, record.sender_device_id, record.nonce),
                    NonceWindow {
                        issued_at: record.issued_at,
                        expires_at: record.expires_at,
                    },
                )
            })
            .collect();
        Ok(Self {
            scopes,
            used_nonces,
        })
    }

    pub fn snapshot(&self, now: u64) -> CompanionResult<ReplayGuardSnapshot> {
        let snapshot = ReplayGuardSnapshot {
            snapshot_version: REPLAY_SNAPSHOT_VERSION,
            high_water_marks: self
                .scopes
                .iter()
                .filter(|(_, window)| window.expires_at > now)
                .map(
                    |((context, sender_device_id), window)| ReplayHighWaterMark {
                        context: context.clone(),
                        sender_device_id: sender_device_id.clone(),
                        last_sequence: window.last_sequence,
                        expires_at: window.expires_at,
                    },
                )
                .collect(),
            used_nonces: self
                .used_nonces
                .iter()
                .filter(|(_, window)| window.expires_at > now)
                .map(
                    |((context, sender_device_id, nonce), window)| ReplayNonceRecord {
                        context: context.clone(),
                        sender_device_id: sender_device_id.clone(),
                        nonce: nonce.clone(),
                        issued_at: window.issued_at,
                        expires_at: window.expires_at,
                    },
                )
                .collect(),
        };
        snapshot.validate_at(now)?;
        Ok(snapshot)
    }

    /// Checks freshness without mutating state. Commit only after the verified
    /// command has been durably accepted by the caller.
    pub fn check(&self, metadata: &ReplayMetadata, now: u64) -> CompanionResult<ReplayPermit> {
        metadata.validate_at(now)?;
        let key = (metadata.context.clone(), metadata.sender_device_id.clone());
        let active_scope = self
            .scopes
            .get(&key)
            .filter(|window| window.expires_at > now);
        let observed_sequence = active_scope.map_or(0, |window| window.last_sequence);
        if metadata.sequence <= observed_sequence {
            return Err(CompanionError::SequenceReplay);
        }
        let active_scope_count = self
            .scopes
            .values()
            .filter(|window| window.expires_at > now)
            .count();
        if active_scope.is_none() && active_scope_count >= MAX_REPLAY_SCOPES {
            return Err(CompanionError::MessageTooLarge);
        }
        let nonce_key = (
            metadata.context.clone(),
            metadata.sender_device_id.clone(),
            metadata.nonce.clone(),
        );
        let nonce_is_active = self
            .used_nonces
            .get(&nonce_key)
            .is_some_and(|window| window.expires_at > now);
        if nonce_is_active {
            return Err(CompanionError::NonceReplay);
        }
        let active_nonces = self
            .used_nonces
            .values()
            .filter(|window| window.expires_at > now)
            .count();
        if !nonce_is_active && active_nonces >= MAX_REPLAY_NONCES {
            return Err(CompanionError::MessageTooLarge);
        }
        Ok(ReplayPermit {
            key,
            sequence: metadata.sequence,
            nonce: metadata.nonce.clone(),
            nonce_issued_at: metadata.issued_at,
            nonce_expires_at: metadata.expires_at,
            observed_sequence,
            checked_at: now,
        })
    }

    pub fn commit(&mut self, permit: ReplayPermit, now: u64) -> CompanionResult<()> {
        self.commit_at(permit, now)
    }

    /// Atomically applies a permit to an isolated next state and returns the
    /// exact snapshot the caller must durably persist with its accepted action.
    /// On error, the current guard remains unchanged.
    pub fn commit_and_snapshot(
        &mut self,
        permit: ReplayPermit,
        now: u64,
    ) -> CompanionResult<ReplayGuardSnapshot> {
        let mut next = self.clone();
        next.commit_at(permit, now)?;
        let snapshot = next.snapshot(now)?;
        *self = next;
        Ok(snapshot)
    }

    fn commit_at(&mut self, permit: ReplayPermit, now: u64) -> CompanionResult<()> {
        if now < permit.checked_at {
            return Err(CompanionError::InvalidIssuedAt);
        }
        if permit.nonce_expires_at <= now {
            return Err(CompanionError::Expired);
        }
        let current = self
            .scopes
            .get(&permit.key)
            .filter(|window| window.expires_at > now)
            .copied();
        let current_sequence = current.map_or(0, |window| window.last_sequence);
        if current_sequence != permit.observed_sequence || permit.sequence <= current_sequence {
            return Err(CompanionError::SequenceReplay);
        }
        let active_scope_count = self
            .scopes
            .values()
            .filter(|window| window.expires_at > now)
            .count();
        if current.is_none() && active_scope_count >= MAX_REPLAY_SCOPES {
            return Err(CompanionError::MessageTooLarge);
        }
        let nonce_key = (permit.key.0.clone(), permit.key.1.clone(), permit.nonce);
        let nonce_is_active = self
            .used_nonces
            .get(&nonce_key)
            .is_some_and(|window| window.expires_at > now);
        if nonce_is_active {
            return Err(CompanionError::NonceReplay);
        }
        let active_nonces = self
            .used_nonces
            .values()
            .filter(|window| window.expires_at > now)
            .count();
        if !nonce_is_active && active_nonces >= MAX_REPLAY_NONCES {
            return Err(CompanionError::MessageTooLarge);
        }

        self.scopes.retain(|_, window| window.expires_at > now);
        self.used_nonces.retain(|_, window| window.expires_at > now);
        self.used_nonces.insert(
            nonce_key,
            NonceWindow {
                issued_at: permit.nonce_issued_at,
                expires_at: permit.nonce_expires_at,
            },
        );
        let scope_expires_at = current.map_or(permit.nonce_expires_at, |window| {
            window.expires_at.max(permit.nonce_expires_at)
        });
        self.scopes.insert(
            permit.key,
            ScopeWindow {
                last_sequence: permit.sequence,
                expires_at: scope_expires_at,
            },
        );
        Ok(())
    }
}

fn validate_scope(context: &str, sender_device_id: &DeviceId) -> CompanionResult<()> {
    if context.is_empty()
        || context.len() > MAX_CONTEXT_BYTES
        || !context.is_ascii()
        || context.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(CompanionError::MalformedMessage);
    }
    DeviceId::parse(sender_device_id.as_str().to_owned()).map(|_| ())
}

fn validate_nonce(nonce: &str) -> CompanionResult<()> {
    if nonce.len() < MIN_NONCE_BYTES
        || nonce.len() > MAX_NONCE_BYTES
        || !nonce.bytes().all(|byte| byte.is_ascii_alphanumeric())
    {
        return Err(CompanionError::InvalidNonce);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::DeviceRole;

    fn metadata(sequence: u64, nonce_byte: char) -> ReplayMetadata {
        ReplayMetadata {
            context: "approval".to_owned(),
            sender_device_id: DeviceId::random(DeviceRole::Mobile),
            sequence,
            nonce: nonce_byte.to_string().repeat(32),
            issued_at: 100,
            expires_at: 200,
        }
    }

    #[test]
    fn rejects_duplicate_sequence_and_nonce() {
        let mut guard = ReplayGuard::new();
        let first = metadata(1, 'a');
        guard
            .commit(guard.check(&first, 101).unwrap(), 101)
            .unwrap();
        assert_eq!(
            guard.check(&first, 102),
            Err(CompanionError::SequenceReplay)
        );

        let mut reused_nonce = first.clone();
        reused_nonce.sequence = 2;
        assert_eq!(
            guard.check(&reused_nonce, 102),
            Err(CompanionError::NonceReplay)
        );
    }

    #[test]
    fn stale_concurrent_permit_cannot_commit() {
        let mut guard = ReplayGuard::new();
        let first = metadata(1, 'a');
        let second = ReplayMetadata {
            sequence: 2,
            nonce: "b".repeat(32),
            ..first.clone()
        };
        let permit_one = guard.check(&first, 101).unwrap();
        let permit_two = guard.check(&second, 101).unwrap();
        guard.commit(permit_one, 101).unwrap();
        assert_eq!(
            guard.commit(permit_two, 101),
            Err(CompanionError::SequenceReplay)
        );
    }

    #[test]
    fn rejects_expiry_future_and_invalid_nonce() {
        let guard = ReplayGuard::new();
        let mut item = metadata(1, 'a');
        assert_eq!(guard.check(&item, 200), Err(CompanionError::Expired));
        item.expires_at = 300;
        item.issued_at = 200;
        assert_eq!(
            guard.check(&item, 100),
            Err(CompanionError::InvalidIssuedAt)
        );
        item.issued_at = 100;
        item.nonce = "short".to_owned();
        assert_eq!(guard.check(&item, 101), Err(CompanionError::InvalidNonce));
    }

    #[test]
    fn scopes_sequence_by_context_and_sender() {
        let mut guard = ReplayGuard::new();
        let first = metadata(1, 'a');
        guard
            .commit(guard.check(&first, 101).unwrap(), 101)
            .unwrap();
        let different_context = ReplayMetadata {
            context: "admin".to_owned(),
            nonce: "b".repeat(32),
            ..first.clone()
        };
        guard
            .commit(guard.check(&different_context, 101).unwrap(), 101)
            .unwrap();
        let different_sender = ReplayMetadata {
            sender_device_id: DeviceId::random(DeviceRole::Mobile),
            nonce: "c".repeat(32),
            ..first
        };
        guard
            .commit(guard.check(&different_sender, 101).unwrap(), 101)
            .unwrap();
    }

    #[test]
    fn future_issued_metadata_with_allowed_skew_roundtrips_snapshot() {
        let mut guard = ReplayGuard::new();
        let mut future = metadata(1, 'a');
        future.issued_at = 160;
        future.expires_at = 1_060;
        let permit = guard.check(&future, 100).unwrap();
        let snapshot = guard.commit_and_snapshot(permit, 100).unwrap();
        assert_eq!(snapshot.used_nonces[0].issued_at, 160);
        assert!(ReplayGuard::from_snapshot(snapshot, 100).is_ok());
    }

    #[test]
    fn delayed_commit_after_expiry_is_rejected_without_mutation() {
        let mut guard = ReplayGuard::new();
        let mut short_lived = metadata(1, 'a');
        short_lived.expires_at = 105;
        let permit = guard.check(&short_lived, 101).unwrap();
        assert_eq!(guard.commit(permit, 105), Err(CompanionError::Expired));
        assert!(guard.snapshot(105).unwrap().high_water_marks.is_empty());
    }

    #[test]
    fn control_and_non_ascii_contexts_are_rejected() {
        let guard = ReplayGuard::new();
        let mut control = metadata(1, 'a');
        control.context = "approval\n".to_owned();
        assert_eq!(
            guard.check(&control, 101),
            Err(CompanionError::MalformedMessage)
        );
        control.context = "\u{03ad}\u{03b3}\u{03ba}\u{03c1}\u{03b9}\u{03c3}\u{03b7}".to_owned();
        assert_eq!(
            guard.check(&control, 101),
            Err(CompanionError::MalformedMessage)
        );
    }

    #[test]
    fn snapshot_roundtrip_rejects_replay_after_restart() {
        let mut guard = ReplayGuard::new();
        let first = metadata(1, 'a');
        let permit = guard.check(&first, 101).unwrap();
        let snapshot = guard.commit_and_snapshot(permit, 101).unwrap();
        let encoded = serde_json::to_vec(&snapshot).unwrap();
        let decoded: ReplayGuardSnapshot = serde_json::from_slice(&encoded).unwrap();
        let mut restarted = ReplayGuard::from_snapshot(decoded, 102).unwrap();

        assert_eq!(
            restarted.check(&first, 102),
            Err(CompanionError::SequenceReplay)
        );
        let reused_nonce = ReplayMetadata {
            sequence: 2,
            ..first.clone()
        };
        assert_eq!(
            restarted.check(&reused_nonce, 102),
            Err(CompanionError::NonceReplay)
        );

        let next = ReplayMetadata {
            sequence: 2,
            nonce: "b".repeat(32),
            ..first
        };
        let next_permit = restarted.check(&next, 102).unwrap();
        let next_snapshot = restarted.commit_and_snapshot(next_permit, 102).unwrap();
        assert_eq!(next_snapshot.high_water_marks[0].last_sequence, 2);
    }

    #[test]
    fn commit_and_snapshot_is_atomic_on_stale_permit() {
        let mut guard = ReplayGuard::new();
        let first = metadata(1, 'a');
        let second = ReplayMetadata {
            sequence: 2,
            nonce: "b".repeat(32),
            ..first.clone()
        };
        let stale = guard.check(&second, 101).unwrap();
        let accepted = guard.check(&first, 101).unwrap();
        let before = guard.commit_and_snapshot(accepted, 101).unwrap();
        assert_eq!(
            guard.commit_and_snapshot(stale, 101),
            Err(CompanionError::SequenceReplay)
        );
        assert_eq!(guard.snapshot(101).unwrap(), before);
    }

    #[test]
    fn concurrent_new_scope_permits_enforce_the_commit_time_capacity() {
        let sender = DeviceId::random(DeviceRole::Mobile);
        let mut guard = ReplayGuard::new();
        for index in 0..(MAX_REPLAY_SCOPES - 1) {
            guard.scopes.insert(
                (format!("scope_{index}"), sender.clone()),
                ScopeWindow {
                    last_sequence: 1,
                    expires_at: 200,
                },
            );
        }

        let mut first = metadata(1, 'a');
        first.context = "boundary_a".to_owned();
        first.sender_device_id = sender.clone();
        let mut second = metadata(1, 'b');
        second.context = "boundary_b".to_owned();
        second.sender_device_id = sender;

        let first_permit = guard.check(&first, 101).unwrap();
        let second_permit = guard.check(&second, 101).unwrap();
        guard.commit(first_permit, 101).unwrap();
        assert_eq!(
            guard.commit(second_permit, 101),
            Err(CompanionError::MessageTooLarge)
        );
        assert_eq!(
            guard.snapshot(101).unwrap().high_water_marks.len(),
            MAX_REPLAY_SCOPES
        );
    }

    #[test]
    fn snapshot_import_is_bounded_and_rejects_duplicates() {
        let sender = DeviceId::random(DeviceRole::Mobile);
        let oversized = ReplayGuardSnapshot {
            snapshot_version: REPLAY_SNAPSHOT_VERSION,
            high_water_marks: (0..=MAX_REPLAY_SCOPES)
                .map(|index| ReplayHighWaterMark {
                    context: format!("scope_{index}"),
                    sender_device_id: sender.clone(),
                    last_sequence: 1,
                    expires_at: 200,
                })
                .collect(),
            used_nonces: Vec::new(),
        };
        assert!(matches!(
            ReplayGuard::from_snapshot(oversized, 101),
            Err(CompanionError::MessageTooLarge)
        ));

        let duplicate = ReplayGuardSnapshot {
            snapshot_version: REPLAY_SNAPSHOT_VERSION,
            high_water_marks: vec![
                ReplayHighWaterMark {
                    context: "approval".to_owned(),
                    sender_device_id: sender.clone(),
                    last_sequence: 1,
                    expires_at: 200,
                },
                ReplayHighWaterMark {
                    context: "approval".to_owned(),
                    sender_device_id: sender,
                    last_sequence: 2,
                    expires_at: 200,
                },
            ],
            used_nonces: Vec::new(),
        };
        assert!(matches!(
            ReplayGuard::from_snapshot(duplicate, 101),
            Err(CompanionError::MalformedMessage)
        ));
    }

    #[test]
    fn expired_nonce_and_scope_are_pruned_without_accepting_expired_message() {
        let mut guard = ReplayGuard::new();
        let mut first = metadata(1, 'a');
        first.expires_at = 105;
        let permit = guard.check(&first, 101).unwrap();
        guard.commit(permit, 101).unwrap();
        let snapshot = guard.snapshot(105).unwrap();
        assert!(snapshot.used_nonces.is_empty());
        assert!(snapshot.high_water_marks.is_empty());

        let restarted = ReplayGuard::from_snapshot(snapshot, 105).unwrap();
        assert_eq!(restarted.check(&first, 105), Err(CompanionError::Expired));
        let next = ReplayMetadata {
            sequence: 1,
            issued_at: 105,
            expires_at: 200,
            ..first
        };
        assert!(restarted.check(&next, 106).is_ok());
    }

    #[test]
    fn random_session_scope_capacity_recovers_after_crypto_expiry_and_restart() {
        let sender = DeviceId::random(DeviceRole::Mobile);
        let snapshot = ReplayGuardSnapshot {
            snapshot_version: REPLAY_SNAPSHOT_VERSION,
            high_water_marks: (0..MAX_REPLAY_SCOPES)
                .map(|index| ReplayHighWaterMark {
                    context: format!("encrypted_frame:random_session_{index}"),
                    sender_device_id: sender.clone(),
                    last_sequence: 1,
                    expires_at: 105,
                })
                .collect(),
            used_nonces: Vec::new(),
        };
        let encoded = serde_json::to_vec(&snapshot).unwrap();
        let decoded: ReplayGuardSnapshot = serde_json::from_slice(&encoded).unwrap();
        let full = ReplayGuard::from_snapshot(decoded.clone(), 101).unwrap();
        let fresh_while_full = ReplayMetadata {
            context: "encrypted_frame:fresh_session".to_owned(),
            sender_device_id: sender.clone(),
            sequence: 1,
            nonce: "capacitynonce0123456789abcdef".to_owned(),
            issued_at: 101,
            expires_at: 200,
        };
        assert_eq!(
            full.check(&fresh_while_full, 102),
            Err(CompanionError::MessageTooLarge)
        );

        let mut restarted_after_expiry = ReplayGuard::from_snapshot(decoded, 105).unwrap();
        let permit = restarted_after_expiry
            .check(&fresh_while_full, 105)
            .unwrap();
        let recovered = restarted_after_expiry
            .commit_and_snapshot(permit, 105)
            .unwrap();
        assert_eq!(recovered.high_water_marks.len(), 1);
        assert_eq!(recovered.high_water_marks[0].last_sequence, 1);

        let expired_old_frame = ReplayMetadata {
            context: "encrypted_frame:random_session_0".to_owned(),
            sender_device_id: sender,
            sequence: 2,
            nonce: "expirednonce0123456789abcdef0".to_owned(),
            issued_at: 100,
            expires_at: 105,
        };
        assert_eq!(
            restarted_after_expiry.check(&expired_old_frame, 105),
            Err(CompanionError::Expired)
        );
    }

    #[test]
    fn scope_is_retained_until_the_latest_message_expiry() {
        let mut guard = ReplayGuard::new();
        let first = metadata(1, 'a');
        let mut shorter = ReplayMetadata {
            sequence: 2,
            nonce: "b".repeat(32),
            expires_at: 150,
            ..first.clone()
        };
        guard
            .commit(guard.check(&first, 101).unwrap(), 101)
            .unwrap();
        guard
            .commit(guard.check(&shorter, 101).unwrap(), 101)
            .unwrap();

        let still_active = ReplayMetadata {
            sequence: 2,
            nonce: "c".repeat(32),
            issued_at: 151,
            expires_at: 250,
            ..first.clone()
        };
        assert_eq!(
            guard.check(&still_active, 151),
            Err(CompanionError::SequenceReplay)
        );
        assert_eq!(
            guard.snapshot(151).unwrap().high_water_marks[0].expires_at,
            200
        );

        shorter.sequence = 1;
        shorter.nonce = "d".repeat(32);
        shorter.issued_at = 200;
        shorter.expires_at = 250;
        assert!(guard.check(&shorter, 200).is_ok());
    }
    #[test]
    fn legacy_v1_snapshot_without_scope_expiry_migrates_fail_closed() {
        let sender = DeviceId::random(DeviceRole::Mobile);
        let encoded = serde_json::json!({
            "snapshot_version": LEGACY_REPLAY_SNAPSHOT_VERSION,
            "high_water_marks": [{
                "context": "legacy_scope",
                "sender_device_id": sender,
                "last_sequence": 7
            }],
            "used_nonces": []
        });
        let decoded: ReplayGuardSnapshot = serde_json::from_value(encoded).unwrap();
        assert_eq!(decoded.high_water_marks[0].expires_at, u64::MAX);
        let guard = ReplayGuard::from_snapshot(decoded, 10_000).unwrap();
        let replayed = ReplayMetadata {
            context: "legacy_scope".to_owned(),
            sender_device_id: sender.clone(),
            sequence: 7,
            nonce: "legacynonce0123456789abcdef01".to_owned(),
            issued_at: 10_000,
            expires_at: 10_100,
        };
        assert_eq!(
            guard.check(&replayed, 10_001),
            Err(CompanionError::SequenceReplay)
        );
        let next = ReplayMetadata {
            sequence: 8,
            nonce: "legacynonce1123456789abcdef01".to_owned(),
            ..replayed
        };
        let permit = guard.check(&next, 10_001).unwrap();
        let mut migrated = guard;
        let snapshot = migrated.commit_and_snapshot(permit, 10_001).unwrap();
        assert_eq!(snapshot.snapshot_version, REPLAY_SNAPSHOT_VERSION);
        assert_eq!(snapshot.high_water_marks[0].expires_at, u64::MAX);
    }

    #[test]
    fn snapshot_rejects_nonce_that_outlives_its_scope_bound() {
        let sender = DeviceId::random(DeviceRole::Mobile);
        let invalid = ReplayGuardSnapshot {
            snapshot_version: REPLAY_SNAPSHOT_VERSION,
            high_water_marks: vec![ReplayHighWaterMark {
                context: "approval".to_owned(),
                sender_device_id: sender.clone(),
                last_sequence: 1,
                expires_at: 150,
            }],
            used_nonces: vec![ReplayNonceRecord {
                context: "approval".to_owned(),
                sender_device_id: sender,
                nonce: "outlivescope0123456789abcdef0".to_owned(),
                issued_at: 100,
                expires_at: 200,
            }],
        };
        assert!(matches!(
            ReplayGuard::from_snapshot(invalid, 101),
            Err(CompanionError::MalformedMessage)
        ));
    }
}

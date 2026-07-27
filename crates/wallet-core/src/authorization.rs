//! Exact, single-use authorization for prepared signing operations.
//!
//! The renderer may request preparation, but it never supplies transaction bytes
//! at execution time. The wallet keeps one canonical operation in the unlocked
//! session and binds every platform-authenticator ceremony to its opaque id and
//! digest. Preparing a new operation invalidates the previous one.

use std::time::{Duration, Instant};

use rand::RngCore;
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::error::{WalletError, WalletResult};

const PREPARED_DOMAIN: &[u8] = b"hacash-wallet-prepared-operation-v1\0";
pub const PREPARED_OPERATION_TTL: Duration = Duration::from_secs(120);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationKind {
    HacL1,
    Hacd,
    BridgedBtc,
    ChannelOpen,
    ChannelClose,
    FastPaySend,
    FastPayAccept,
    AirgapClassic,
    DappTransaction,
    QuantumType4,
    ColdVaultActivation,
}

impl OperationKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::HacL1 => "hac_l1",
            Self::Hacd => "hacd",
            Self::BridgedBtc => "bridged_btc",
            Self::ChannelOpen => "channel_open",
            Self::ChannelClose => "channel_close",
            Self::FastPaySend => "fast_pay_send",
            Self::FastPayAccept => "fast_pay_accept",
            Self::AirgapClassic => "airgap_classic",
            Self::DappTransaction => "dapp_transaction",
            Self::QuantumType4 => "quantum_type4",
            Self::ColdVaultActivation => "cold_vault_activation",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorizationRequirement {
    None,
    AnyPlatformFactor,
    WebAuthn,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AssuranceMethod {
    NativeBiometric,
    WebAuthn,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TrustedDisplayField {
    pub label: String,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TrustedOperationDisplay {
    pub title: String,
    pub summary: String,
    pub fields: Vec<TrustedDisplayField>,
}

impl TrustedOperationDisplay {
    pub fn native_prompt(&self) -> String {
        let mut prompt = format!("{}\n{}", self.title, self.summary);
        for field in self.fields.iter().take(8) {
            prompt.push('\n');
            prompt.push_str(&field.label);
            prompt.push_str(": ");
            prompt.push_str(&field.value);
        }
        sanitize_prompt(&prompt)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PreparedOperationView {
    pub id: String,
    pub digest: String,
    pub kind: OperationKind,
    pub wallet_address: String,
    pub network_mode: String,
    pub chain_id: Option<u32>,
    pub display: TrustedOperationDisplay,
    pub authorization_required: bool,
    pub webauthn_required: bool,
    pub expires_in_secs: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NativeAuthorizationChallenge {
    pub nonce: String,
    pub operation_id: String,
    pub operation_digest: String,
    pub message: String,
}

#[derive(Debug)]
struct PreparedOperation<T> {
    view: PreparedOperationView,
    requirement: AuthorizationRequirement,
    assurance: Option<AssuranceMethod>,
    pending_native_nonce: Option<String>,
    webauthn_pending: bool,
    created_at: Instant,
    payload: T,
}

impl<T> PreparedOperation<T> {
    /// The single source of truth for "has the exact ceremony happened".
    fn satisfies_requirement(&self) -> bool {
        matches!(
            (self.requirement, self.assurance),
            (AuthorizationRequirement::None, _)
                | (AuthorizationRequirement::AnyPlatformFactor, Some(_))
                | (
                    AuthorizationRequirement::WebAuthn,
                    Some(AssuranceMethod::WebAuthn)
                )
        )
    }
}

#[derive(Debug)]
pub struct PreparedOperationState<T> {
    current: Option<PreparedOperation<T>>,
}

impl<T> Default for PreparedOperationState<T> {
    fn default() -> Self {
        Self { current: None }
    }
}

impl<T> PreparedOperationState<T> {
    #[allow(clippy::too_many_arguments)]
    pub fn prepare(
        &mut self,
        kind: OperationKind,
        wallet_address: &str,
        network_mode: &str,
        chain_id: Option<u32>,
        canonical_payload: &[u8],
        display: TrustedOperationDisplay,
        requirement: AuthorizationRequirement,
        payload: T,
    ) -> WalletResult<PreparedOperationView> {
        self.prepare_at(
            kind,
            wallet_address,
            network_mode,
            chain_id,
            canonical_payload,
            display,
            requirement,
            payload,
            Instant::now(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn prepare_at(
        &mut self,
        kind: OperationKind,
        wallet_address: &str,
        network_mode: &str,
        chain_id: Option<u32>,
        canonical_payload: &[u8],
        display: TrustedOperationDisplay,
        requirement: AuthorizationRequirement,
        payload: T,
        now: Instant,
    ) -> WalletResult<PreparedOperationView> {
        if wallet_address.is_empty() || network_mode.is_empty() || canonical_payload.is_empty() {
            self.clear();
            return Err(WalletError::Policy(
                "prepared operation is missing canonical binding data".into(),
            ));
        }
        let id = random_hex_32();
        let digest = operation_digest(
            kind,
            wallet_address,
            network_mode,
            chain_id,
            canonical_payload,
        );
        let view = PreparedOperationView {
            id,
            digest: hex::encode(digest),
            kind,
            wallet_address: wallet_address.to_owned(),
            network_mode: network_mode.to_owned(),
            chain_id,
            display,
            authorization_required: requirement != AuthorizationRequirement::None,
            webauthn_required: requirement == AuthorizationRequirement::WebAuthn,
            expires_in_secs: PREPARED_OPERATION_TTL.as_secs(),
        };
        self.current = Some(PreparedOperation {
            view: view.clone(),
            requirement,
            assurance: None,
            pending_native_nonce: None,
            webauthn_pending: false,
            created_at: now,
            payload,
        });
        Ok(view)
    }

    pub fn begin_native(
        &mut self,
        operation_id: &str,
    ) -> WalletResult<NativeAuthorizationChallenge> {
        let operation = self.current_mut(operation_id, Instant::now())?;
        if operation.requirement == AuthorizationRequirement::None {
            return Err(WalletError::Policy(
                "this operation does not require platform authorization".into(),
            ));
        }
        if operation.requirement == AuthorizationRequirement::WebAuthn {
            return Err(WalletError::Policy(
                "this operation requires WebAuthn; native biometric is insufficient".into(),
            ));
        }
        operation.assurance = None;
        operation.webauthn_pending = false;
        let nonce = random_hex_32();
        operation.pending_native_nonce = Some(nonce.clone());
        Ok(NativeAuthorizationChallenge {
            nonce,
            operation_id: operation.view.id.clone(),
            operation_digest: operation.view.digest.clone(),
            message: operation.view.display.native_prompt(),
        })
    }

    pub fn finish_native(&mut self, operation_id: &str, nonce: &str) -> WalletResult<()> {
        let operation = self.current_mut(operation_id, Instant::now())?;
        let expected = operation.pending_native_nonce.take().ok_or_else(|| {
            WalletError::Policy("no native authorization is pending for this operation".into())
        })?;
        if !constant_time_eq(expected.as_bytes(), nonce.as_bytes()) {
            operation.assurance = None;
            return Err(WalletError::Policy(
                "native authorization does not match the prepared operation".into(),
            ));
        }
        operation.assurance = Some(AssuranceMethod::NativeBiometric);
        Ok(())
    }

    pub fn begin_webauthn(&mut self, operation_id: &str) -> WalletResult<[u8; 32]> {
        let operation = self.current_mut(operation_id, Instant::now())?;
        if operation.requirement == AuthorizationRequirement::None {
            return Err(WalletError::Policy(
                "this operation does not require platform authorization".into(),
            ));
        }
        operation.assurance = None;
        operation.pending_native_nonce = None;
        operation.webauthn_pending = true;
        decode_digest(&operation.view.digest)
    }

    pub fn finish_webauthn(&mut self, operation_id: &str) -> WalletResult<()> {
        let operation = self.current_mut(operation_id, Instant::now())?;
        if !std::mem::take(&mut operation.webauthn_pending) {
            operation.assurance = None;
            return Err(WalletError::Policy(
                "no WebAuthn ceremony is pending for this operation".into(),
            ));
        }
        operation.assurance = Some(AssuranceMethod::WebAuthn);
        Ok(())
    }

    pub fn take(
        &mut self,
        operation_id: &str,
        expected_kind: OperationKind,
    ) -> WalletResult<(T, Option<AssuranceMethod>, PreparedOperationView)> {
        self.take_at(operation_id, expected_kind, Instant::now())
    }

    fn take_at(
        &mut self,
        operation_id: &str,
        expected_kind: OperationKind,
        now: Instant,
    ) -> WalletResult<(T, Option<AssuranceMethod>, PreparedOperationView)> {
        let operation = self
            .current
            .take()
            .ok_or_else(|| WalletError::Policy("prepare and review this operation again".into()))?;
        if elapsed_at(operation.created_at, now) > PREPARED_OPERATION_TTL {
            return Err(WalletError::Policy(
                "prepared operation expired; rebuild and review it".into(),
            ));
        }
        if !constant_time_eq(operation.view.id.as_bytes(), operation_id.as_bytes()) {
            return Err(WalletError::Policy(
                "prepared operation id mismatch; request was invalidated".into(),
            ));
        }
        if operation.view.kind != expected_kind {
            return Err(WalletError::Policy(
                "prepared operation type mismatch; request was invalidated".into(),
            ));
        }
        if !operation.satisfies_requirement() {
            return Err(WalletError::Policy(
                "fresh authorization for this exact operation is required".into(),
            ));
        }
        Ok((operation.payload, operation.assurance, operation.view))
    }

    /// Non-consuming check that the live ticket is exactly `operation_id` of
    /// `kind` and already carries the assurance its requirement demands.
    ///
    /// This grants nothing and reveals nothing about the payload. It exists so a
    /// shell can perform an irreversible pre-step (deleting an OS unlock secret
    /// before an irreversible policy migration) only once the ceremony has
    /// really happened for this exact operation.
    pub fn is_authorized_for(&self, operation_id: &str, kind: OperationKind) -> bool {
        self.is_authorized_for_at(operation_id, kind, Instant::now())
    }

    fn is_authorized_for_at(&self, operation_id: &str, kind: OperationKind, now: Instant) -> bool {
        let Some(operation) = self.current.as_ref() else {
            return false;
        };
        elapsed_at(operation.created_at, now) <= PREPARED_OPERATION_TTL
            && constant_time_eq(operation.view.id.as_bytes(), operation_id.as_bytes())
            && operation.view.kind == kind
            && operation.satisfies_requirement()
    }

    pub fn clear(&mut self) {
        self.current = None;
    }

    fn current_mut(
        &mut self,
        operation_id: &str,
        now: Instant,
    ) -> WalletResult<&mut PreparedOperation<T>> {
        let expired = self.current.as_ref().is_some_and(|operation| {
            elapsed_at(operation.created_at, now) > PREPARED_OPERATION_TTL
        });
        if expired {
            self.clear();
            return Err(WalletError::Policy(
                "prepared operation expired; rebuild and review it".into(),
            ));
        }
        let matches = self.current.as_ref().is_some_and(|operation| {
            constant_time_eq(operation.view.id.as_bytes(), operation_id.as_bytes())
        });
        if !matches {
            self.clear();
            return Err(WalletError::Policy(
                "prepared operation id mismatch; request was invalidated".into(),
            ));
        }
        self.current
            .as_mut()
            .ok_or_else(|| WalletError::Policy("prepare and review an operation first".into()))
    }
}

fn operation_digest(
    kind: OperationKind,
    wallet_address: &str,
    network_mode: &str,
    chain_id: Option<u32>,
    canonical_payload: &[u8],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(PREPARED_DOMAIN);
    hash_field(&mut hasher, kind.as_str().as_bytes());
    hash_field(&mut hasher, wallet_address.as_bytes());
    hash_field(&mut hasher, network_mode.as_bytes());
    hash_field(&mut hasher, &chain_id.unwrap_or(u32::MAX).to_be_bytes());
    hash_field(&mut hasher, canonical_payload);
    hasher.finalize().into()
}

fn hash_field(hasher: &mut Sha256, field: &[u8]) {
    hasher.update((field.len() as u64).to_be_bytes());
    hasher.update(field);
}

fn decode_digest(value: &str) -> WalletResult<[u8; 32]> {
    hex::decode(value)
        .map_err(|_| WalletError::Policy("invalid prepared operation digest".into()))?
        .try_into()
        .map_err(|_| WalletError::Policy("invalid prepared operation digest length".into()))
}

fn random_hex_32() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

fn elapsed_at(start: Instant, now: Instant) -> Duration {
    now.checked_duration_since(start).unwrap_or_default()
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    let mut difference = left.len() ^ right.len();
    for index in 0..left.len().max(right.len()) {
        difference |= usize::from(
            left.get(index).copied().unwrap_or(0) ^ right.get(index).copied().unwrap_or(0),
        );
    }
    difference == 0
}

fn sanitize_prompt(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .take(700)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn display(to: &str) -> TrustedOperationDisplay {
        TrustedOperationDisplay {
            title: "Send HAC".into(),
            summary: format!("Send to {to}"),
            fields: vec![TrustedDisplayField {
                label: "Recipient".into(),
                value: to.into(),
            }],
        }
    }

    fn prepare(
        state: &mut PreparedOperationState<&'static str>,
        to: &str,
        requirement: AuthorizationRequirement,
        now: Instant,
    ) -> PreparedOperationView {
        state
            .prepare_at(
                OperationKind::HacL1,
                "1Wallet",
                "mainnet",
                Some(0),
                format!("canonical-body-{to}").as_bytes(),
                display(to),
                requirement,
                "payload",
                now,
            )
            .unwrap()
    }

    #[test]
    fn exact_operation_is_single_use_and_wrong_id_consumes() {
        let base = Instant::now();
        let mut state = PreparedOperationState::default();
        let view = prepare(
            &mut state,
            "1Recipient",
            AuthorizationRequirement::AnyPlatformFactor,
            base,
        );
        let challenge = state.begin_native(&view.id).unwrap();
        state.finish_native(&view.id, &challenge.nonce).unwrap();
        assert!(state.take("attacker", OperationKind::HacL1).is_err());
        assert!(state.take(&view.id, OperationKind::HacL1).is_err());
    }

    #[test]
    fn new_prepare_invalidates_approved_operation() {
        let base = Instant::now();
        let mut state = PreparedOperationState::default();
        let first = prepare(
            &mut state,
            "1First",
            AuthorizationRequirement::AnyPlatformFactor,
            base,
        );
        let challenge = state.begin_native(&first.id).unwrap();
        state.finish_native(&first.id, &challenge.nonce).unwrap();
        let second = prepare(&mut state, "1Second", AuthorizationRequirement::None, base);
        assert!(state.take(&first.id, OperationKind::HacL1).is_err());
        assert!(state.take(&second.id, OperationKind::HacL1).is_err());
    }

    #[test]
    fn assurance_is_bound_to_method_and_operation() {
        let base = Instant::now();
        let mut state = PreparedOperationState::default();
        let view = prepare(
            &mut state,
            "1Recipient",
            AuthorizationRequirement::WebAuthn,
            base,
        );
        assert!(state.begin_native(&view.id).is_err());
        let digest = state.begin_webauthn(&view.id).unwrap();
        assert_eq!(hex::encode(digest), view.digest);
        state.finish_webauthn(&view.id).unwrap();
        state.take(&view.id, OperationKind::HacL1).unwrap();
        assert!(state.take(&view.id, OperationKind::HacL1).is_err());
    }

    #[test]
    fn expiry_and_kind_mismatch_fail_closed() {
        let base = Instant::now();
        let mut state = PreparedOperationState::default();
        let view = prepare(
            &mut state,
            "1Recipient",
            AuthorizationRequirement::None,
            base,
        );
        assert!(
            state
                .take_at(
                    &view.id,
                    OperationKind::HacL1,
                    base + PREPARED_OPERATION_TTL + Duration::from_secs(1)
                )
                .is_err()
        );
        let view = prepare(
            &mut state,
            "1Recipient",
            AuthorizationRequirement::None,
            base,
        );
        assert!(state.take(&view.id, OperationKind::Hacd).is_err());
        assert!(state.take(&view.id, OperationKind::HacL1).is_err());
    }

    #[test]
    fn session_lock_clear_destroys_pending_and_approved_operations() {
        let base = Instant::now();
        let mut state = PreparedOperationState::default();
        let view = prepare(
            &mut state,
            "1Recipient",
            AuthorizationRequirement::AnyPlatformFactor,
            base,
        );
        let challenge = state.begin_native(&view.id).unwrap();
        state.finish_native(&view.id, &challenge.nonce).unwrap();
        state.clear();
        assert!(state.take(&view.id, OperationKind::HacL1).is_err());
        assert!(state.begin_native(&view.id).is_err());
    }

    #[test]
    fn digest_binds_all_security_fields() {
        let body = b"canonical";
        let a = operation_digest(OperationKind::HacL1, "1A", "mainnet", Some(0), body);
        assert_ne!(
            a,
            operation_digest(OperationKind::Hacd, "1A", "mainnet", Some(0), body)
        );
        assert_ne!(
            a,
            operation_digest(OperationKind::HacL1, "1B", "mainnet", Some(0), body)
        );
        assert_ne!(
            a,
            operation_digest(OperationKind::HacL1, "1A", "testnet", Some(0), body)
        );
        assert_ne!(
            a,
            operation_digest(OperationKind::HacL1, "1A", "mainnet", Some(1), body)
        );
        assert_ne!(
            a,
            operation_digest(OperationKind::HacL1, "1A", "mainnet", Some(0), b"mutated")
        );
    }

    #[test]
    fn authorization_probe_never_reports_an_unapproved_or_foreign_ticket() {
        let base = Instant::now();
        let mut state = PreparedOperationState::default();
        let view = prepare(
            &mut state,
            "1Recipient",
            AuthorizationRequirement::AnyPlatformFactor,
            base,
        );
        assert!(!state.is_authorized_for(&view.id, OperationKind::HacL1));
        let challenge = state.begin_native(&view.id).unwrap();
        assert!(!state.is_authorized_for(&view.id, OperationKind::HacL1));
        state.finish_native(&view.id, &challenge.nonce).unwrap();

        assert!(state.is_authorized_for(&view.id, OperationKind::HacL1));
        assert!(!state.is_authorized_for("attacker", OperationKind::HacL1));
        assert!(!state.is_authorized_for(&view.id, OperationKind::ColdVaultActivation));
        assert!(!state.is_authorized_for_at(
            &view.id,
            OperationKind::HacL1,
            base + PREPARED_OPERATION_TTL + Duration::from_secs(1)
        ));
        state.clear();
        assert!(!state.is_authorized_for(&view.id, OperationKind::HacL1));
    }

    #[test]
    fn authorization_probe_rejects_native_factor_when_webauthn_is_required() {
        let base = Instant::now();
        let mut state = PreparedOperationState::default();
        let view = prepare(
            &mut state,
            "1Recipient",
            AuthorizationRequirement::WebAuthn,
            base,
        );
        state.begin_webauthn(&view.id).unwrap();
        assert!(!state.is_authorized_for(&view.id, OperationKind::HacL1));
        state.finish_webauthn(&view.id).unwrap();
        assert!(state.is_authorized_for(&view.id, OperationKind::HacL1));
    }

    #[test]
    fn native_prompt_is_sanitized() {
        let mut state = PreparedOperationState::default();
        let view = state
            .prepare(
                OperationKind::HacL1,
                "1Wallet",
                "mainnet",
                Some(0),
                b"body",
                display("1Recipient\nSYSTEM"),
                AuthorizationRequirement::AnyPlatformFactor,
                (),
            )
            .unwrap();
        let challenge = state.begin_native(&view.id).unwrap();
        assert!(!challenge.message.contains('\n'));
        assert!(!challenge.message.contains('\r'));
    }
}

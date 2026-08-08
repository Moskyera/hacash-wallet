//! Restricted desktop companion identity signer.
//!
//! This is not the Hacash blockchain signer. It can receive only typed
//! companion signing requests because the protocol keeps request construction
//! private. Its authority is invalidated and its secret is zeroized when the
//! owning Agent Wallet unlock session ends.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use hpay_companion_protocol::{
    CompanionError, DeviceId, DeviceRole, DeviceSignaturePurpose, DeviceSigningRequest,
    PlatformDeviceIdentity, PlatformDeviceSigner, PlatformP256Signature, PlatformSignFuture,
};
use p256::ecdsa::signature::Signer as _;
use p256::ecdsa::{Signature, SigningKey};
use zeroize::{Zeroize, Zeroizing};

use crate::error::{AgentWalletError, AgentWalletResult};

struct CompanionSigningAuthority {
    enabled: AtomicBool,
    secret: Mutex<Zeroizing<[u8; 32]>>,
}

impl CompanionSigningAuthority {
    fn disable(&self) {
        self.enabled.store(false, Ordering::SeqCst);
        match self.secret.lock() {
            Ok(mut secret) => secret.zeroize(),
            Err(poisoned) => poisoned.into_inner().zeroize(),
        }
    }
}

impl Drop for CompanionSigningAuthority {
    fn drop(&mut self) {
        self.enabled.store(false, Ordering::SeqCst);
        match self.secret.get_mut() {
            Ok(secret) => secret.zeroize(),
            Err(poisoned) => poisoned.into_inner().zeroize(),
        }
    }
}

/// Desktop device identity usable only by typed HPAY companion protocols.
///
/// Clones share one session authority. Lock, timeout, or manager drop disables
/// every clone and zeroizes the shared key bytes. There is no key export method.
#[derive(Clone)]
pub(crate) struct AgentDesktopCompanionSigner {
    identity: PlatformDeviceIdentity,
    authority: Arc<CompanionSigningAuthority>,
}

impl std::fmt::Debug for AgentDesktopCompanionSigner {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AgentDesktopCompanionSigner")
            .field("device_id", self.identity.device_id())
            .field("private_key", &"<non-exportable-session-authority>")
            .finish()
    }
}

impl AgentDesktopCompanionSigner {
    pub(crate) fn from_unlocked_secret(
        device_id: DeviceId,
        secret: &[u8; 32],
    ) -> AgentWalletResult<Self> {
        let signing_key = SigningKey::from_slice(secret).map_err(|_| AgentWalletError::Crypto)?;
        let identity = PlatformDeviceIdentity::new(
            device_id,
            DeviceRole::Desktop,
            signing_key
                .verifying_key()
                .to_encoded_point(true)
                .as_bytes()
                .to_vec(),
        )
        .map_err(|_| AgentWalletError::Crypto)?;
        Ok(Self {
            identity,
            authority: Arc::new(CompanionSigningAuthority {
                enabled: AtomicBool::new(true),
                secret: Mutex::new(Zeroizing::new(*secret)),
            }),
        })
    }

    pub(crate) fn disable(&self) {
        self.authority.disable();
    }

    pub(crate) fn shares_authority_with(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.authority, &other.authority)
            && self.authority.enabled.load(Ordering::SeqCst)
            && other.authority.enabled.load(Ordering::SeqCst)
    }
}

impl PlatformDeviceSigner for AgentDesktopCompanionSigner {
    fn identity(&self) -> &PlatformDeviceIdentity {
        &self.identity
    }

    fn sign<'a>(&'a self, request: DeviceSigningRequest<'a>) -> PlatformSignFuture<'a> {
        Box::pin(async move {
            if !allows_desktop_purpose(request.purpose()) {
                return Err(CompanionError::PermissionDenied);
            }
            if !self.authority.enabled.load(Ordering::SeqCst) {
                return Err(CompanionError::PlatformSignerUnavailable);
            }
            let secret = self
                .authority
                .secret
                .lock()
                .map_err(|_| CompanionError::PlatformSignerUnavailable)?;
            if !self.authority.enabled.load(Ordering::SeqCst) {
                return Err(CompanionError::PlatformSignerUnavailable);
            }
            let signing_key = SigningKey::from_slice(secret.as_ref())
                .map_err(|_| CompanionError::PlatformSignerUnavailable)?;
            let signature: Signature = signing_key.sign(request.canonical_payload());
            PlatformP256Signature::from_fixed_bytes(signature.to_bytes().as_slice())
        })
    }
}

fn allows_desktop_purpose(purpose: DeviceSignaturePurpose) -> bool {
    matches!(
        purpose,
        DeviceSignaturePurpose::PairingConfirmation
            | DeviceSignaturePurpose::SessionChallenge
            | DeviceSignaturePurpose::SessionConfirmation
    ) || (cfg!(feature = "agent-wallet-testnet-pilot")
        && matches!(
            purpose,
            DeviceSignaturePurpose::RollbackAnchor | DeviceSignaturePurpose::RotationPairingTicket
        ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hpay_companion_protocol::{
        CompanionError, MobilePairingAttempt, PairingSession, SoftwareDeviceIdentity,
    };
    use p256::SecretKey;

    #[test]
    fn desktop_purpose_allowlist_rejects_every_mobile_only_authority() {
        assert!(allows_desktop_purpose(
            DeviceSignaturePurpose::PairingConfirmation
        ));
        assert!(allows_desktop_purpose(
            DeviceSignaturePurpose::SessionChallenge
        ));
        assert!(allows_desktop_purpose(
            DeviceSignaturePurpose::SessionConfirmation
        ));
        for denied in [
            DeviceSignaturePurpose::PairingRequest,
            DeviceSignaturePurpose::PairingMobileProof,
            DeviceSignaturePurpose::SessionResponse,
            DeviceSignaturePurpose::ApprovalDecision,
            DeviceSignaturePurpose::AdminCommand,
            DeviceSignaturePurpose::WitnessReceipt,
            DeviceSignaturePurpose::WitnessRotationAuthorization,
            DeviceSignaturePurpose::RotationCandidateAcceptance,
            DeviceSignaturePurpose::WitnessRotationBaselineReceipt,
        ] {
            assert!(!allows_desktop_purpose(denied));
        }
    }

    #[tokio::test]
    async fn typed_pairing_works_until_authority_is_disabled_then_fails_closed() {
        let secret = SecretKey::random(&mut rand::rngs::OsRng).to_bytes();
        let signer = AgentDesktopCompanionSigner::from_unlocked_secret(
            DeviceId::parse("desktop_11111111111111111111111111111111").unwrap(),
            secret.as_ref(),
        )
        .unwrap();
        let mobile = SoftwareDeviceIdentity::generate(DeviceRole::Mobile);
        let mut active = PairingSession::new(&signer, "aw_one", Vec::new(), 100, 60).unwrap();
        let attempt = MobilePairingAttempt::start(active.offer().clone(), &mobile, 101)
            .await
            .unwrap();
        assert!(
            active
                .accept_request(attempt.request().clone(), &signer, 102)
                .await
                .is_ok()
        );

        let mut disabled = PairingSession::new(&signer, "aw_one", Vec::new(), 103, 60).unwrap();
        let attempt = MobilePairingAttempt::start(disabled.offer().clone(), &mobile, 104)
            .await
            .unwrap();
        signer.disable();
        assert!(matches!(
            disabled
                .accept_request(attempt.request().clone(), &signer, 105)
                .await,
            Err(CompanionError::PlatformSignerUnavailable)
        ));
        assert!(!format!("{signer:?}").contains(&hex::encode(secret)));
    }
}

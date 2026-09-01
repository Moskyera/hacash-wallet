//! Android Keystore-backed identity for the HPAY mobile companion.
//!
//! This adapter is intentionally separate from Personal Wallet biometrics and
//! blockchain signing. It exposes no Tauri command and accepts only typed
//! companion-protocol signing requests.

use base64::{Engine as _, engine::general_purpose::STANDARD};
use hpay_companion_protocol::{
    AgentFastPayApprovalDecision, AgentHvmApprovalDecision, ApprovalDecision, CompanionError,
    CompanionResult, DeviceId, DeviceSignaturePurpose, DeviceSigningRequest,
    MobileApprovalDecision, PlatformDeviceIdentity, PlatformDeviceSigner, PlatformP256Signature,
    PlatformSignFuture,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tauri::{
    AppHandle, Manager, Runtime,
    plugin::{Builder, PluginHandle, TauriPlugin},
};

const PLUGIN_NAME: &str = "agent-companion-identity";
const PLUGIN_PACKAGE: &str = "org.hacash.wallet.mobile";
const PLUGIN_CLASS: &str = "AgentCompanionIdentityPlugin";
const DEVICE_ID_DOMAIN: &[u8] = b"HPAY/COMPANION/ANDROID-DEVICE-ID/V1";

struct AgentCompanionNative<R: Runtime>(PluginHandle<R>);

pub fn init<R: Runtime>() -> TauriPlugin<R> {
    Builder::new(PLUGIN_NAME)
        .setup(|app, api| {
            let handle = api.register_android_plugin(PLUGIN_PACKAGE, PLUGIN_CLASS)?;
            app.manage(AgentCompanionNative(handle));
            Ok(())
        })
        .build()
}

fn handle<R: Runtime>(app: &AppHandle<R>) -> Result<PluginHandle<R>, String> {
    app.try_state::<AgentCompanionNative<R>>()
        .map(|native| native.0.clone())
        .ok_or_else(|| "Android Agent companion identity plugin is not registered".to_owned())
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AndroidCompanionIdentityStatus {
    pub configured: bool,
    pub public_key_sec1_hex: Option<String>,
    pub key_security_level: String,
    pub hardware_backed: bool,
    pub strong_box_backed: bool,
    pub authentication_enforced_by_secure_hardware: bool,
    pub auth_per_use: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AndroidAgentActivityClose {
    closed: bool,
}

pub async fn finish_agent_activity<R: Runtime>(app: &AppHandle<R>) -> Result<(), String> {
    let response = handle(app)?
        .run_mobile_plugin_async::<AndroidAgentActivityClose>("finishAgentActivity", ())
        .await
        .map_err(|error| format!("Android Agent companion activity close: {error}"))?;
    if !response.closed {
        return Err("Android Agent companion activity close was not confirmed".to_owned());
    }
    Ok(())
}

async fn native_status<R: Runtime>(
    app: &AppHandle<R>,
    create: bool,
) -> Result<AndroidCompanionIdentityStatus, String> {
    let operation = if create {
        "createIdentity"
    } else {
        "identityStatus"
    };
    handle(app)?
        .run_mobile_plugin_async::<AndroidCompanionIdentityStatus>(operation, ())
        .await
        .map_err(|error| format!("Android Agent companion identity: {error}"))
}

pub async fn status<R: Runtime>(
    app: &AppHandle<R>,
) -> Result<AndroidCompanionIdentityStatus, String> {
    native_status(app, false).await
}

/// Creates the non-exportable key only when called by an explicit pairing flow.
pub async fn create<R: Runtime>(
    app: &AppHandle<R>,
) -> Result<AndroidCompanionIdentitySigner<R>, String> {
    signer_from_status(app.clone(), native_status(app, true).await?)
}

pub async fn open<R: Runtime>(
    app: &AppHandle<R>,
) -> Result<Option<AndroidCompanionIdentitySigner<R>>, String> {
    let status = native_status(app, false).await?;
    if !status.configured {
        return Ok(None);
    }
    signer_from_status(app.clone(), status).map(Some)
}

fn signer_from_status<R: Runtime>(
    app: AppHandle<R>,
    status: AndroidCompanionIdentityStatus,
) -> Result<AndroidCompanionIdentitySigner<R>, String> {
    if !status.configured || !status.auth_per_use {
        return Err("Android companion identity is not protected per use".to_owned());
    }
    if !status.hardware_backed || !status.authentication_enforced_by_secure_hardware {
        return Err("Android companion identity is not hardware protected".to_owned());
    }
    let public_key_hex = status
        .public_key_sec1_hex
        .as_deref()
        .ok_or_else(|| "Android companion identity has no public key".to_owned())?;
    let public_key =
        hex::decode(public_key_hex).map_err(|_| "Android companion public key is invalid")?;
    let device_id = device_id_for_public_key(&public_key)?;
    let identity = PlatformDeviceIdentity::new(
        device_id,
        hpay_companion_protocol::DeviceRole::Mobile,
        public_key,
    )
    .map_err(|error| error.to_string())?;
    Ok(AndroidCompanionIdentitySigner { app, identity })
}

fn device_id_for_public_key(public_key: &[u8]) -> Result<DeviceId, String> {
    let mut digest = Sha256::new();
    digest.update(DEVICE_ID_DOMAIN);
    digest.update(public_key);
    let digest = digest.finalize();
    DeviceId::parse(format!("mobile_{}", hex::encode(&digest[..16])))
        .map_err(|error| error.to_string())
}

pub struct AndroidCompanionIdentitySigner<R: Runtime> {
    app: AppHandle<R>,
    identity: PlatformDeviceIdentity,
}

impl<R: Runtime> std::fmt::Debug for AndroidCompanionIdentitySigner<R> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AndroidCompanionIdentitySigner")
            .field("identity", &self.identity)
            .field("private_key", &"<android-keystore-non-exportable>")
            .finish()
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct NativeSignRequest {
    payload_base64: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct NativeSignResponse {
    signature_der_base64: String,
}

async fn sign_native<R: Runtime>(
    app: &AppHandle<R>,
    purpose: DeviceSignaturePurpose,
    canonical_payload: &[u8],
) -> CompanionResult<PlatformP256Signature> {
    let operation = match purpose {
        DeviceSignaturePurpose::PairingRequest => "signPairingRequest",
        DeviceSignaturePurpose::PairingMobileProof => "signPairingMobileProof",
        DeviceSignaturePurpose::SessionResponse => "signSessionResponse",
        DeviceSignaturePurpose::ApprovalDecision
            if cfg!(feature = "agent-wallet-testnet-pilot") =>
        {
            match MobileApprovalDecision::from_canonical_bytes(canonical_payload)?.decision {
                ApprovalDecision::Approve => "signApprovalDecisionApprove",
                ApprovalDecision::Reject => "signApprovalDecisionReject",
            }
        }
        DeviceSignaturePurpose::AgentFastPayApprovalDecision
            if cfg!(feature = "agent-wallet-testnet-pilot") =>
        {
            match AgentFastPayApprovalDecision::from_canonical_bytes(canonical_payload)?.decision {
                ApprovalDecision::Approve => "signAgentFastPayApprovalDecisionApprove",
                ApprovalDecision::Reject => "signAgentFastPayApprovalDecisionReject",
            }
        }
        DeviceSignaturePurpose::AgentHvmApprovalDecision
            if cfg!(feature = "agent-wallet-testnet-pilot") =>
        {
            match AgentHvmApprovalDecision::from_canonical_bytes(canonical_payload)?.decision {
                ApprovalDecision::Approve => "signAgentHvmApprovalDecisionApprove",
                ApprovalDecision::Reject => "signAgentHvmApprovalDecisionReject",
            }
        }
        DeviceSignaturePurpose::WitnessReceipt if cfg!(feature = "agent-wallet-testnet-pilot") => {
            "signWitnessReceipt"
        }
        // Authorizing this handset's own replacement is not an approval and not
        // a payment witness: it moves no money, signs no transaction, and only
        // ever hands authority away from this phone. It stays available in a
        // read-only build so a handset marked as needing a controlled rotation
        // can actually complete one, instead of being stuck for good.
        DeviceSignaturePurpose::WitnessRotationAuthorization => "signWitnessRotationAuthorization",
        DeviceSignaturePurpose::RotationCandidateAcceptance
            if cfg!(feature = "agent-wallet-testnet-pilot") =>
        {
            "signRotationCandidateAcceptance"
        }
        DeviceSignaturePurpose::WitnessRotationBaselineReceipt
            if cfg!(feature = "agent-wallet-testnet-pilot") =>
        {
            "signWitnessRotationBaselineReceipt"
        }
        DeviceSignaturePurpose::ApprovalDecision
        | DeviceSignaturePurpose::AgentFastPayApprovalDecision
        | DeviceSignaturePurpose::AgentHvmApprovalDecision
        | DeviceSignaturePurpose::AdminCommand
        | DeviceSignaturePurpose::RollbackAnchor
        | DeviceSignaturePurpose::WitnessReceipt
        | DeviceSignaturePurpose::RotationPairingTicket
        | DeviceSignaturePurpose::RotationCandidateAcceptance
        | DeviceSignaturePurpose::WitnessRotationBaselineReceipt
        | DeviceSignaturePurpose::PairingConfirmation
        | DeviceSignaturePurpose::SessionChallenge
        | DeviceSignaturePurpose::SessionConfirmation => {
            return Err(CompanionError::PermissionDenied);
        }
    };
    let response = handle(app)
        .map_err(|_| CompanionError::PlatformSignerUnavailable)?
        .run_mobile_plugin_async::<NativeSignResponse>(
            operation,
            NativeSignRequest {
                payload_base64: STANDARD.encode(canonical_payload),
            },
        )
        .await
        .map_err(|_| CompanionError::PlatformSignerUnavailable)?;
    let der = STANDARD
        .decode(response.signature_der_base64)
        .map_err(|_| CompanionError::InvalidSignature)?;
    PlatformP256Signature::from_der_bytes(der)
}

impl<R: Runtime> PlatformDeviceSigner for AndroidCompanionIdentitySigner<R> {
    fn identity(&self) -> &PlatformDeviceIdentity {
        &self.identity
    }

    fn sign<'a>(&'a self, request: DeviceSigningRequest<'a>) -> PlatformSignFuture<'a> {
        Box::pin(async move {
            sign_native(&self.app, request.purpose(), request.canonical_payload()).await
        })
    }
}

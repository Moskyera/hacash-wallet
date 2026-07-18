//! Android-native operations routed through Tauri's managed Activity lifecycle.
//!
//! The legacy `ndk-context` accessor is lifecycle-bound and panics when its
//! global is unavailable. Native calls instead use a registered mobile plugin
//! so they always receive the live Activity owned by the Tauri runtime.

use serde::{Deserialize, Serialize};
use tauri::{
    AppHandle, Manager, Runtime,
    plugin::{Builder, PluginHandle, TauriPlugin},
};

const PLUGIN_NAME: &str = "wallet-native";
const PLUGIN_PACKAGE: &str = "org.hacash.wallet.mobile";
const PLUGIN_CLASS: &str = "WalletNativePlugin";

struct WalletNative<R: Runtime>(PluginHandle<R>);

pub fn init<R: Runtime>() -> TauriPlugin<R> {
    Builder::new(PLUGIN_NAME)
        .setup(|app, api| {
            let handle = api.register_android_plugin(PLUGIN_PACKAGE, PLUGIN_CLASS)?;
            app.manage(WalletNative(handle));
            Ok(())
        })
        .build()
}

fn handle<R: Runtime>(app: &AppHandle<R>) -> Result<PluginHandle<R>, String> {
    app.try_state::<WalletNative<R>>()
        .map(|native| native.0.clone())
        .ok_or_else(|| "Android wallet-native plugin is not registered".to_string())
}

fn plugin_error(operation: &str, error: impl std::fmt::Display) -> String {
    format!("Android {operation}: {error}")
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ConfiguredResponse {
    configured: bool,
}

pub async fn biometric_is_configured<R: Runtime>(app: &AppHandle<R>) -> Result<bool, String> {
    handle(app)?
        .run_mobile_plugin_async::<ConfiguredResponse>("biometricIsConfigured", ())
        .await
        .map(|response| response.configured)
        .map_err(|error| plugin_error("Keystore status", error))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct StoreBiometricRequest<'a> {
    passphrase: &'a str,
}

pub async fn biometric_store<R: Runtime>(
    app: &AppHandle<R>,
    passphrase: &str,
) -> Result<(), String> {
    handle(app)?
        .run_mobile_plugin_async::<()>("biometricStore", StoreBiometricRequest { passphrase })
        .await
        .map_err(|error| plugin_error("Keystore store", error))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct LoadBiometricResponse {
    passphrase: String,
}

pub async fn biometric_load<R: Runtime>(app: &AppHandle<R>) -> Result<String, String> {
    handle(app)?
        .run_mobile_plugin_async::<LoadBiometricResponse>("biometricLoad", ())
        .await
        .map(|response| response.passphrase)
        .map_err(|error| plugin_error("Keystore load", error))
}

pub async fn biometric_clear<R: Runtime>(app: &AppHandle<R>) -> Result<(), String> {
    handle(app)?
        .run_mobile_plugin_async::<()>("biometricClear", ())
        .await
        .map_err(|error| plugin_error("Keystore clear", error))
}

#[derive(Deserialize)]
struct StrongBiometricStatusResponse {
    available: bool,
    kind: String,
}

pub async fn strong_biometric_status<R: Runtime>(
    app: &AppHandle<R>,
) -> Result<(bool, Option<String>), String> {
    handle(app)?
        .run_mobile_plugin_async::<StrongBiometricStatusResponse>("strongBiometricStatus", ())
        .await
        .map(|response| {
            (
                response.available,
                response.available.then_some(response.kind),
            )
        })
        .map_err(|error| plugin_error("strong biometric status", error))
}

#[derive(Serialize)]
struct AuthenticateStrongRequest<'a> {
    reason: &'a str,
}

pub async fn authenticate_strong<R: Runtime>(
    app: &AppHandle<R>,
    reason: &str,
) -> Result<(), String> {
    handle(app)?
        .run_mobile_plugin_async::<()>("authenticateStrong", AuthenticateStrongRequest { reason })
        .await
        .map_err(|error| plugin_error("strong biometric authentication", error))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct InstallApkRequest<'a> {
    apk_path: &'a str,
}

pub async fn install_apk<R: Runtime>(app: &AppHandle<R>, apk_path: &str) -> Result<(), String> {
    handle(app)?
        .run_mobile_plugin_async::<()>("installApk", InstallApkRequest { apk_path })
        .await
        .map_err(|error| plugin_error("package installer", error))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CopyBackupRequest<'a> {
    source_path: &'a str,
    display_name: &'a str,
}

#[derive(Deserialize)]
struct CopyBackupResponse {
    destination: String,
}

pub async fn copy_backup_to_downloads<R: Runtime>(
    app: &AppHandle<R>,
    source_path: &str,
    display_name: &str,
) -> Result<String, String> {
    handle(app)?
        .run_mobile_plugin_async::<CopyBackupResponse>(
            "copyBackupToDownloads",
            CopyBackupRequest {
                source_path,
                display_name,
            },
        )
        .await
        .map(|response| response.destination)
        .map_err(|error| plugin_error("backup export", error))
}

#[derive(Serialize)]
struct DeleteBackupRequest<'a> {
    source: &'a str,
}

pub async fn delete_backup_source<R: Runtime>(
    app: &AppHandle<R>,
    source: &str,
) -> Result<(), String> {
    handle(app)?
        .run_mobile_plugin_async::<()>("deleteBackupSource", DeleteBackupRequest { source })
        .await
        .map_err(|error| plugin_error("backup deletion", error))
}

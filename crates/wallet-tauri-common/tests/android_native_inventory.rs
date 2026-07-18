use std::fs;
use std::path::{Path, PathBuf};

const NATIVE_COMMANDS: [&str; 9] = [
    "biometricIsConfigured",
    "biometricStore",
    "biometricLoad",
    "biometricClear",
    "strongBiometricStatus",
    "authenticateStrong",
    "installApk",
    "copyBackupToDownloads",
    "deleteBackupSource",
];

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read(root: &Path, relative: &str) -> String {
    fs::read_to_string(root.join(relative))
        .unwrap_or_else(|error| panic!("read {relative}: {error}"))
}

fn rust_sources(path: &Path, output: &mut Vec<PathBuf>) {
    for entry in
        fs::read_dir(path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()))
    {
        let entry = entry.expect("directory entry");
        let path = entry.path();
        if path.is_dir() {
            rust_sources(&path, output);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            output.push(path);
        }
    }
}

#[test]
fn android_native_operations_use_one_managed_tauri_plugin() {
    let root = repo_root();
    let native_rust = read(&root, "crates/wallet-tauri-common/src/android_native.rs");
    let native_kotlin = read(
        &root,
        "apps/mobile/src-tauri/android-src/org/hacash/wallet/mobile/WalletNativePlugin.kt",
    );
    let mobile_lib = read(&root, "apps/mobile/src-tauri/src/lib.rs");

    assert!(
        mobile_lib.contains("builder.plugin(wallet_tauri_common::android_native::init())"),
        "the mobile builder must register the wallet-native plugin"
    );
    assert!(native_kotlin.contains("@TauriPlugin"));
    assert!(native_kotlin.contains("class WalletNativePlugin"));

    for command in NATIVE_COMMANDS {
        assert!(
            native_rust.contains(&format!("\"{command}\"")),
            "Rust plugin bridge is missing {command}"
        );
        assert!(
            native_kotlin.contains(&format!("fun {command}(")),
            "Kotlin plugin is missing {command}"
        );
    }
}

#[test]
fn wallet_code_has_no_legacy_direct_android_context_calls() {
    let root = repo_root();
    for manifest in [
        "apps/mobile/src-tauri/Cargo.toml",
        "crates/wallet-tauri-common/Cargo.toml",
    ] {
        let source = read(&root, manifest);
        assert!(
            !source.lines().any(|line| {
                let line = line.trim_start();
                line.starts_with("jni =") || line.starts_with("ndk-context =")
            }),
            "{manifest} must not directly depend on JNI or ndk-context"
        );
    }

    let mut sources = Vec::new();
    rust_sources(&root.join("apps/mobile/src-tauri/src"), &mut sources);
    rust_sources(&root.join("crates/wallet-tauri-common/src"), &mut sources);
    for path in sources {
        let source = fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
        assert!(
            !source.contains("ndk_context::") && !source.contains("jni::"),
            "{} bypasses Tauri's managed Android lifecycle",
            path.display()
        );
    }
}

#[test]
fn android_9_backup_export_has_a_scoped_runtime_permission_flow() {
    let root = repo_root();
    let native_kotlin = read(
        &root,
        "apps/mobile/src-tauri/android-src/org/hacash/wallet/mobile/WalletNativePlugin.kt",
    );
    let manifest_permissions = read(&root, "apps/mobile/src-tauri/android-permissions.xml");
    let backup_helper = read(
        &root,
        "apps/mobile/src-tauri/android-src/org/hacash/wallet/mobile/BackupExportHelper.kt",
    );

    assert_eq!(
        manifest_permissions
            .matches("android.permission.WRITE_EXTERNAL_STORAGE")
            .count(),
        1,
        "legacy storage permission must be declared exactly once"
    );
    assert!(
        manifest_permissions
            .contains(r#"android.permission.WRITE_EXTERNAL_STORAGE" android:maxSdkVersion="28""#),
        "legacy storage permission must be capped to Android 9"
    );
    for contract in [
        "Manifest.permission.WRITE_EXTERNAL_STORAGE",
        "requestPermissionForAlias(",
        "@PermissionCallback",
        "fun copyBackupPermissionResult(",
        "getPermissionState(BACKUP_DOWNLOADS_PERMISSION)",
    ] {
        assert!(
            native_kotlin.contains(contract),
            "Android 9 backup permission flow is missing {contract}"
        );
    }
    for filename_guard in [
        "displayName.length > 128",
        "File(displayName).name != displayName",
        "it == '/'",
        "it.code == 92",
        "it.isISOControl()",
    ] {
        assert!(
            backup_helper.contains(filename_guard),
            "Android backup filename validation is missing {filename_guard}"
        );
    }
}

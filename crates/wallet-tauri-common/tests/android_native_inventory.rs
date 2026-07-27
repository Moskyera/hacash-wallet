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
    for streaming_contract in [
        "MAX_BACKUP_BYTES = 64L * 1024L * 1024L",
        "source.parentFile != cacheRoot",
        "Files.isSymbolicLink(requestedSource.toPath())",
        "FileInputStream(source).use",
        "copyBounded(input, stream)",
        "buffer.fill(0)",
        "MediaStore.Downloads.IS_PENDING",
        "uri?.let { activity.contentResolver.delete(it, null, null) }",
        "temporary.renameTo(destination)",
    ] {
        assert!(
            backup_helper.contains(streaming_contract),
            "Android backup bounded-streaming contract is missing {streaming_contract}"
        );
    }
    assert!(!backup_helper.contains("readBytes()"));
    assert!(!backup_helper.contains("writeBytes(bytes)"));
}

/// The Kotlin helper accepts a source file only if its parent is exactly
/// `activity.cacheDir`, the app's private cache. Tauri's Android path resolver maps
/// `cache_dir()` to `getExternalCacheDir` and only `app_cache_dir()` to `getCacheDir`,
/// so staging with `cache_dir()` makes every Android backup export fail. Nothing
/// asserted that the two sides agreed, which is how it shipped.
#[test]
fn backup_export_stages_the_file_where_the_native_helper_accepts_it() {
    let root = repo_root();
    let export = read(&root, "crates/wallet-tauri-common/src/backup_commands.rs");
    let backup_helper = read(
        &root,
        "apps/mobile/src-tauri/android-src/org/hacash/wallet/mobile/BackupExportHelper.kt",
    );

    let staging = export
        .split_once("pub async fn wallet_export_backup_to_downloads(")
        .expect("backup export command")
        .1
        .split_once("copy_backup_file_to_downloads")
        .expect("native copy call")
        .0;

    assert!(
        staging.contains("app.path().app_cache_dir()"),
        "the backup must be staged with app_cache_dir(), which is the private cache the \
         native helper requires"
    );
    assert!(
        !staging.contains("app.path().cache_dir()"),
        "cache_dir() is the EXTERNAL cache on Android; the native helper rejects it and \
         the encrypted key must not be staged on shared storage"
    );
    assert!(
        backup_helper.contains("val cacheRoot = activity.cacheDir.canonicalFile"),
        "the native helper must keep pinning the private cache as the only valid parent"
    );
    // The update flow shares this constraint, so it must not regress either.
    let update = read(&root, "crates/wallet-tauri-common/src/update_commands.rs");
    assert!(
        !update.contains("app.path().cache_dir()"),
        "the APK update download must stay in the private cache as well"
    );
}

/// The mobile Security screen only disables the Paranoid button. A disabled control is
/// a suggestion, not a policy, so the command has to refuse it as well: Paranoid demands
/// a WebAuthn ceremony for every send that Android cannot perform, which would stop every
/// send on the device. Compiled out on desktop, so this asserts the source contract.
#[test]
fn android_refuses_the_paranoid_profile_at_the_command_layer() {
    let root = repo_root();
    let commands = read(&root, "crates/wallet-tauri-common/src/commands.rs");

    let profile_command = commands
        .split_once("pub fn wallet_set_security_profile(")
        .expect("security profile command")
        .1
        .split_once("svc.change_security_profile(")
        .expect("profile change call")
        .0;

    assert!(
        profile_command.contains("#[cfg(target_os = \"android\")]"),
        "the refusal must be Android-only, since desktop can complete the WebAuthn ceremony"
    );
    assert!(
        profile_command.contains("if profile == \"paranoid\""),
        "the command must reject the paranoid profile on Android before applying it"
    );
    assert!(
        profile_command.contains("return Err("),
        "rejecting means returning an error, not silently substituting another profile"
    );

    // Cold Vault legitimately runs on the paranoid profile, and it must keep working.
    // It reaches that profile through the vault migration, never through this command.
    let wallet = read(&root, "crates/wallet-core/src/wallet.rs");
    assert!(
        wallet.contains("target_profile = SecurityProfile::paranoid();"),
        "Cold Vault must keep setting the paranoid profile directly in the migration"
    );
}

#[test]
fn windows_android_release_fallback_reuses_the_verified_native_library() {
    let root = repo_root();
    let build_script = read(&root, "apps/mobile/build-android.ps1");

    for contract in [
        r#""yarn.cmd""#,
        "run tauri -- android build --ci --target aarch64 --apk",
        "Copy-Item -LiteralPath $nativeLib",
        "assembleUniversalRelease -x :app:rustBuildArm64Release",
        "verify-release-apk.ps1",
    ] {
        assert!(
            build_script.contains(contract),
            "Windows Android release fallback is missing {contract}"
        );
    }
}

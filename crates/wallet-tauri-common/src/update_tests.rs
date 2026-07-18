use super::download::validate_downloaded_update_as;
use super::*;
use sha2::{Digest, Sha256};
use std::io::Write;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

fn release_asset(tag: &str, name: &str, digest: Option<String>) -> GhAsset {
    GhAsset {
        name: name.into(),
        browser_download_url: format!(
            "https://github.com/{GITHUB_REPO}/releases/download/{tag}/{name}"
        ),
        size: 600_002,
        digest,
        state: "uploaded".into(),
    }
}

fn trusted_update(channel: UpdateChannel) -> TrustedUpdate {
    let (asset_name, download_url) = match channel {
        UpdateChannel::Desktop => (
            "hacash-wallet-desktop-v0.1.55-x64-setup.exe",
            "https://github.com/Moskyera/hacash-wallet/releases/download/v0.1.55-desktop/hacash-wallet-desktop-v0.1.55-x64-setup.exe",
        ),
        UpdateChannel::Mobile => (
            "hacash-wallet-mobile-v0.1.55-arm64.apk",
            "https://github.com/Moskyera/hacash-wallet/releases/download/v0.1.55-mobile/hacash-wallet-mobile-v0.1.55-arm64.apk",
        ),
    };
    TrustedUpdate {
        channel,
        download_url: download_url.into(),
        asset_name: asset_name.into(),
        download_size: 600_002,
        sha256: "a".repeat(64),
    }
}

#[test]
fn validate_apk_rejects_tiny_or_non_zip() {
    let dir = tempfile::tempdir().unwrap();
    let tiny = dir.path().join("tiny.apk");
    std::fs::write(&tiny, b"x").unwrap();
    assert!(validate_apk_file(&tiny).is_err());

    let bad = dir.path().join("bad.apk");
    std::fs::write(&bad, vec![0u8; 200_000]).unwrap();
    assert!(validate_apk_file(&bad).is_err());
}

#[test]
fn validate_downloaded_update_routes_by_extension() {
    let dir = tempfile::tempdir().unwrap();
    let exe = dir.path().join("u.exe");
    let mut file = std::fs::File::create(&exe).unwrap();
    file.write_all(b"MZ").unwrap();
    file.write_all(&vec![0u8; 600_000]).unwrap();
    assert!(validate_downloaded_update(&exe).is_ok());

    let apk = dir.path().join("u.apk");
    let mut file = std::fs::File::create(&apk).unwrap();
    file.write_all(&[0x50, 0x4B, 0x03, 0x04]).unwrap();
    file.write_all(&vec![0u8; 200_000]).unwrap();
    assert!(validate_downloaded_update(&apk).is_ok());
}

#[test]
fn staged_part_files_validate_against_trusted_destination_type() {
    let dir = tempfile::tempdir().unwrap();

    let exe = dir.path().join("setup.exe.part");
    let mut file = std::fs::File::create(&exe).unwrap();
    file.write_all(b"MZ").unwrap();
    file.write_all(&vec![0u8; 600_000]).unwrap();
    drop(file);
    assert!(validate_downloaded_update_as(&exe, "exe").is_ok());

    let apk = dir.path().join("wallet.apk.part");
    let mut file = std::fs::File::create(&apk).unwrap();
    file.write_all(&[0x50, 0x4B, 0x03, 0x04]).unwrap();
    file.write_all(&vec![0u8; 200_000]).unwrap();
    drop(file);
    assert!(validate_downloaded_update_as(&apk, "apk").is_ok());

    let msi = dir.path().join("wallet.msi.part");
    let mut file = std::fs::File::create(&msi).unwrap();
    file.write_all(&[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1])
        .unwrap();
    file.write_all(&vec![0u8; 600_000]).unwrap();
    drop(file);
    assert!(validate_downloaded_update_as(&msi, "msi").is_ok());
    assert!(validate_downloaded_update_as(&msi, "part").is_err());
}

#[test]
fn semver_and_release_tags_are_strict() {
    assert_eq!(parse_semver_triplet("0.1.30"), Some((0, 1, 30)));
    assert_eq!(parse_semver_triplet("v0.1.30-mobile"), Some((0, 1, 30)));
    assert_eq!(parse_semver_triplet("1.2.3.4"), None);
    assert_eq!(parse_semver_triplet("vv1.2.3"), None);
    assert_eq!(parse_semver_triplet("1.2.3-rc1"), None);
    assert_eq!(
        parse_release_triplet("v0.1.55-mobile", UpdateChannel::Mobile),
        Some((0, 1, 55))
    );
    assert_eq!(
        parse_release_triplet("v0.1.55-desktop", UpdateChannel::Mobile),
        None
    );
    assert_eq!(
        parse_release_triplet("v0.01.55-mobile", UpdateChannel::Mobile),
        None
    );
}

#[test]
fn release_urls_are_pinned_to_exact_tag_and_filename() {
    let name = "hacash-wallet-mobile-v0.1.55-arm64.apk";
    let valid = format!("https://github.com/{GITHUB_REPO}/releases/download/v0.1.55-mobile/{name}");
    assert!(validate_release_asset_url(&valid, "v0.1.55-mobile", name).is_ok());
    assert!(validate_release_asset_url(&valid, "v0.1.54-mobile", name).is_err());
    assert!(validate_release_asset_url(&valid, "v0.1.55-mobile", "other.apk").is_err());
    assert!(
        validate_release_download_url(
            "https://github.com:444/Moskyera/hacash-wallet/releases/download/v1/update.apk"
        )
        .is_err()
    );
    assert!(
        validate_release_download_url(
            "https://github.com/Moskyera/hacash-wallet.evil/releases/download/v1/update.apk"
        )
        .is_err()
    );
}

#[test]
fn eligible_assets_require_exact_version_architecture_and_preference() {
    let tag = "v0.1.55-desktop";
    let release = GhRelease {
        tag_name: tag.into(),
        name: None,
        body: None,
        draft: false,
        prerelease: false,
        assets: vec![
            release_asset(
                tag,
                "hacash-wallet-desktop-v0.1.54-x64-setup.exe",
                Some(format!("sha256:{}", "1".repeat(64))),
            ),
            release_asset(
                tag,
                "hacash-wallet-desktop-v0.1.55-arm64-setup.exe",
                Some(format!("sha256:{}", "2".repeat(64))),
            ),
            release_asset(
                tag,
                "hacash-wallet-desktop-v0.1.55-x64-portable.exe",
                Some(format!("sha256:{}", "3".repeat(64))),
            ),
            release_asset(
                tag,
                "hacash-wallet-desktop-v0.1.55-x64.msi",
                Some(format!("sha256:{}", "4".repeat(64))),
            ),
            release_asset(
                tag,
                "hacash-wallet-desktop-v0.1.55-x64-setup.exe",
                Some(format!("sha256:{}", "5".repeat(64))),
            ),
        ],
    };
    let eligible = eligible_assets(
        &release,
        &UpdateTarget::from_parts("windows", "x86_64"),
        (0, 1, 55),
    );
    assert_eq!(eligible.len(), 2);
    assert_eq!(
        eligible[0].asset.name,
        "hacash-wallet-desktop-v0.1.55-x64.msi"
    );
    assert_eq!(
        eligible[1].asset.name,
        "hacash-wallet-desktop-v0.1.55-x64-setup.exe"
    );
}

#[test]
fn desktop_setup_is_used_only_when_the_preferred_msi_is_ineligible() {
    let tag = "v0.1.55-desktop";
    let mut invalid_msi = release_asset(
        tag,
        "hacash-wallet-desktop-v0.1.55-x64.msi",
        Some(format!("sha256:{}", "4".repeat(64))),
    );
    invalid_msi.state = "new".into();
    let release = GhRelease {
        tag_name: tag.into(),
        name: None,
        body: None,
        draft: false,
        prerelease: false,
        assets: vec![
            release_asset(
                tag,
                "hacash-wallet-desktop-v0.1.55-x64-setup.exe",
                Some(format!("sha256:{}", "5".repeat(64))),
            ),
            invalid_msi,
        ],
    };

    let eligible = eligible_assets(
        &release,
        &UpdateTarget::from_parts("windows", "x86_64"),
        (0, 1, 55),
    );
    assert_eq!(eligible.len(), 1);
    assert_eq!(
        eligible[0].asset.name,
        "hacash-wallet-desktop-v0.1.55-x64-setup.exe"
    );
    assert_eq!(eligible[0].priority, 1);
}

#[test]
fn linux_never_selects_or_offers_windows_installers() {
    let tag = "v0.1.55-desktop";
    let release = GhRelease {
        tag_name: tag.into(),
        name: None,
        body: None,
        draft: false,
        prerelease: false,
        assets: vec![
            release_asset(
                tag,
                "hacash-wallet-desktop-v0.1.55-x64-setup.exe",
                Some(format!("sha256:{}", "1".repeat(64))),
            ),
            release_asset(
                tag,
                "hacash-wallet-desktop-v0.1.55-x64.msi",
                Some(format!("sha256:{}", "2".repeat(64))),
            ),
            release_asset(
                tag,
                "hacash-wallet-desktop-v0.1.55-x64.AppImage",
                Some(format!("sha256:{}", "3".repeat(64))),
            ),
        ],
    };

    let linux = UpdateTarget::from_parts("LiNuX", "X86_64");
    assert_eq!(linux.channel(), UpdateChannel::Desktop);
    assert!(!linux.supports_automatic_install());
    let eligible = eligible_assets(&release, &linux, (0, 1, 55));
    assert!(eligible.is_empty());
    assert!(
        update_asset_priority(
            &linux,
            "0.1.55",
            "hacash-wallet-desktop-v0.1.55-x64-setup.exe"
        )
        .is_none()
    );
    assert!(
        update_asset_priority(&linux, "0.1.55", "hacash-wallet-desktop-v0.1.55-x64.msi").is_none()
    );
    assert_eq!(
        release_page(tag),
        "https://github.com/Moskyera/hacash-wallet/releases/tag/v0.1.55-desktop"
    );
}

#[test]
fn update_target_derivation_gates_automatic_install_by_os_and_arch() {
    let windows = UpdateTarget::from_parts("windows", "x86_64");
    assert_eq!(windows.channel(), UpdateChannel::Desktop);
    assert!(windows.supports_automatic_install());

    let android = UpdateTarget::from_parts("android", "aarch64");
    assert_eq!(android.channel(), UpdateChannel::Mobile);
    assert!(android.supports_automatic_install());

    let ios = UpdateTarget::from_parts("ios", "aarch64");
    assert_eq!(ios.channel(), UpdateChannel::Mobile);
    assert!(!ios.supports_automatic_install());

    let windows_arm = UpdateTarget::from_parts("windows", "aarch64");
    assert!(!windows_arm.supports_automatic_install());
}

#[tokio::test]
async fn native_digest_does_not_load_checksum_file() {
    let calls = Arc::new(AtomicUsize::new(0));
    let counter = calls.clone();
    let asset = release_asset(
        "v0.1.55-mobile",
        "hacash-wallet-mobile-v0.1.55-arm64.apk",
        Some(format!("sha256:{}", "a".repeat(64))),
    );
    let trusted = resolve_trusted_asset(
        vec![EligibleAsset {
            priority: 0,
            channel: UpdateChannel::Mobile,
            asset,
        }],
        move || async move {
            counter.fetch_add(1, Ordering::SeqCst);
            Err("must not run".into())
        },
    )
    .await
    .unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(trusted.sha256, "a".repeat(64));
}

#[tokio::test]
async fn missing_digest_loads_sums_once_and_preserves_asset_priority() {
    let calls = Arc::new(AtomicUsize::new(0));
    let counter = calls.clone();
    let setup_name = "hacash-wallet-desktop-v0.1.55-x64-setup.exe";
    let setup = release_asset("v0.1.55-desktop", setup_name, None);
    let msi = release_asset(
        "v0.1.55-desktop",
        "hacash-wallet-desktop-v0.1.55-x64.msi",
        Some(format!("sha256:{}", "b".repeat(64))),
    );
    let trusted = resolve_trusted_asset(
        vec![
            EligibleAsset {
                priority: 0,
                channel: UpdateChannel::Desktop,
                asset: setup,
            },
            EligibleAsset {
                priority: 1,
                channel: UpdateChannel::Desktop,
                asset: msi,
            },
        ],
        move || async move {
            counter.fetch_add(1, Ordering::SeqCst);
            Ok(HashMap::from([(setup_name.to_string(), "c".repeat(64))]))
        },
    )
    .await
    .unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(trusted.asset_name, setup_name);
    assert_eq!(trusted.sha256, "c".repeat(64));
}

#[tokio::test]
async fn failed_sums_fall_through_to_native_digest_candidate() {
    let calls = Arc::new(AtomicUsize::new(0));
    let counter = calls.clone();
    let setup = release_asset(
        "v0.1.55-desktop",
        "hacash-wallet-desktop-v0.1.55-x64-setup.exe",
        None,
    );
    let msi_name = "hacash-wallet-desktop-v0.1.55-x64.msi";
    let msi = release_asset(
        "v0.1.55-desktop",
        msi_name,
        Some(format!("sha256:{}", "d".repeat(64))),
    );
    let trusted = resolve_trusted_asset(
        vec![
            EligibleAsset {
                priority: 0,
                channel: UpdateChannel::Desktop,
                asset: setup,
            },
            EligibleAsset {
                priority: 1,
                channel: UpdateChannel::Desktop,
                asset: msi,
            },
        ],
        move || async move {
            counter.fetch_add(1, Ordering::SeqCst);
            Err("offline".into())
        },
    )
    .await
    .unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(trusted.asset_name, msi_name);
}

#[test]
fn checksum_parser_rejects_duplicates_and_malformed_entries() {
    let name = "hacash-wallet-mobile-v0.1.55-arm64.apk";
    let valid = format!("{}  {name}\n", "a".repeat(64));
    assert_eq!(parse_sha256_sums(&valid).unwrap()[name], "a".repeat(64));
    assert!(parse_sha256_sums(&format!("{valid}{valid}")).is_err());
    assert!(parse_sha256_sums("not-a-hash  file.apk\n").is_err());
    assert!(parse_sha256_sums(&format!("{}  ../file.apk\n", "a".repeat(64))).is_err());
    assert!(parse_sha256_sums("# comments only\n").is_err());
}

#[test]
fn offer_store_enforces_phase_channel_and_expiry() {
    let store = UpdateOfferStore::new();
    let now = Instant::now();
    let id = store.register_at(trusted_update(UpdateChannel::Mobile), now);
    assert!(uuid::Uuid::parse_str(&id).is_ok());
    assert!(store.begin_download_at(&id, now).is_ok());
    assert!(store.begin_download_at(&id, now).is_err());
    store
        .download_complete_at(&id, PathBuf::from("verified.apk"), now)
        .unwrap();
    assert!(store.downloaded_at(&id, UpdateChannel::Mobile, now).is_ok());
    assert!(
        store
            .downloaded_at(&id, UpdateChannel::Mobile, now + Duration::from_secs(1))
            .is_ok()
    );

    assert!(
        store
            .downloaded_at(&id, UpdateChannel::Desktop, now)
            .is_err()
    );
    assert!(
        store
            .downloaded_at(
                &id,
                UpdateChannel::Mobile,
                now + UPDATE_OFFER_TTL + Duration::from_secs(1),
            )
            .is_err()
    );

    let expired_ready = store.register_at(trusted_update(UpdateChannel::Desktop), now);
    assert!(
        store
            .begin_download_at(
                &expired_ready,
                now + UPDATE_OFFER_TTL + Duration::from_secs(1),
            )
            .is_err()
    );

    let expired_download = store.register_at(trusted_update(UpdateChannel::Desktop), now);
    assert!(store.begin_download_at(&expired_download, now).is_ok());
    assert!(
        store
            .download_complete_at(
                &expired_download,
                PathBuf::from("expired.msi"),
                now + UPDATE_OFFER_TTL + Duration::from_secs(1),
            )
            .is_err()
    );
}

#[test]
fn failed_download_can_be_retried() {
    let store = UpdateOfferStore::new();
    let id = store.register(trusted_update(UpdateChannel::Desktop));
    assert!(store.begin_download(&id).is_ok());
    store.download_failed(&id);
    assert!(store.begin_download(&id).is_ok());
}

#[test]
fn install_time_verification_detects_size_and_hash_changes() {
    let dir = tempfile::tempdir().unwrap();
    let installer = dir.path().join("setup.exe");
    let mut file = std::fs::File::create(&installer).unwrap();
    file.write_all(b"MZ").unwrap();
    file.write_all(&vec![7u8; 600_000]).unwrap();
    drop(file);
    let bytes = std::fs::read(&installer).unwrap();
    let sha256 = format!("{:x}", Sha256::digest(&bytes));
    assert!(verify_downloaded_update(&installer, &sha256, bytes.len() as u64).is_ok());
    assert!(verify_downloaded_update(&installer, &sha256, bytes.len() as u64 + 1).is_err());
    std::fs::OpenOptions::new()
        .append(true)
        .open(&installer)
        .unwrap()
        .write_all(b"tamper")
        .unwrap();
    assert!(verify_downloaded_update(&installer, &sha256, bytes.len() as u64).is_err());
}

#[test]
fn update_offer_serialization_is_discriminated_and_opaque() {
    let release_page = "https://github.com/Moskyera/hacash-wallet/releases/tag/v0.1.55-mobile";
    let untrusted = serde_json::to_value(AppUpdateInfo::AvailableUntrusted {
        current_version: "0.1.54".into(),
        latest_version: "v0.1.55".into(),
        release_notes: None,
        release_page: release_page.into(),
        target_os: "android".into(),
        target_arch: "aarch64".into(),
    })
    .unwrap();
    assert_eq!(untrusted["status"], "available_untrusted");
    assert!(untrusted.get("offer_id").is_none());

    let manual = serde_json::to_value(AppUpdateInfo::AvailableManual {
        current_version: "0.1.54".into(),
        latest_version: "v0.1.55".into(),
        release_notes: None,
        release_page: release_page.into(),
        target_os: "linux".into(),
        target_arch: "x86_64".into(),
    })
    .unwrap();
    assert_eq!(manual["status"], "available_manual");
    assert!(manual.get("offer_id").is_none());

    let trusted = serde_json::to_value(AppUpdateInfo::AvailableTrusted {
        current_version: "0.1.54".into(),
        latest_version: "v0.1.55".into(),
        release_notes: None,
        release_page: release_page.into(),
        target_os: "android".into(),
        target_arch: "aarch64".into(),
        offer_id: "opaque-offer".into(),
        asset_name: "hacash-wallet-mobile-v0.1.55-arm64.apk".into(),
        download_size: 123_456,
    })
    .unwrap();
    assert_eq!(trusted["status"], "available_trusted");
    assert_eq!(trusted["offer_id"], "opaque-offer");
    assert!(trusted.get("download_url").is_none());
    assert!(trusted.get("sha256").is_none());
}

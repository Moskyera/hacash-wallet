//! The user-chosen second-factor threshold may only tighten the authenticated policy.
//!
//! The profile lives in the vault and is bound to the key through the vault metadata.
//! The chosen amount lives in settings.json, which is bound to nothing, so the only
//! thing that makes it safe to honour is that it can never raise the profile's ceiling.

mod common;

use common::{tier0_gate, with_isolated_wallet_dir};
use hacash_wallet_core::WalletService;
use hacash_wallet_core::security::effective_second_factor_threshold;

const PASSPHRASE: &str = "threshold-passphrase12";

#[test]
fn a_chosen_amount_can_only_lower_the_profile_ceiling() {
    // Balanced allows 100. Anything lower is honoured.
    assert_eq!(effective_second_factor_threshold(100, None), 100);
    assert_eq!(effective_second_factor_threshold(100, Some(5)), 5);
    assert_eq!(effective_second_factor_threshold(100, Some(100)), 100);

    // The tampering case that matters: a settings file asking for a weaker policy.
    assert_eq!(effective_second_factor_threshold(100, Some(101)), 100);
    assert_eq!(effective_second_factor_threshold(100, Some(u64::MAX)), 100);

    // Paranoid already needs a factor for everything, so no preference can loosen it.
    assert_eq!(effective_second_factor_threshold(1, Some(50)), 1);
    assert_eq!(effective_second_factor_threshold(1, None), 1);

    // Zero would read as "no threshold at all", the opposite of a small number.
    assert_eq!(effective_second_factor_threshold(100, Some(0)), 1);
}

#[test]
fn the_wallet_enforces_the_chosen_amount_and_reports_it() {
    tier0_gate("threshold_enforced", || {
        with_isolated_wallet_dir(|| {
            let mut svc = WalletService::new(None, None).unwrap();
            svc.create_wallet(PASSPHRASE).unwrap();

            assert_eq!(svc.second_factor_threshold_mei(), 100);
            assert_eq!(svc.status().require_second_factor_above_mei, 100);

            svc.set_second_factor_threshold(PASSPHRASE, Some(5))
                .unwrap();
            assert_eq!(svc.second_factor_threshold_mei(), 5);
            assert_eq!(
                svc.status().require_second_factor_above_mei,
                5,
                "the interface must be told the value that is actually enforced"
            );

            // Above the ceiling: stored, but ignored rather than obeyed.
            svc.set_second_factor_threshold(PASSPHRASE, Some(10_000))
                .unwrap();
            assert_eq!(svc.second_factor_threshold_mei(), 100);
            assert_eq!(svc.status().require_second_factor_above_mei, 100);

            // None restores the profile's own value.
            svc.set_second_factor_threshold(PASSPHRASE, None).unwrap();
            assert_eq!(svc.second_factor_threshold_mei(), 100);
        });
    });
}

#[test]
fn lowering_the_threshold_makes_a_smaller_send_need_a_factor() {
    tier0_gate("threshold_gates_send", || {
        with_isolated_wallet_dir(|| {
            let mut svc = WalletService::new(None, None).unwrap();
            svc.create_wallet(PASSPHRASE).unwrap();
            let rt = tokio::runtime::Runtime::new().unwrap();

            // 10 HAC is below the default ceiling, so policy does not gate it and the
            // send proceeds far enough to fail on balance instead.
            let before = rt
                .block_on(svc.send_hac(
                    "1AVRuFXNFi3rdMrPH4hdqSgFrEBnWisWaS",
                    10.0,
                    Default::default(),
                ))
                .unwrap_err()
                .to_string();
            assert!(
                before.contains("Insufficient balance"),
                "10 HAC must reach the balance check at the default threshold, meaning no \
                 factor was demanded, got: {before}"
            );

            svc.set_second_factor_threshold(PASSPHRASE, Some(5))
                .unwrap();

            // Same amount, now at or above the chosen threshold, so it never reaches the
            // balance check. Two guards can refuse it and either is correct: the session
            // factor check runs first and asks for a confirmation, and the unprepared
            // barrier would refuse afterwards because authorization cannot be bound to
            // this path. What matters is that the payment no longer goes through
            // unchallenged, so accept either refusal rather than pinning the order.
            let after = rt
                .block_on(svc.send_hac(
                    "1AVRuFXNFi3rdMrPH4hdqSgFrEBnWisWaS",
                    10.0,
                    Default::default(),
                ))
                .unwrap_err()
                .to_string();
            assert!(
                after.contains("confirmation required")
                    || after.contains("prepared-operation authorization"),
                "10 HAC must need a factor once the threshold is 5, got: {after}"
            );
            assert!(
                !after.contains("Insufficient balance"),
                "the refusal must happen before the wallet ever looks at the balance, got: {after}"
            );
        });
    });
}

#[test]
fn changing_the_threshold_needs_the_passphrase_and_its_own_command() {
    tier0_gate("threshold_needs_passphrase", || {
        with_isolated_wallet_dir(|| {
            let mut svc = WalletService::new(None, None).unwrap();
            svc.create_wallet(PASSPHRASE).unwrap();

            assert!(
                svc.set_second_factor_threshold("wrong-passphrase12", Some(5))
                    .is_err()
            );
            assert_eq!(svc.second_factor_threshold_mei(), 100);

            // The generic settings path must refuse it, so the authenticated command is
            // the only way in.
            let mut settings = svc.get_settings();
            settings.require_second_factor_above_mei = Some(5);
            assert!(
                svc.update_settings(settings).is_err(),
                "a signing policy change must not ride in on generic settings"
            );
            assert_eq!(svc.second_factor_threshold_mei(), 100);

            // Zero is meaningless and refused outright.
            assert!(
                svc.set_second_factor_threshold(PASSPHRASE, Some(0))
                    .is_err()
            );
        });
    });
}

#[test]
fn zero_is_refused_by_validation_and_dropped_by_normalisation() {
    let settings = hacash_wallet_core::settings::WalletSettings {
        require_second_factor_above_mei: Some(0),
        ..Default::default()
    };
    assert!(settings.clone().validate_and_normalize().is_err());

    let mut normalised = settings;
    normalised.normalize();
    assert_eq!(normalised.require_second_factor_above_mei, None);
}

/// Nothing outside the two accessors may read the profile threshold directly. Every
/// policy path has to see the user's choice, and this repository has already shipped two
/// bugs of exactly this shape: one site left reading a stale value while the others
/// moved on.
#[test]
fn every_policy_path_reads_the_threshold_through_the_accessor() {
    // Named so the offset arithmetic below is not a magic number, and so the one needle
    // this walker greps for is stated once.
    const FIELD: &str = "profile.require_second_factor_above_mei";
    // Expressed numerically so the escape cannot be mangled by tooling.
    let newline = char::from(10u8);
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut offenders = Vec::new();
    // The IPC crate has no policy read today, but it is where one would most plausibly be
    // added, so it is walked as well. A guard that only covers the crate you happened to
    // be editing is the reason this gap keeps reappearing.
    let mut stack = vec![root.join("src"), root.join("../wallet-tauri-common/src")];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).expect("read source dir") {
            let path = entry.expect("dir entry").path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            if path.extension().is_none_or(|ext| ext != "rs") {
                continue;
            }
            // security.rs owns the field and the one comparison against it.
            if path.ends_with("security.rs") {
                continue;
            }
            let source = std::fs::read_to_string(&path).expect("read source");
            // Judge each read by the function that contains it and by whether it feeds
            // the shared formula, not by how the line happens to be wrapped. A pattern
            // that matches text is easy to satisfy accidentally; this one is not.
            for (offset, _) in source.match_indices(FIELD) {
                let before = &source[..offset];
                let line_start = before.rfind('\n').map(|i| i + 1).unwrap_or(0);
                if source[line_start..offset].trim_start().starts_with("//") {
                    continue;
                }
                // Assignment writes the effective value into the clone, it does not read
                // policy from the raw field. Test the field as the assignment TARGET:
                // a contains(" =") also matches " ==", which would exempt a genuine read
                // sitting inside a compound condition.
                let after = source[offset + FIELD.len()..].trim_start();
                if after.starts_with('=') && !after.starts_with("==") {
                    continue;
                }
                // Passing the ceiling into the shared formula is the sanctioned pattern,
                // whether the argument sits on the same line or the next one.
                // Require the sanctioned call to still be open, so one correct read
                // cannot shelter a wrong one a couple of lines below it.
                let window = &before[before.len().saturating_sub(220)..];
                if let Some(call) = window.rfind("effective_second_factor_threshold(")
                    && !window[call..].contains(';')
                {
                    continue;
                }
                // Report the enclosing function so the failure says where to look.
                // Top-level functions are unindented, methods are indented, and getting
                // that wrong names an unrelated function and sends the reader astray.
                let enclosing = [
                    "\n    pub fn ",
                    "\n    pub(crate) fn ",
                    "\n    pub(super) fn ",
                    "\n    fn ",
                    "\n    pub async fn ",
                    "
    pub(crate) async fn ",
                    "
    async fn ",
                    "\n    pub fn ",
                    "\npub fn ",
                    "\npub async fn ",
                    "\nfn ",
                    "\nasync fn ",
                ]
                .iter()
                .filter_map(|marker| before.rfind(marker).map(|i| i + marker.len()))
                .max()
                .map(|start| {
                    source[start..]
                        .split(['(', '<'])
                        .next()
                        .unwrap_or("")
                        .trim()
                        .to_string()
                })
                .unwrap_or_default();
                if enclosing == "second_factor_threshold_mei" || enclosing == "effective_profile" {
                    continue;
                }
                let line_number = before.matches('\n').count() + 1;
                offenders.push(format!(
                    "{}:{line_number} in fn {enclosing}",
                    path.display()
                ));
            }

            // The same bypass with nothing to grep for: a helper that reads the field
            // for you, handed the raw profile. check_send_policy(&self.profile, ..) was
            // three of the thirteen sites, and the loop above cannot see it, because the
            // amount comes from a local and the read itself lives in security.rs, which
            // this walker skips. Policy helpers must be given effective_profile(); a
            // whole-struct borrow of the raw profile has no other legitimate caller, and
            // &self.profile.name, which the vault does use, matches neither pattern.
            for needle in ["&self.profile,", "&self.profile)"] {
                for (offset, _) in source.match_indices(needle) {
                    let before = &source[..offset];
                    let line_start = before.rfind(newline).map(|i| i + 1).unwrap_or(0);
                    if source[line_start..offset].trim_start().starts_with("//") {
                        continue;
                    }
                    let line_number = before.matches(newline).count() + 1;
                    offenders.push(format!(
                        "{}:{line_number} hands the raw profile to a policy helper",
                        path.display()
                    ));
                }
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "these sites bypass second_factor_threshold_mei, so a user preference would not \
         apply on them: {offenders:?}"
    );
}

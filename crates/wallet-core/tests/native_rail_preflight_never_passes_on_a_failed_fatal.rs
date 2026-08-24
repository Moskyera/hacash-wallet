//! THE PREFLIGHT MUST NEVER SHOW PASS WHILE A FATAL ITEM FAILED OR WAS SKIPPED.
//!
//! This is the one rule the screen hangs on, so it gets its own file rather
//! than one assertion buried among twenty. Three ways of getting it wrong are
//! held closed here at once:
//!
//! 1. counting only `Fail` and letting `Skip` through, which is the natural
//!    shape of the bug: an unreachable Hub leaves its items unjudged, and
//!    unjudged renders as "nothing failed";
//! 2. reading a summary counter instead of the items, so a counter that is
//!    computed after the verdict can disagree with it;
//! 3. passing a run in which no fatal item was asked at all.
//!
//! It is deliberately exhaustive over every combination of one fatal item and
//! one warning item, because the failure mode this guards against is a rule
//! that is right for the case somebody thought of.

use hacash_wallet_core::hpay_native_rail_preflight::{
    CheckSeverity, CheckStatus, PreflightCheck, PreflightVerdict, verdict_for,
};

const ALL_STATUSES: [CheckStatus; 3] = [CheckStatus::Pass, CheckStatus::Fail, CheckStatus::Skip];

fn item(id: &str, severity: CheckSeverity, status: CheckStatus) -> PreflightCheck {
    // Built through the public shape a report actually carries, so this test
    // is held to the same struct the screen reads.
    serde_json::from_value(serde_json::json!({
        "id": id,
        "title": id,
        "severity": match severity {
            CheckSeverity::Fatal => "fatal",
            CheckSeverity::Warning => "warning",
        },
        "status": match status {
            CheckStatus::Pass => "pass",
            CheckStatus::Fail => "fail",
            CheckStatus::Skip => "skip",
        },
        "observed": "",
        "reason": null
    }))
    .expect("a preflight check is exactly this shape")
}

#[test]
fn a_failed_fatal_item_denies_the_pass_whatever_else_is_green() {
    let checks = vec![
        item("a", CheckSeverity::Fatal, CheckStatus::Pass),
        item("b", CheckSeverity::Fatal, CheckStatus::Pass),
        item("c", CheckSeverity::Fatal, CheckStatus::Fail),
        item("d", CheckSeverity::Warning, CheckStatus::Pass),
    ];
    assert_eq!(verdict_for(&checks), PreflightVerdict::NotPass);
}

/// A skipped check is not a passed check. This is the clause that a naive
/// "count the failures" rule silently drops.
#[test]
fn a_skipped_fatal_item_denies_the_pass_exactly_as_a_failed_one_does() {
    let skipped = vec![
        item("a", CheckSeverity::Fatal, CheckStatus::Pass),
        item("b", CheckSeverity::Fatal, CheckStatus::Skip),
    ];
    let failed = vec![
        item("a", CheckSeverity::Fatal, CheckStatus::Pass),
        item("b", CheckSeverity::Fatal, CheckStatus::Fail),
    ];
    assert_eq!(
        verdict_for(&skipped),
        PreflightVerdict::NotPass,
        "a fatal item that was never reached must never render as a pass"
    );
    assert_eq!(verdict_for(&skipped), verdict_for(&failed));
}

#[test]
fn the_rule_holds_for_every_combination_of_one_fatal_and_one_warning_item() {
    for fatal in ALL_STATUSES {
        for warning in ALL_STATUSES {
            let checks = vec![
                item("fatal", CheckSeverity::Fatal, fatal),
                item("warning", CheckSeverity::Warning, warning),
            ];
            let expected = if fatal == CheckStatus::Pass {
                PreflightVerdict::Pass
            } else {
                PreflightVerdict::NotPass
            };
            assert_eq!(
                verdict_for(&checks),
                expected,
                "fatal {fatal:?} with warning {warning:?}"
            );
        }
    }
}

/// Warnings are advisory by construction. A warning that fails must not turn a
/// genuinely green infrastructure red, or the next person to see one will
/// learn to ignore the whole screen.
#[test]
fn a_failed_warning_alone_never_denies_the_pass() {
    let checks = vec![
        item("a", CheckSeverity::Fatal, CheckStatus::Pass),
        item("b", CheckSeverity::Warning, CheckStatus::Fail),
        item("c", CheckSeverity::Warning, CheckStatus::Skip),
    ];
    assert_eq!(verdict_for(&checks), PreflightVerdict::Pass);
}

/// Nothing failed only because nothing was asked. That is the emptiest form of
/// the same mistake and it is refused too.
#[test]
fn a_run_with_no_fatal_items_is_not_a_pass() {
    assert_eq!(verdict_for(&[]), PreflightVerdict::NotPass);
    assert_eq!(
        verdict_for(&[item("w", CheckSeverity::Warning, CheckStatus::Pass)]),
        PreflightVerdict::NotPass
    );
}

/// One failure anywhere in a long green run is enough, at every position.
#[test]
fn position_does_not_matter() {
    for bad in 0..12usize {
        for status in [CheckStatus::Fail, CheckStatus::Skip] {
            let checks: Vec<PreflightCheck> = (0..12)
                .map(|index| {
                    item(
                        &format!("item{index}"),
                        CheckSeverity::Fatal,
                        if index == bad {
                            status
                        } else {
                            CheckStatus::Pass
                        },
                    )
                })
                .collect();
            assert_eq!(
                verdict_for(&checks),
                PreflightVerdict::NotPass,
                "a {status:?} at position {bad} must deny the pass"
            );
        }
    }
}

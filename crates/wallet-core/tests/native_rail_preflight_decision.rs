//! Every fatal path in the native-rail mainnet preflight, and the one rule the
//! screen hangs on.
//!
//! No HTTP, no node, no Hub. `judge` is pure over a set of observations, which
//! is exactly why it can be held to every refusal it claims to make. Each test
//! starts from a fully green mainnet observation set and breaks precisely one
//! thing, so a green result can never be an accident of three checks cancelling
//! out.
//!
//! The rule the surface hangs on has its own file:
//! `native_rail_preflight_never_passes_on_a_failed_fatal.rs`.

use hacash_wallet_core::hpay_native_rail_preflight::{
    CheckSeverity, CheckStatus, PreflightCheck, PreflightObservations, PreflightRequest,
    PreflightVerdict, judge, verdict_for,
};
use hacash_wallet_core::l2_hub::{HubHealth, HubMainnetReadiness, VoucherRouteProbe};
use hacash_wallet_core::node::BlockIntroResponse;
use hacash_wallet_core::node_capabilities::{NodeCapabilities, network_instance_id};
use hacash_wallet_core::node_discovery::MAINNET_BLOCK_ONE_HASH;
use serde_json::{Value, json};

const OWNER: &str = "1AVRuFXNFi3rdMrPH4hdqSgFrEBnWisWaS";
const HUB: &str = "1LFPqztfKhamVuzzV5WV6pHfykktGD5pMW";
const NODE_URL: &str = "https://node.example.com";
const HUB_URL: &str = "https://hub.example.com";

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn green_request() -> PreflightRequest {
    PreflightRequest {
        node_url: NODE_URL.to_owned(),
        hub_url: HUB_URL.to_owned(),
        hub_address: HUB.to_owned(),
        owner_address: OWNER.to_owned(),
        channel_deposit_hac: "1".to_owned(),
        payment_hac: "0.1".to_owned(),
    }
}

/// A mainnet capability document that this wallet's own `validate()` accepts.
///
/// Built as JSON and decoded, so the fixture is held to the same wire contract
/// a real node is, rather than to a struct literal that can drift away from it.
fn green_capability_json(now: u64) -> Value {
    let instance = network_instance_id(
        "mainnet",
        0,
        true,
        MAINNET_BLOCK_ONE_HASH,
        "hacash-mainnet",
        2,
    );
    json!({
        "ret": 0,
        "api_version": 1,
        "node": { "name": "hacash-fullnode", "version": "1.0.10", "build_time": "2026/7/10 #1" },
        "chain": { "id": 0, "height": 900_000, "next_height": 900_001, "mainnet": true },
        "network": {
            "kind": "mainnet",
            "node_profile_id": "hacash-mainnet",
            "block_1_available": true,
            "block_1_hash": MAINNET_BLOCK_ONE_HASH,
            "instance_id": instance,
            "funding_confirmed": true,
            "transaction_ready": true,
            "current_height": 900_000,
            "transaction_format_version": 2
        },
        "sync": {
            "tip_timestamp_unix": now - 60,
            "observed_unix": now,
            "tip_age_seconds": 60,
            "max_tip_age_seconds": 3600,
            "fresh": true
        },
        "istanbul": { "activation_height": 765_432, "evaluation_height": 900_001, "active": true },
        "transactions": { "registered": [0, 1, 2, 3], "enabled": [0, 1, 2, 3] },
        // The native rail's exact set, plus the three siblings action_guard
        // brings with 0x0411. No 40/41/44 anywhere: that is the point.
        "actions": {
            "registered": [1, 2, 3, 14, 1041, 1042, 1043, 1044],
            "enabled": [1, 2, 3, 14, 1041, 1042, 1043, 1044]
        },
        "features": {
            "action_guard": true, "tx_blob": false, "ast": false, "tex": false,
            "native_assets": false, "hip20": false, "hip20_primitives": false, "hvm": false,
            "p2sh": false, "account_abstraction": false, "intent": false,
            "contract_state_leasing": false, "ir_decompilation": false, "req_sign_list": false,
            "type4_mainnet": false, "exact_unsigned_simulation": false
        },
        "api": {
            "balance_query": true, "transaction_submit": true, "transaction_submit_bound": true,
            "transaction_query": true, "reconciliation_by_tx_hash": true
        },
        "limits": {
            "max_tx_size": 16384, "max_tx_actions": 200, "max_type3_signers": 200,
            "gas_max_byte": 99, "gas_max": 111_911, "ast_depth": 6
        },
        // A node other nodes have actually reached. The measured shape of the
        // owner's live node is the leaf below, which is the interesting case
        // and gets its own test rather than being baked into "green".
        "peers": {
            "measured": true,
            "total": 9,
            "inbound_established": 5,
            "outbound_established": 4,
            "public": 4,
            "inbound_proven": true,
            "role": "participant"
        },
        "source": "reported"
    })
}

fn capabilities_from(value: Value) -> NodeCapabilities {
    serde_json::from_value::<NodeCapabilities>(value)
        .expect("capability shape")
        .validate()
        .expect("the fixture must satisfy the wallet's own capability contract")
}

fn green_readiness_json(now: u64) -> Value {
    let instance = network_instance_id(
        "mainnet",
        0,
        true,
        MAINNET_BLOCK_ONE_HASH,
        "hacash-mainnet",
        2,
    );
    json!({
        "schema": "hpay-fast-pay-mainnet-readiness/1",
        "evaluated_unix": now,
        "valid_until_unix": now + 300,
        "profile": "mainnet-bounded-pilot",
        "payments_enabled": true,
        "close_enabled": true,
        "mainnet_detected": true,
        "fullnode_capabilities": {
            "observed_unix": now,
            "api_version": 1,
            "chain_id": 0,
            "height": 900_000,
            "next_height": 900_001,
            "mainnet": true,
            "network_instance_id": instance,
            "tip_timestamp_unix": now - 60,
            "tip_age_seconds": 60,
            "enabled_actions": [1, 2, 3, 14, 1041]
        },
        "max_payment_hac_zhu": 100_000_000u64,
        "max_channel_funding_hac_zhu": 1_000_000_000u64,
        "max_aggregate_tvl_hac_zhu": 10_000_000_000u64,
        "aggregate_tvl_within_limit": true,
        "max_payment_satoshi": 0,
        "wallet_fee_hac": "0",
        "trustless_finality": false,
        "unilateral_l1_enforceable": false,
        "trusted_bounded_pilot": true,
        "settlement_model": "official Hacash ChannelPay bills with hub-coordinated bounded mainnet pilot",
        "blockers": [],
        "close_blockers": [],
        "disclosed_blockers": [],
        "limitations": [],
        "allowlist_configured": true
    })
}

fn green_health_json() -> Value {
    json!({
        "ok": true,
        "version": 7,
        "name": "pilot hub",
        "hub_address": HUB,
        "hub_fee_mei": "0",
        "settlement_ready": true,
        "cross_channel_ready": true,
        "official_channelpay_ready": true,
        "trusted_bounded_pilot_ready": true,
        "deployment_profile": "mainnet-bounded-pilot"
    })
}

/// Everything green, exactly as a ready mainnet node and Hub would answer.
fn green() -> PreflightObservations {
    let now = now();
    let raw = green_readiness_json(now);
    PreflightObservations {
        signing_transport: Ok(NODE_URL.to_owned()),
        hub_transport: Ok(HUB_URL.to_owned()),
        capabilities: Ok(capabilities_from(green_capability_json(now))),
        block_one: Ok(BlockIntroResponse {
            ret: 0,
            err: None,
            height: 1,
            hash: MAINNET_BLOCK_ONE_HASH.to_owned(),
        }),
        health: Ok(serde_json::from_value::<HubHealth>(green_health_json()).unwrap()),
        readiness: Ok(serde_json::from_value::<HubMainnetReadiness>(raw.clone()).unwrap()),
        readiness_raw: Some(raw),
        voucher_route: Ok(VoucherRouteProbe {
            status: 405,
            allow: Some("POST".to_owned()),
        }),
        observed_unix: now,
    }
}

fn status_of(observations: &PreflightObservations, id: &str) -> CheckStatus {
    judge(&green_request(), observations)
        .checks
        .into_iter()
        .find(|check| check.id == id)
        .unwrap_or_else(|| panic!("no check with id {id}"))
        .status
}

fn reason_of(observations: &PreflightObservations, id: &str) -> String {
    judge(&green_request(), observations)
        .checks
        .into_iter()
        .find(|check| check.id == id)
        .unwrap_or_else(|| panic!("no check with id {id}"))
        .reason
        .unwrap_or_default()
}

/// Rebuild the observations with one field of the readiness JSON changed.
fn with_readiness(
    mutate: impl FnOnce(&mut serde_json::Map<String, Value>),
) -> PreflightObservations {
    let mut observations = green();
    let mut raw = green_readiness_json(observations.observed_unix);
    mutate(raw.as_object_mut().unwrap());
    observations.readiness = serde_json::from_value::<HubMainnetReadiness>(raw.clone())
        .map_err(|error| error.to_string());
    observations.readiness_raw = Some(raw);
    observations
}

fn with_health(mutate: impl FnOnce(&mut serde_json::Map<String, Value>)) -> PreflightObservations {
    let mut observations = green();
    let mut raw = green_health_json();
    mutate(raw.as_object_mut().unwrap());
    observations.health = Ok(serde_json::from_value::<HubHealth>(raw).unwrap());
    observations
}

fn with_capabilities(
    mutate: impl FnOnce(&mut serde_json::Map<String, Value>),
) -> PreflightObservations {
    let mut observations = green();
    let mut raw = green_capability_json(observations.observed_unix);
    mutate(raw.as_object_mut().unwrap());
    observations.capabilities = Ok(capabilities_from(raw));
    observations
}

// ------------------------------------------------------------- the green case

#[test]
fn a_fully_green_mainnet_node_and_hub_pass_and_nothing_is_skipped() {
    let report = judge(&green_request(), &green());
    assert_eq!(
        report.verdict,
        PreflightVerdict::Pass,
        "{:#?}",
        report
            .checks
            .iter()
            .filter(|check| check.status != CheckStatus::Pass)
            .collect::<Vec<_>>()
    );
    assert_eq!(report.fatal_failed, 0);
    assert_eq!(report.fatal_skipped, 0);
    // Every fatal path below has to be reachable, so the green set must
    // actually exercise all of them.
    assert!(
        report
            .checks
            .iter()
            .filter(|check| check.severity == CheckSeverity::Fatal)
            .count()
            >= 12
    );
    // The caveats travel with the verdict, not in a comment.
    assert_eq!(report.cannot_be_checked.len(), 6);
    assert_eq!(report.validity_seconds, 330);
}

/// The whole reason this preflight exists: the registry rail's node features
/// are absent from the green fixture and it still passes.
#[test]
fn the_native_rail_passes_on_a_node_with_no_hvm_and_no_actions_40_41_44() {
    let capabilities = capabilities_from(green_capability_json(now()));
    assert!(!capabilities.features.hvm);
    assert!(!capabilities.features.contract_state_leasing);
    assert!(!capabilities.supports_action(40));
    assert!(!capabilities.supports_action(41));
    assert!(!capabilities.supports_action(44));
    assert_eq!(
        judge(&green_request(), &green()).verdict,
        PreflightVerdict::Pass
    );
}

// ------------------------------------------------------------- node refusals

#[test]
fn a_non_mainnet_node_fails_identity_and_the_binding() {
    // Exactly what the chain 7 pilot node answers.
    let observations =
        with_capabilities(|raw| {
            raw.insert(
                "chain".into(),
                json!({ "id": 7, "height": 4472, "next_height": 4473, "mainnet": false }),
            );
            raw.insert(
                "istanbul".into(),
                json!({ "activation_height": 765_432, "evaluation_height": 4473, "active": true }),
            );
            let instance = network_instance_id(
                "local_pilot_v1",
                7,
                false,
                "000087f67e55660eaefed72e0b9499147556a33a34f18fa48900f4a2fa30cd29",
                "hpay-local-pilot-chain-v1",
                2,
            );
            raw.insert("network".into(), json!({
            "kind": "local_pilot_v1",
            "node_profile_id": "hpay-local-pilot-chain-v1",
            "block_1_available": true,
            "block_1_hash": "000087f67e55660eaefed72e0b9499147556a33a34f18fa48900f4a2fa30cd29",
            "instance_id": instance,
            "funding_confirmed": true,
            "transaction_ready": true,
            "current_height": 4472,
            "transaction_format_version": 2
        }));
        });
    assert_eq!(status_of(&observations, "node_identity"), CheckStatus::Fail);
    assert_eq!(
        status_of(&observations, "network_binding"),
        CheckStatus::Fail
    );
    assert_eq!(
        judge(&green_request(), &observations).verdict,
        PreflightVerdict::NotPass
    );
}

#[test]
fn a_node_whose_chain_store_disagrees_with_its_capability_block_fails() {
    let mut observations = green();
    observations.block_one = Ok(BlockIntroResponse {
        ret: 0,
        err: None,
        height: 1,
        hash: "000087f67e55660eaefed72e0b9499147556a33a34f18fa48900f4a2fa30cd29".to_owned(),
    });
    assert_eq!(status_of(&observations, "block_one"), CheckStatus::Fail);
}

#[test]
fn a_stale_tip_fails_against_the_nodes_clock_and_against_this_devices_clock() {
    // The node's own document says stale: this is the chain 7 shape, where
    // no miner runs and the tip ages past 3600 s.
    let stale = with_capabilities(|raw| {
        let now = raw["sync"]["observed_unix"].as_u64().unwrap();
        raw.insert(
            "sync".into(),
            json!({
                "tip_timestamp_unix": now - 8496,
                "observed_unix": now,
                "tip_age_seconds": 8496,
                "max_tip_age_seconds": 3600,
                "fresh": false
            }),
        );
        // transaction_ready cannot be claimed on a mainnet node that is not
        // fresh, so the fixture has to drop it too, which is the node's own
        // contract talking.
        raw["network"]["transaction_ready"] = json!(false);
    });
    assert_eq!(status_of(&stale, "tip_freshness"), CheckStatus::Fail);
    assert!(reason_of(&stale, "tip_freshness").contains("not fresh"));

    // And the second clock: the node insists it is fresh against its own
    // slow clock, while this device says the tip is hours old.
    let laundered = {
        let mut observations = green();
        let node_clock = observations.observed_unix - 20_000;
        observations.capabilities = Ok(capabilities_from({
            let mut raw = green_capability_json(observations.observed_unix);
            raw["sync"] = json!({
                "tip_timestamp_unix": node_clock - 60,
                "observed_unix": node_clock,
                "tip_age_seconds": 60,
                "max_tip_age_seconds": 3600,
                "fresh": true
            });
            raw
        }));
        observations
    };
    assert_eq!(status_of(&laundered, "tip_freshness"), CheckStatus::Fail);
    assert!(
        reason_of(&laundered, "tip_freshness").contains("this device's clock"),
        "{}",
        reason_of(&laundered, "tip_freshness")
    );
}

#[test]
fn a_node_that_declares_a_looser_staleness_bound_than_the_wallet_is_refused() {
    // A node may not widen its own staleness window. The wallet's own decode
    // refuses the document outright, which is the strongest form of this.
    let mut raw = green_capability_json(now());
    raw["sync"]["max_tip_age_seconds"] = json!(86_400);
    let decoded = serde_json::from_value::<NodeCapabilities>(raw)
        .unwrap()
        .validate();
    assert!(
        decoded.is_err(),
        "a node cannot widen its own staleness window"
    );

    let mut observations = green();
    observations.capabilities = Err(decoded.unwrap_err().to_string());
    // Unreadable capabilities leave every node item unjudged, and unjudged is
    // not passed.
    assert_eq!(status_of(&observations, "node_identity"), CheckStatus::Skip);
    assert_eq!(status_of(&observations, "tip_freshness"), CheckStatus::Skip);
    assert_eq!(
        status_of(&observations, "network_binding"),
        CheckStatus::Skip
    );
    assert_eq!(
        judge(&green_request(), &observations).verdict,
        PreflightVerdict::NotPass
    );
}

#[test]
fn a_node_missing_channel_close_action_3_fails_the_action_set() {
    let observations = with_capabilities(|raw| {
        raw.insert(
            "actions".into(),
            json!({
                "registered": [1, 2, 3, 14, 1041, 1042, 1043, 1044],
                "enabled": [1, 2, 14, 1041, 1042, 1043, 1044]
            }),
        );
    });
    assert_eq!(
        status_of(&observations, "node_action_set"),
        CheckStatus::Fail
    );
    assert!(reason_of(&observations, "node_action_set").contains("ChannelClose 3"));
}

#[test]
fn a_node_with_plain_submit_but_not_bound_submit_is_refused() {
    let observations = with_capabilities(|raw| {
        raw["api"]["transaction_submit_bound"] = json!(false);
    });
    assert_eq!(
        status_of(&observations, "node_api_surface"),
        CheckStatus::Fail
    );
    assert!(reason_of(&observations, "node_api_surface").contains("transaction_submit_bound"));
}

#[test]
fn plain_http_to_a_remote_node_is_refused_and_loopback_http_is_not() {
    let mut observations = green();
    observations.signing_transport = Err("mainnet signing requires HTTPS".to_owned());
    assert_eq!(
        status_of(&observations, "signing_transport"),
        CheckStatus::Fail
    );

    // The predicate deliberately allows a node on this same device.
    let mut loopback = green();
    loopback.signing_transport = Ok("http://127.0.0.1:8197".to_owned());
    assert_eq!(status_of(&loopback, "signing_transport"), CheckStatus::Pass);
}

// ------------------------------------------- is this node reached, or a leaf

fn check_of(observations: &PreflightObservations, id: &str) -> PreflightCheck {
    judge(&green_request(), observations)
        .checks
        .into_iter()
        .find(|check| check.id == id)
        .unwrap_or_else(|| panic!("no check with id {id}"))
}

/// The exact block the owner's live mainnet node answered on 2026-08-24: four
/// peers, every one of them dialed by this node, nobody able to reach it.
fn leaf_node() -> PreflightObservations {
    with_capabilities(|raw| {
        raw.insert(
            "peers".into(),
            json!({
                "measured": true,
                "total": 4,
                "inbound_established": 0,
                "outbound_established": 4,
                "public": 4,
                "inbound_proven": false,
                "role": "leaf"
            }),
        );
    })
}

#[test]
fn a_node_nobody_can_reach_says_what_it_cannot_do_rather_than_printing_a_count() {
    let check = check_of(&leaf_node(), "node_can_be_reached");
    assert_eq!(check.status, CheckStatus::Fail);

    // The whole point of the item: plain words about the consequence, not a
    // number left for the reader to interpret.
    let words = format!("{} {}", check.observed, check.reason.clone().unwrap());
    assert!(
        words.contains("no other node has reached this one"),
        "{words}"
    );
    assert!(words.contains("relays for nobody"), "{words}");
    assert!(
        words.contains("carry your signed channel open or your close voucher out to the miners"),
        "{words}"
    );
    // And the fix, because a diagnosis with no fix is another kind of silence.
    assert!(words.contains("TCP 3337"), "{words}");
    assert!(words.contains("LISTENING is not the same thing"), "{words}");
    // The counts are still there, underneath the sentence, never instead of it.
    assert!(check.observed.contains("inbound 0"), "{}", check.observed);
}

/// The judgement call, pinned so it cannot drift silently: a leaf is a WARNING.
///
/// It does not block funding, because a leaf is still right about the chain it
/// has and because a payment that never reaches a miner never confirms and
/// leaves the money where it is. It is still on the screen before the deposit,
/// which is the half that was missing.
#[test]
fn a_leaf_node_warns_before_the_deposit_and_does_not_block_it() {
    let observations = leaf_node();
    let check = check_of(&observations, "node_can_be_reached");
    assert_eq!(check.severity, CheckSeverity::Warning);
    let report = judge(&green_request(), &observations);
    assert_eq!(report.verdict, PreflightVerdict::Pass);
    assert_eq!(report.fatal_failed, 0);
    assert_eq!(report.fatal_skipped, 0);
    assert!(report.warnings >= 1);
}

#[test]
fn a_node_that_has_been_reached_passes_and_the_pass_is_only_for_this_moment() {
    let check = check_of(&green(), "node_can_be_reached");
    assert_eq!(check.status, CheckStatus::Pass);
    assert!(
        check
            .observed
            .contains("5 other node(s) have reached this one"),
        "{}",
        check.observed
    );
    assert!(
        check.reason.unwrap().contains("peers come and go"),
        "a pass here is a snapshot and has to say so"
    );
}

/// A missing answer is not a passing answer.
#[test]
fn an_older_node_that_cannot_answer_the_question_reads_as_unknown_not_as_fine() {
    let observations = with_capabilities(|raw| {
        raw.remove("peers");
    });
    let check = check_of(&observations, "node_can_be_reached");
    assert_eq!(
        check.status,
        CheckStatus::Skip,
        "an absent field must never render as a pass"
    );
    assert_ne!(check.status, CheckStatus::Pass);
    let words = format!("{} {}", check.observed, check.reason.clone().unwrap());
    assert!(
        words.contains("does not report who has reached it"),
        "{words}"
    );
    assert!(
        words.contains("Treat it as unknown rather than as fine"),
        "{words}"
    );
}

/// And an unmeasured zero is not a measured zero. A node that carries the
/// block and could not count must not be reported as a node nobody reached.
#[test]
fn a_node_that_could_not_count_is_not_reported_as_a_node_nobody_reached() {
    let observations = with_capabilities(|raw| {
        raw.insert(
            "peers".into(),
            json!({
                "measured": false,
                "total": Value::Null,
                "inbound_established": Value::Null,
                "outbound_established": Value::Null,
                "public": Value::Null,
                "inbound_proven": false,
                "role": "unknown"
            }),
        );
    });
    let check = check_of(&observations, "node_can_be_reached");
    assert_eq!(check.status, CheckStatus::Skip);
    assert!(
        !check.observed.contains("no other node has reached"),
        "an unmeasured zero must not be stated as a fact: {}",
        check.observed
    );
    assert!(
        check
            .reason
            .unwrap()
            .contains("do not read a blank as a yes"),
        "unknown has to say it is unknown"
    );
}

/// The count decides. A node whose own one-word summary disagrees with its own
/// number is not a node to take a summary from.
#[test]
fn a_node_whose_label_contradicts_its_own_count_is_not_believed() {
    let liar = with_capabilities(|raw| {
        raw.insert(
            "peers".into(),
            json!({
                "measured": true,
                "total": 4,
                "inbound_established": 0,
                "outbound_established": 4,
                "public": 4,
                "inbound_proven": true,
                "role": "participant"
            }),
        );
    });
    let check = check_of(&liar, "node_can_be_reached");
    assert_eq!(
        check.status,
        CheckStatus::Fail,
        "a participant label over a zero count must not buy a pass"
    );
    assert!(
        check.reason.unwrap().contains("contradicts its own count"),
        "and it has to say why"
    );
}

#[test]
fn a_node_that_cannot_be_read_at_all_leaves_this_question_unanswered() {
    let mut observations = green();
    observations.capabilities = Err("connection refused".to_owned());
    let check = check_of(&observations, "node_can_be_reached");
    assert_eq!(check.status, CheckStatus::Skip);
    assert!(check.reason.unwrap().contains("connection refused"));
}

// -------------------------------------------------------------- hub refusals

#[test]
fn a_hub_that_will_not_answer_leaves_every_hub_item_unjudged_and_never_passes() {
    let mut observations = green();
    observations.health = Err("hub unreachable".to_owned());
    observations.readiness = Err("hub unreachable".to_owned());
    observations.readiness_raw = None;
    observations.voucher_route = Err("hub unreachable".to_owned());
    for id in [
        "hub_open_ready",
        "hub_voucher_ready",
        "voucher_route",
        "readiness_document",
        "declared_caps",
        "hub_fullnode",
        "hub_blockers",
    ] {
        assert_eq!(status_of(&observations, id), CheckStatus::Skip, "{id}");
    }
    assert_eq!(
        judge(&green_request(), &observations).verdict,
        PreflightVerdict::NotPass
    );
    assert_eq!(judge(&green_request(), &observations).fatal_failed, 0);
    assert!(judge(&green_request(), &observations).fatal_skipped >= 7);
}

/// The old preflight's gap: a Hub green for the open and red for the close.
#[test]
fn a_hub_ready_to_open_but_not_to_close_passes_the_open_item_and_fails_the_voucher_item() {
    let observations = with_health(|raw| {
        raw.insert("official_channelpay_ready".into(), json!(false));
    });
    assert_eq!(
        status_of(&observations, "hub_open_ready"),
        CheckStatus::Pass
    );
    assert_eq!(
        status_of(&observations, "hub_voucher_ready"),
        CheckStatus::Fail
    );
    assert!(reason_of(&observations, "hub_voucher_ready").contains("official_channelpay_ready"));
    assert_eq!(
        judge(&green_request(), &observations).verdict,
        PreflightVerdict::NotPass
    );
}

#[test]
fn a_hub_with_close_disabled_or_close_blockers_fails_the_voucher_item() {
    let disabled = with_readiness(|raw| {
        raw.insert("close_enabled".into(), json!(false));
    });
    assert_eq!(status_of(&disabled, "hub_voucher_ready"), CheckStatus::Fail);

    let blocked = with_readiness(|raw| {
        raw.insert(
            "close_blockers".into(),
            json!(["fullnode_capability_probe_failed"]),
        );
    });
    assert_eq!(status_of(&blocked, "hub_voucher_ready"), CheckStatus::Fail);
    assert!(reason_of(&blocked, "hub_voucher_ready").contains("fullnode_capability_probe_failed"));
}

#[test]
fn a_hub_address_that_is_not_the_one_this_wallet_expects_fails_both_hub_items() {
    let observations = with_health(|raw| {
        raw.insert("hub_address".into(), json!(OWNER));
    });
    assert_eq!(
        status_of(&observations, "hub_open_ready"),
        CheckStatus::Fail
    );
    assert_eq!(
        status_of(&observations, "hub_voucher_ready"),
        CheckStatus::Fail
    );
}

/// The most dangerous omission in the old preflight, and the item that closes
/// the hostage window: an older Hub with no close-voucher route at all.
#[test]
fn a_hub_with_no_close_voucher_route_is_refused_before_any_money_moves() {
    let mut observations = green();
    observations.voucher_route = Ok(VoucherRouteProbe {
        status: 404,
        allow: None,
    });
    assert_eq!(status_of(&observations, "voucher_route"), CheckStatus::Fail);
    assert!(reason_of(&observations, "voucher_route").contains("older build"));
    assert_eq!(
        judge(&green_request(), &observations).verdict,
        PreflightVerdict::NotPass
    );
}

#[test]
fn an_unexpected_answer_to_the_route_probe_is_unproven_and_unproven_is_not_a_pass() {
    for status in [200u16, 401, 500, 502] {
        let mut observations = green();
        observations.voucher_route = Ok(VoucherRouteProbe {
            status,
            allow: None,
        });
        assert_eq!(
            status_of(&observations, "voucher_route"),
            CheckStatus::Fail,
            "status {status} must never read as a pass"
        );
    }
    // An Allow header naming POST is proof the route exists even without 405.
    let mut observations = green();
    observations.voucher_route = Ok(VoucherRouteProbe {
        status: 415,
        allow: Some("POST, OPTIONS".to_owned()),
    });
    assert_eq!(status_of(&observations, "voucher_route"), CheckStatus::Pass);
}

#[test]
fn a_readiness_document_of_the_wrong_schema_or_profile_or_an_expired_one_is_refused() {
    let wrong_schema = with_readiness(|raw| {
        raw.insert("schema".into(), json!("hpay-fast-pay-mainnet-readiness/2"));
    });
    assert_eq!(
        status_of(&wrong_schema, "readiness_document"),
        CheckStatus::Fail
    );

    let wrong_profile = with_readiness(|raw| {
        raw.insert("profile".into(), json!("mainnet-pilot"));
        raw.insert("trusted_bounded_pilot".into(), json!(false));
    });
    assert_eq!(
        status_of(&wrong_profile, "readiness_document"),
        CheckStatus::Fail
    );

    // A Hub cannot widen its own snapshot window past 330 s.
    let long_window = with_readiness(|raw| {
        let evaluated = raw["evaluated_unix"].as_u64().unwrap();
        raw.insert("valid_until_unix".into(), json!(evaluated + 3600));
    });
    assert_eq!(
        status_of(&long_window, "readiness_document"),
        CheckStatus::Fail
    );
    assert!(reason_of(&long_window, "readiness_document").contains("330"));

    let expired = with_readiness(|raw| {
        let evaluated = raw["evaluated_unix"].as_u64().unwrap();
        raw.insert("evaluated_unix".into(), json!(evaluated - 1000));
        raw.insert("valid_until_unix".into(), json!(evaluated - 700));
        raw["fullnode_capabilities"]["observed_unix"] = json!(evaluated - 1000);
    });
    assert_eq!(status_of(&expired, "readiness_document"), CheckStatus::Fail);
}

#[test]
fn a_deposit_or_payment_past_this_hubs_own_declared_cap_is_refused() {
    // Judged against the Hub's declaration, never against this build's
    // ceilings. This Hub declares 0.5 HAC per channel; the deposit is 1.
    let small_channel_cap = with_readiness(|raw| {
        raw.insert("max_channel_funding_hac_zhu".into(), json!(50_000_000u64));
    });
    assert_eq!(
        status_of(&small_channel_cap, "declared_caps"),
        CheckStatus::Fail
    );
    assert!(reason_of(&small_channel_cap, "declared_caps").contains("per-channel cap"));

    let small_payment_cap = with_readiness(|raw| {
        raw.insert("max_payment_hac_zhu".into(), json!(1_000_000u64));
    });
    assert_eq!(
        status_of(&small_payment_cap, "declared_caps"),
        CheckStatus::Fail
    );

    // And a Hub whose declaration exceeds this build's compiled ceiling is
    // refused in the other direction.
    let oversized = with_readiness(|raw| {
        raw.insert(
            "max_channel_funding_hac_zhu".into(),
            json!(2_000_000_000u64),
        );
    });
    assert_eq!(status_of(&oversized, "declared_caps"), CheckStatus::Fail);
}

#[test]
fn the_hubs_own_fullnode_must_be_on_mainnet_fresh_and_accept_actions_2_and_3() {
    let wrong_chain = with_readiness(|raw| {
        raw["fullnode_capabilities"]["chain_id"] = json!(7);
        raw["fullnode_capabilities"]["mainnet"] = json!(false);
    });
    assert_eq!(status_of(&wrong_chain, "hub_fullnode"), CheckStatus::Fail);

    let no_close_action = with_readiness(|raw| {
        raw["fullnode_capabilities"]["enabled_actions"] = json!([1, 2, 14, 1041]);
    });
    assert_eq!(
        status_of(&no_close_action, "hub_fullnode"),
        CheckStatus::Fail
    );
    assert!(reason_of(&no_close_action, "hub_fullnode").contains("ChannelClose 3"));

    let measured_earlier = with_readiness(|raw| {
        let evaluated = raw["evaluated_unix"].as_u64().unwrap();
        raw["fullnode_capabilities"]["observed_unix"] = json!(evaluated - 600);
    });
    assert_eq!(
        status_of(&measured_earlier, "hub_fullnode"),
        CheckStatus::Fail
    );

    let absent = with_readiness(|raw| {
        raw.insert("fullnode_capabilities".into(), Value::Null);
    });
    assert_eq!(status_of(&absent, "hub_fullnode"), CheckStatus::Fail);
}

#[test]
fn two_different_mainnet_views_warn_and_do_not_refuse() {
    let observations = with_readiness(|raw| {
        raw["fullnode_capabilities"]["network_instance_id"] =
            json!("9ebd8657a72faed35ed4d6e309fab2ef259f054e4820684fab6c6b848e4438f3");
    });
    assert_eq!(
        status_of(&observations, "hub_fullnode_instance"),
        CheckStatus::Fail
    );
    // A warning never blocks the verdict.
    assert_eq!(
        judge(&green_request(), &observations).verdict,
        PreflightVerdict::Pass
    );
    assert_eq!(judge(&green_request(), &observations).warnings, 1);
}

#[test]
fn any_gating_blocker_refuses_and_a_broken_witness_says_so_in_words() {
    let blocked = with_readiness(|raw| {
        raw.insert(
            "blockers".into(),
            json!(["mainnet_pilot_user_allowlist_is_not_configured"]),
        );
    });
    assert_eq!(status_of(&blocked, "hub_blockers"), CheckStatus::Fail);
    assert!(reason_of(&blocked, "hub_blockers").contains("allowlist"));

    let broken_witness = with_readiness(|raw| {
        raw.insert(
            "rollback_anchor_witness_identity_break".into(),
            json!({
                "witness_url": "https://witness.example",
                "pinned_identity": "a".repeat(64),
                "observed_identity": "b".repeat(64),
                "observed_unix": 1_800_000_000u64
            }),
        );
    });
    // Either the Hub crate's own shape decoded, in which case the wallet must
    // say the refusal is permanent, or it did not, in which case the document
    // is unreadable and the item is unjudged. Both are refusals.
    assert_ne!(
        status_of(&broken_witness, "hub_blockers"),
        CheckStatus::Pass
    );
}

/// A bounded-pilot Hub publishes an empty `blockers` by design. A preflight
/// that reads only that list gives a clean bill of health to a Hub with a real
/// disclosed gap, so the second list has to reach the screen too.
#[test]
fn disclosed_gaps_are_shown_as_a_warning_and_never_swallowed() {
    let observations = with_readiness(|raw| {
        raw.insert(
            "disclosed_blockers".into(),
            json!([
                "external_monotonic_rollback_anchor_is_not_ready",
                "unilateral_l1_dispute_path_is_not_ready"
            ]),
        );
    });
    assert!(observations.readiness.as_ref().unwrap().blockers.is_empty());
    assert_eq!(status_of(&observations, "hub_blockers"), CheckStatus::Pass);
    assert_eq!(
        status_of(&observations, "hub_disclosed_gaps"),
        CheckStatus::Fail
    );
    let report = judge(&green_request(), &observations);
    // Non-gating by design, so the verdict still passes, and the gap is on
    // screen rather than in a log.
    assert_eq!(report.verdict, PreflightVerdict::Pass);
    assert!(report.warnings >= 1);
    let shown = report
        .checks
        .iter()
        .find(|check| check.id == "hub_disclosed_gaps")
        .unwrap();
    assert!(
        shown
            .observed
            .contains("unilateral_l1_dispute_path_is_not_ready")
    );
}

#[test]
fn allowlist_configured_is_read_raw_and_reported_as_a_warning_only() {
    let observations = with_readiness(|raw| {
        raw.insert("allowlist_configured".into(), json!(false));
    });
    let report = judge(&green_request(), &observations);
    let check = report
        .checks
        .iter()
        .find(|c| c.id == "allowlist_configured")
        .unwrap();
    assert_eq!(check.severity, CheckSeverity::Warning);
    assert_eq!(check.status, CheckStatus::Fail);
    // Reading a field the typed struct does not decode must not break the
    // typed decode.
    assert!(observations.readiness.is_ok());

    // An older Hub omits the field entirely, and "absent" is not "false".
    let older = with_readiness(|raw| {
        raw.remove("allowlist_configured");
    });
    assert_eq!(status_of(&older, "allowlist_configured"), CheckStatus::Skip);
}

// ------------------------------------------------------------- owner-side items

#[test]
fn a_malformed_or_self_dealing_pair_of_addresses_is_refused() {
    let observations = green();
    let mut request = green_request();
    request.owner_address = "not-an-address".to_owned();
    let report = judge(&request, &observations);
    let check = report
        .checks
        .iter()
        .find(|c| c.id == "voucher_parties")
        .unwrap();
    assert_eq!(check.status, CheckStatus::Fail);
    assert_eq!(report.verdict, PreflightVerdict::NotPass);

    let mut same = green_request();
    same.owner_address = HUB.to_owned();
    let report = judge(&same, &observations);
    assert_eq!(
        report
            .checks
            .iter()
            .find(|c| c.id == "voucher_parties")
            .unwrap()
            .status,
        CheckStatus::Fail
    );
}

#[test]
fn the_verdict_helper_and_the_report_never_disagree() {
    for observations in [green(), {
        let mut broken = green();
        broken.voucher_route = Ok(VoucherRouteProbe {
            status: 404,
            allow: None,
        });
        broken
    }] {
        let report = judge(&green_request(), &observations);
        assert_eq!(report.verdict, verdict_for(&report.checks));
    }
}

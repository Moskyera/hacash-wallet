//! THE WALLET MUST READ WHAT THE HUB ACTUALLY SENDS.
//!
//! The fixture beside this file is not hand-written. It is the verbatim
//! `/v1/readiness/mainnet` body of a real `fast-pay-hub` binary started with
//! `--deployment-profile mainnet-bounded-pilot` on loopback, with only the two
//! clock fields pinned so the fixture is deterministic. No mainnet was
//! contacted to produce it: the Hub's `--node-url` pointed at a dead loopback
//! port, which is why `fullnode_capability_probe_failed` is among its blockers.
//!
//! It exists because the wallet's `HubMainnetReadiness` silently dropped two
//! fields this document has always carried, `max_aggregate_tvl_hac_zhu` and
//! `aggregate_tvl_within_limit`. A struct with `#[serde(default)]` on a missing
//! field decodes a real document without complaint and shows the user nothing,
//! so no existing test could catch it. This one holds the wallet to the wire.

use hacash_wallet_core::l2_hub::HubMainnetReadiness;

fn live_document() -> HubMainnetReadiness {
    let raw = include_str!("fixtures/hub-readiness-mainnet-bounded-pilot.json");
    serde_json::from_str(raw).expect("the wallet must decode a real Hub's readiness document")
}

#[test]
fn the_wallet_reads_all_three_caps_a_real_bounded_pilot_hub_publishes() {
    let readiness = live_document();
    assert_eq!(readiness.profile, "mainnet-bounded-pilot");
    assert!(readiness.trusted_bounded_pilot);

    let caps = readiness.declared_caps_hac();
    assert_eq!(caps.max_payment_hac.as_deref(), Some("1"));
    assert_eq!(caps.max_channel_funding_hac.as_deref(), Some("10"));
    // The field the wallet used to drop. Without it, a person sizing a deposit
    // against the channel cap has no way to see the Hub's total exposure cap.
    assert_eq!(caps.max_aggregate_tvl_hac.as_deref(), Some("100"));
    assert_eq!(caps.aggregate_tvl_within_limit, Some(true));
}

#[test]
fn the_hubs_own_named_blockers_survive_the_last_hop() {
    let readiness = live_document();
    assert!(!readiness.payments_enabled);

    // The single thing actually stopping this Hub, in its own words. Summarised
    // into "provider is online but does not support safe, fee-free routed
    // settlement yet", it sends a person off to change providers, which fixes
    // nothing: this Hub needs a synchronized HPAY fullnode, not a replacement.
    assert!(
        readiness
            .blockers
            .iter()
            .any(|blocker| blocker.starts_with("fullnode_capability_probe_failed")),
        "{:?}",
        readiness.blockers
    );

    // The bounded pilot routes its waived gates into disclosures rather than
    // blockers, deliberately. Both lists must reach a surface, and they must
    // stay distinguishable: one is why it cannot pay, the other is what is
    // outstanding and knowingly not gated on.
    assert!(
        readiness
            .disclosed_blockers
            .contains(&"external_monotonic_rollback_anchor_is_not_ready".to_string())
    );
    assert!(
        readiness
            .disclosed_blockers
            .contains(&"unilateral_l1_dispute_path_is_not_ready".to_string())
    );
    assert!(readiness.blockers.len() < readiness.disclosed_gaps().len());

    // And the aggregate cap is repeated in the Hub's own limitation prose, so
    // a surface that shows limitations shows the number twice rather than not
    // at all.
    assert!(
        readiness
            .limitations
            .iter()
            .any(|limitation| limitation.contains("10000000000 zhu")),
        "{:?}",
        readiness.limitations
    );
}

/// An older Hub does not send the aggregate fields. It must decode, and its
/// undeclared cap must read as undeclared rather than as a cap of zero.
#[test]
fn an_older_hub_that_omits_the_aggregate_cap_still_decodes_and_says_so() {
    let raw = include_str!("fixtures/hub-readiness-mainnet-bounded-pilot.json");
    let mut document: serde_json::Value = serde_json::from_str(raw).unwrap();
    let object = document.as_object_mut().unwrap();
    object.remove("max_aggregate_tvl_hac_zhu");
    object.remove("aggregate_tvl_within_limit");

    let readiness: HubMainnetReadiness = serde_json::from_value(document).unwrap();
    let caps = readiness.declared_caps_hac();
    assert_eq!(caps.max_aggregate_tvl_hac, None);
    assert_eq!(caps.aggregate_tvl_within_limit, None);
    // The caps it did declare are unaffected.
    assert_eq!(caps.max_channel_funding_hac.as_deref(), Some("10"));
}

/// A cap of zero is a declaration, not an absence.
///
/// `max_payment_hac_zhu` and `max_channel_funding_hac_zhu` carry no
/// `serde(default)`: a document missing either one fails to decode outright, so
/// a zero in those fields came from the Hub and means every payment or every
/// channel is refused. Rendering that as "not declared" would hide the single
/// number a person most needs to see before funding. Only the aggregate pair,
/// which an older Hub genuinely omits, may read as undeclared.
#[test]
fn a_hub_that_declares_a_cap_of_zero_says_zero_and_not_undeclared() {
    let raw = include_str!("fixtures/hub-readiness-mainnet-bounded-pilot.json");
    let mut document: serde_json::Value = serde_json::from_str(raw).unwrap();
    let object = document.as_object_mut().unwrap();
    object.insert("max_payment_hac_zhu".into(), serde_json::json!(0));
    object.insert("max_channel_funding_hac_zhu".into(), serde_json::json!(0));

    let readiness: HubMainnetReadiness = serde_json::from_value(document).unwrap();
    let caps = readiness.declared_caps_hac();
    assert_eq!(caps.max_payment_hac.as_deref(), Some("0"));
    assert_eq!(caps.max_channel_funding_hac.as_deref(), Some("0"));
    // The aggregate cap is still present in this document, so it still reads.
    assert_eq!(caps.max_aggregate_tvl_hac.as_deref(), Some("100"));
}

/// A required cap missing from the wire is a decode failure, not a silent zero.
/// This is what makes the rule above sound.
#[test]
fn a_document_missing_a_required_cap_does_not_decode_at_all() {
    let raw = include_str!("fixtures/hub-readiness-mainnet-bounded-pilot.json");
    let mut document: serde_json::Value = serde_json::from_str(raw).unwrap();
    document
        .as_object_mut()
        .unwrap()
        .remove("max_payment_hac_zhu");
    serde_json::from_value::<HubMainnetReadiness>(document)
        .expect_err("a readiness document without a payment cap must not decode");
}

/// THE FIELD THAT WOULD HAVE ANSWERED THE OWNER'S QUESTION.
///
/// `aggregate_tvl_within_limit` is the Hub's `current <= cap`, so a Hub holding
/// its entire budget publishes `true`. The first mainnet Fast Pay channel open
/// was refused by a Hub in exactly that state, and every field the wallet could
/// read said the Hub was healthy. A Hub now also publishes what its TVL is and
/// whether a new channel can be admitted at all; the wallet has to carry both
/// across the last hop or the addition changes nothing where a person is
/// looking.
#[test]
fn a_hub_at_exactly_its_cap_is_decoded_as_having_no_room_for_a_new_channel() {
    let raw = include_str!("fixtures/hub-readiness-mainnet-bounded-pilot.json");
    let mut document: serde_json::Value = serde_json::from_str(raw).unwrap();
    let object = document.as_object_mut().unwrap();
    // The owner's Hub: a cap of exactly one 0.2 HAC channel, entirely spent.
    object.insert(
        "max_aggregate_tvl_hac_zhu".into(),
        serde_json::json!(20_000_000),
    );
    object.insert(
        "aggregate_tvl_hac_zhu".into(),
        serde_json::json!(20_000_000),
    );
    object.insert(
        "aggregate_tvl_headroom_hac_zhu".into(),
        serde_json::json!(0),
    );
    object.insert(
        "new_channel_admission_available".into(),
        serde_json::json!(false),
    );
    // Unchanged, and the reason none of the old fields could raise the alarm.
    object.insert("aggregate_tvl_within_limit".into(), serde_json::json!(true));

    let readiness: HubMainnetReadiness = serde_json::from_value(document).unwrap();
    let caps = readiness.declared_caps_hac();
    assert_eq!(caps.max_aggregate_tvl_hac.as_deref(), Some("0.2"));
    assert_eq!(caps.aggregate_tvl_hac.as_deref(), Some("0.2"));
    assert_eq!(
        caps.aggregate_tvl_within_limit,
        Some(true),
        "the old flag still reads healthy, which is the whole problem"
    );
    assert_eq!(
        caps.new_channel_admission_available,
        Some(false),
        "and the new one says the Hub will refuse the next channel"
    );
}

/// A Hub that does not publish the new fields must read as "did not say", never
/// as "closed". `false` is the alarming value here, so a serde default would
/// have told every person on an older Hub that their Hub was shut.
#[test]
fn an_older_hub_that_omits_the_headroom_fields_says_nothing_rather_than_no() {
    let readiness = live_document();
    assert!(
        !readiness.blockers.is_empty(),
        "this fixture is a real Hub document, captured before the headroom \
         fields existed, which is exactly what an older Hub sends"
    );
    let caps = readiness.declared_caps_hac();
    assert_eq!(caps.new_channel_admission_available, None);
    assert_eq!(caps.aggregate_tvl_hac, None);
    // The fields it does carry are untouched by the addition.
    assert_eq!(caps.max_aggregate_tvl_hac.as_deref(), Some("100"));
    assert_eq!(caps.aggregate_tvl_within_limit, Some(true));
}

use super::*;
use crate::rollback_anchor::protocol::{HubAnchorRequestV1, SignedHubAnchorRequestV1};

const NOW: u64 = 1_800_000_000;

fn hub_account() -> Account {
    Account::create_by("rollback-anchor-witness-hub").unwrap()
}

fn receipt_account() -> Account {
    Account::create_by("rollback-anchor-witness-receipt").unwrap()
}

fn binding() -> String {
    "aa".repeat(32)
}

fn request(hub: &Account, serial: u64, counter: u64, bill_byte: u8) -> SignedHubAnchorRequestV1 {
    let previous = if serial <= 2 {
        "11".repeat(32)
    } else {
        format!("{:02x}", bill_byte.wrapping_sub(1)).repeat(32)
    };
    let request = HubAnchorRequestV1 {
        request_version: 1,
        request_id: format!("op-{serial}-{counter}-{bill_byte}"),
        hub_identity: hub.readable().to_owned(),
        witness_id: "witness-under-test".into(),
        witness_epoch: 1,
        settlement_profile: "hpay-hvm-shared-registry-v2".into(),
        network_instance_id: "22".repeat(32),
        binding_commitment: binding(),
        channel_id: "0123456789abcdef".into(),
        reuse_version: 1,
        serial,
        previous_bill_commitment: previous,
        proposed_bill_commitment: format!("{bill_byte:02x}").repeat(32),
        counter_value: counter,
        hub_journal_sequence: counter,
        hub_journal_head_hash: "33".repeat(32),
        hub_state_commitment: "44".repeat(32),
        created_at: NOW,
        expires_at: NOW + 60,
    };
    SignedHubAnchorRequestV1::sign(request, hub).unwrap()
}

fn chained(hub: &Account, serial: u64, counter: u64) -> SignedHubAnchorRequestV1 {
    // A chain where the bill commitment at serial N is byte 0x10 + N, so the
    // previous commitment of serial N is the proposed commitment of N - 1.
    let bill = 0x10_u8 + u8::try_from(serial).unwrap();
    let mut signed = request(hub, serial, counter, bill);
    signed.request.previous_bill_commitment = format!("{:02x}", bill - 1).repeat(32);
    SignedHubAnchorRequestV1::sign(signed.request, hub).unwrap()
}

/// The same ledger position under a fresh operation id. This is what a Hub
/// restored from backup produces: it does not know it already asked.
fn chained_as_new_operation(
    hub: &Account,
    serial: u64,
    counter: u64,
    request_id: &str,
) -> SignedHubAnchorRequestV1 {
    let mut signed = chained(hub, serial, counter);
    signed.request.request_id = request_id.to_owned();
    SignedHubAnchorRequestV1::sign(signed.request, hub).unwrap()
}

fn service(dir: &std::path::Path, receipt: Account) -> WitnessService {
    WitnessService::open(
        WitnessServiceConfig {
            witness_id: "witness-under-test".into(),
            witness_epoch: 1,
            store_path: dir.join("witness-log.jsonl"),
            receipt_account: receipt,
        },
        NOW,
    )
    .unwrap()
}

fn receipt_of(answer: HubWitnessAnswerV1) -> SignedHubWitnessReceiptV1 {
    match answer {
        HubWitnessAnswerV1::Receipt(receipt) => *receipt,
        HubWitnessAnswerV1::Refusal(refusal) => {
            panic!("expected a receipt, got {:?}", refusal.refusal.reason)
        }
    }
}

fn refusal_of(answer: HubWitnessAnswerV1) -> SignedHubWitnessRefusalV1 {
    match answer {
        HubWitnessAnswerV1::Refusal(refusal) => *refusal,
        HubWitnessAnswerV1::Receipt(receipt) => {
            panic!(
                "expected a refusal, got a receipt at serial {}",
                receipt.receipt.serial
            )
        }
    }
}

#[test]
fn the_counter_advances_by_exactly_one_and_the_receipt_binds_the_exact_bill() {
    let directory = tempfile::tempdir().unwrap();
    let hub = hub_account();
    let receipt_key = receipt_account();
    let service = service(directory.path(), receipt_key);

    let first = receipt_of(service.reserve(&chained(&hub, 2, 1), NOW).unwrap());
    first
        .verify_against_pinned_key(service.receipt_address())
        .unwrap();
    assert_eq!(first.receipt.previous_counter_value, 0);
    assert_eq!(first.receipt.counter_value, 1);
    assert_eq!(first.receipt.serial, 2);

    let second = receipt_of(service.reserve(&chained(&hub, 3, 2), NOW).unwrap());
    assert_eq!(second.receipt.previous_counter_value, 1);
    assert_eq!(second.receipt.counter_value, 2);
    assert_eq!(
        second.receipt.proposed_bill_commitment,
        chained(&hub, 3, 2).request.proposed_bill_commitment,
        "the receipt must attest to a unique bill, not merely a position"
    );
}

/// The core threat, at the witness. Two different bills at the same serial is
/// exactly the double signature the anchor exists to prevent.
#[test]
fn a_second_different_bill_at_the_same_serial_is_refused_as_a_fork() {
    let directory = tempfile::tempdir().unwrap();
    let hub = hub_account();
    let service = service(directory.path(), receipt_account());
    receipt_of(service.reserve(&chained(&hub, 2, 1), NOW).unwrap());

    let mut fork = chained(&hub, 2, 2);
    fork.request.request_id = "op-fork".into();
    fork.request.proposed_bill_commitment = "9f".repeat(32);
    let fork = SignedHubAnchorRequestV1::sign(fork.request, &hub).unwrap();
    let refusal = refusal_of(service.reserve(&fork, NOW).unwrap());
    assert_eq!(refusal.refusal.reason, WitnessRefusalReason::ForkAtSerial);
    assert_eq!(
        refusal.refusal.reason.identifier(),
        "rollback_anchor_fork_at_serial"
    );
}

/// An identical request replayed returns the identical reservation and does
/// **not** advance the counter. This is what makes the crash window between
/// "the witness recorded" and "the Hub persisted the receipt" recoverable.
#[test]
fn an_identical_replay_returns_the_same_receipt_and_a_changed_one_is_an_equivocation() {
    let directory = tempfile::tempdir().unwrap();
    let hub = hub_account();
    let service = service(directory.path(), receipt_account());
    let once = receipt_of(service.reserve(&chained(&hub, 2, 1), NOW).unwrap());
    let twice = receipt_of(service.reserve(&chained(&hub, 2, 1), NOW).unwrap());
    assert_eq!(once.receipt.counter_value, twice.receipt.counter_value);
    assert_eq!(once.receipt, twice.receipt);

    let mut equivocation = chained(&hub, 2, 1);
    equivocation.request.proposed_bill_commitment = "7e".repeat(32);
    let equivocation = SignedHubAnchorRequestV1::sign(equivocation.request, &hub).unwrap();
    let refusal = refusal_of(service.reserve(&equivocation, NOW).unwrap());
    assert_eq!(refusal.refusal.reason, WitnessRefusalReason::ReplayMismatch);
}

/// The requirement in one test: the witness refuses a counter it has already
/// passed, and that refusal survives its own restart because it is rebuilt
/// from the append-only log rather than held in memory.
#[test]
fn a_restarted_witness_still_refuses_a_counter_it_has_already_passed() {
    let directory = tempfile::tempdir().unwrap();
    let hub = hub_account();
    let instance_before;
    {
        let service = service(directory.path(), receipt_account());
        instance_before = service.instance_id().unwrap();
        receipt_of(service.reserve(&chained(&hub, 2, 1), NOW).unwrap());
        receipt_of(service.reserve(&chained(&hub, 3, 2), NOW).unwrap());
        receipt_of(service.reserve(&chained(&hub, 4, 3), NOW).unwrap());
    }

    // A brand new process over the same durable store.
    let service = service(directory.path(), receipt_account());
    assert_eq!(
        service.instance_id().unwrap(),
        instance_before,
        "the store identity must survive the process, or the Hub's pin means nothing"
    );

    let restored = chained_as_new_operation(&hub, 2, 1, "op-after-restore");
    let replayed = refusal_of(service.reserve(&restored, NOW).unwrap());
    assert_eq!(
        replayed.refusal.reason,
        WitnessRefusalReason::HubBehindWitness,
        "a counter and serial already passed must still be refused after a restart"
    );
    assert_eq!(replayed.refusal.observed_counter_value, 3);
    assert_eq!(replayed.refusal.observed_serial, 4);

    // And the next legitimate position still works, so the refusal is a
    // monotonic floor rather than a jam.
    let next = receipt_of(service.reserve(&chained(&hub, 5, 4), NOW).unwrap());
    assert_eq!(next.receipt.previous_counter_value, 3);
    assert_eq!(next.receipt.counter_value, 4);
}

#[test]
fn a_counter_that_skips_forward_is_refused() {
    let directory = tempfile::tempdir().unwrap();
    let hub = hub_account();
    let service = service(directory.path(), receipt_account());
    receipt_of(service.reserve(&chained(&hub, 2, 1), NOW).unwrap());

    let refusal = refusal_of(service.reserve(&chained(&hub, 3, 9), NOW).unwrap());
    assert_eq!(refusal.refusal.reason, WitnessRefusalReason::CounterSkipped);
}

/// A Hub that is ahead of the witness is refused too. An anchor that has
/// forgotten is not an anchor, and it must not be silently re-taught.
#[test]
fn a_witness_behind_the_hub_refuses_rather_than_catching_up() {
    let directory = tempfile::tempdir().unwrap();
    let hub = hub_account();
    let service = service(directory.path(), receipt_account());
    receipt_of(service.reserve(&chained(&hub, 2, 1), NOW).unwrap());

    let refusal = refusal_of(service.reserve(&chained(&hub, 9, 2), NOW).unwrap());
    assert_eq!(
        refusal.refusal.reason,
        WitnessRefusalReason::WitnessBehindHub
    );
}

#[test]
fn an_unsigned_or_expired_request_never_advances_the_counter() {
    let directory = tempfile::tempdir().unwrap();
    let hub = hub_account();
    let other = Account::create_by("rollback-anchor-not-the-hub").unwrap();
    let service = service(directory.path(), receipt_account());

    let forged = SignedHubAnchorRequestV1::sign(chained(&hub, 2, 1).request, &other).unwrap();
    let refusal = refusal_of(service.reserve(&forged, NOW).unwrap());
    assert_eq!(
        refusal.refusal.reason,
        WitnessRefusalReason::MalformedRequest
    );

    let expired = chained(&hub, 2, 1);
    let refusal = refusal_of(service.reserve(&expired, NOW + 3_600).unwrap());
    assert_eq!(refusal.refusal.reason, WitnessRefusalReason::Expired);

    // The counter never moved, so the next honest reservation is still 1.
    let accepted = receipt_of(service.reserve(&chained(&hub, 2, 1), NOW).unwrap());
    assert_eq!(accepted.receipt.counter_value, 1);
}

#[test]
fn a_store_whose_log_was_edited_refuses_to_open() {
    let directory = tempfile::tempdir().unwrap();
    let hub = hub_account();
    let path = directory.path().join("witness-log.jsonl");
    {
        let service = service(directory.path(), receipt_account());
        receipt_of(service.reserve(&chained(&hub, 2, 1), NOW).unwrap());
        receipt_of(service.reserve(&chained(&hub, 3, 2), NOW).unwrap());
    }
    let contents = std::fs::read_to_string(&path).unwrap();
    let mut lines: Vec<&str> = contents.lines().collect();
    // Remove the first reservation, which is what "restore the counter to an
    // older value" looks like on disk.
    lines.remove(1);
    std::fs::write(&path, lines.join("\n") + "\n").unwrap();
    assert!(
        WitnessStore::open(&path, "witness-under-test", NOW).is_err(),
        "a truncated append-only log must refuse to open rather than serve a lower counter"
    );
}

/// The crash window between "the witness recorded" and "the Hub persisted the
/// receipt" can outlive the request's own bounded lifetime: a Hub that crashed
/// there may not restart for hours. Replaying the identical request must
/// therefore still return the reservation the witness durably holds, freshly
/// stamped so the Hub can act on it, and must still not move the counter.
#[test]
fn an_identical_replay_after_the_request_expired_still_returns_the_held_reservation() {
    let directory = tempfile::tempdir().unwrap();
    let hub = hub_account();
    let service = service(directory.path(), receipt_account());
    let first = receipt_of(service.reserve(&chained(&hub, 2, 1), NOW).unwrap());
    assert_eq!(first.receipt.counter_value, 1);

    let much_later = NOW + 86_400;
    let replayed = receipt_of(service.reserve(&chained(&hub, 2, 1), much_later).unwrap());
    assert_eq!(
        replayed.receipt.counter_value, 1,
        "a replay must never advance the counter"
    );
    assert_eq!(replayed.receipt.serial, first.receipt.serial);
    assert_eq!(
        replayed.receipt.proposed_bill_commitment, first.receipt.proposed_bill_commitment,
        "a replay authorises the same exact bill and no other"
    );
    assert!(
        replayed.receipt.receipt_expires_at > much_later,
        "the re-attestation must be usable now, or the honest retry is impossible"
    );

    // A brand new request at the same expired timestamp is still refused: only
    // a reservation the witness already holds escapes the clock.
    let fresh = chained_as_new_operation(&hub, 3, 2, "op-expired-fresh");
    assert_eq!(
        refusal_of(service.reserve(&fresh, much_later).unwrap())
            .refusal
            .reason,
        WitnessRefusalReason::Expired
    );
}

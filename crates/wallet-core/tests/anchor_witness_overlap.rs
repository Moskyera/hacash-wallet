//! The counterparty-side rollback-anchor ratchet.
//!
//! Every new bill must carry a receipt from at least one witness that
//! receipted the counterparty's most recently accepted bill — and, more
//! strongly, no witness the wallet recorded may silently disappear.
//!
//! These tests need no `rollback-witness` feature and no witness service:
//! `SignedHubWitnessReceiptV1::sign` is public and ungated, so an ordinary
//! account is enough to mint both honest and adversarial receipts.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use hacash_wallet_core::account::WalletAccount;
use hacash_wallet_core::l2_safety::{
    ANCHOR_WITNESS_DECISION_REQUIRED, AnchorWitnessDecision, ClientL2Safety,
};
use l2_fast_pay_hub::rollback_anchor::{HubWitnessReceiptV1, SignedHubWitnessReceiptV1};

const HUB_PASSPHRASE: &str = "anchor-overlap-hub";
const PAYER_PASSPHRASE: &str = "anchor-overlap-payer";

fn hash64(tag: u8) -> String {
    format!("{tag:02x}").repeat(32)
}

struct Rig {
    _root: tempfile::TempDir,
    l2: PathBuf,
    payer: WalletAccount,
    hub_identity: String,
    scope: String,
    channel_id: String,
}

impl Rig {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let l2 = root.path().join("l2");
        let payer = WalletAccount::create(PAYER_PASSPHRASE).unwrap();
        let hub = WalletAccount::create(HUB_PASSPHRASE).unwrap();
        let scope = format!("personal:{}", payer.address());
        Self {
            _root: root,
            l2,
            hub_identity: hub.address(),
            scope,
            channel_id: hash64(0x11),
            payer,
        }
    }

    fn open(&self) -> ClientL2Safety {
        ClientL2Safety::open_scoped_with_key_provider_for_network(
            &self.payer,
            &self.l2,
            &self.scope,
            "testnet",
            &self.hub_identity,
            &self.channel_id,
        )
        .unwrap()
    }

    fn open_error(&self) -> String {
        match ClientL2Safety::open_scoped_with_key_provider_for_network(
            &self.payer,
            &self.l2,
            &self.scope,
            "testnet",
            &self.hub_identity,
            &self.channel_id,
        ) {
            Ok(_) => panic!("the store opened when it should have refused"),
            Err(error) => error.to_string(),
        }
    }

    fn state_file(&self) -> PathBuf {
        only_child(&self.l2).join("operations.json")
    }
}

fn only_child(root: &Path) -> PathBuf {
    let mut entries: Vec<PathBuf> = std::fs::read_dir(root)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();
    assert_eq!(entries.len(), 1, "expected exactly one scoped store");
    entries.pop().unwrap()
}

/// One witness, described by everything the overlap key and the ratchet use.
struct Witness {
    passphrase: String,
    account: WalletAccount,
    /// The Hub-typed label. Evidence for a human, never part of the key.
    label: String,
    instance: String,
    epoch: u64,
}

impl Witness {
    fn new(passphrase: &str, label: &str, instance_tag: u8) -> Self {
        Self {
            passphrase: passphrase.to_owned(),
            account: WalletAccount::create(passphrase).unwrap(),
            label: label.to_owned(),
            instance: hash64(instance_tag),
            epoch: 1,
        }
    }

    /// The same signing key, a brand-new durable store. This is the amnesia
    /// attack, and it is indistinguishable from an innocent witness rebuild.
    fn reprovisioned(&self, instance_tag: u8) -> Self {
        let mut rebuilt = Self::new(&self.passphrase, &self.label, instance_tag);
        rebuilt.epoch = self.epoch;
        rebuilt
    }

    fn receipt(
        &self,
        hub_identity: &str,
        binding: &str,
        serial: u64,
        bill_commitment: &str,
        counter: u64,
    ) -> HubWitnessReceiptV1 {
        HubWitnessReceiptV1 {
            receipt_version: 1,
            request_id: format!("req-{serial}-{}", self.label),
            request_commitment: hash64(0x22),
            witness_id: self.label.clone(),
            witness_epoch: self.epoch,
            witness_instance_id: self.instance.clone(),
            witness_boot_id: hash64(0x33),
            hub_identity: hub_identity.to_owned(),
            binding_commitment: binding.to_owned(),
            serial,
            proposed_bill_commitment: bill_commitment.to_owned(),
            previous_counter_value: counter - 1,
            counter_value: counter,
            accepted_at: 1_700_000_000,
            receipt_expires_at: 1_700_000_060,
        }
    }

    fn sign(&self, receipt: HubWitnessReceiptV1) -> SignedHubWitnessReceiptV1 {
        SignedHubWitnessReceiptV1::sign(receipt, self.account.inner()).unwrap()
    }
}

// ---------------------------------------------------------------------------
// 1. RECORD — migration over a real store written before the field existed.
// ---------------------------------------------------------------------------

/// `crates/wallet-core/tests/fixtures/l2-safety-pre-anchor` was produced by
/// running the previous version of this code, not by hand. If the new field
/// changed the serialised bytes, `state_commitment` would move and
/// `initialize_state` would refuse the store with "RecoveryRequired: L2
/// journal and materialized state differ" — bricking every channel that
/// already exists.
#[test]
fn a_store_written_before_the_anchor_field_existed_still_opens() {
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("l2-safety-pre-anchor");
    let raw = std::fs::read_to_string(only_child(&fixture).join("operations.json")).unwrap();
    assert!(
        !raw.contains("anchor_witness_memory"),
        "the fixture must predate the field it is proving migration for"
    );

    let root = tempfile::tempdir().unwrap();
    let l2 = root.path().join("l2");
    std::fs::create_dir_all(&l2).unwrap();
    let source = only_child(&fixture);
    let target = l2.join(source.file_name().unwrap());
    std::fs::create_dir_all(&target).unwrap();
    for file in std::fs::read_dir(&source).unwrap() {
        let file = file.unwrap();
        std::fs::copy(file.path(), target.join(file.file_name())).unwrap();
    }

    let payer = WalletAccount::create("pre-anchor-fixture-payer").unwrap();
    let hub = WalletAccount::create("pre-anchor-fixture-hub").unwrap();
    let scope = format!("personal:{}", payer.address());
    let safety = ClientL2Safety::open_scoped_with_key_provider_for_network(
        &payer,
        &l2,
        &scope,
        "testnet",
        &hub.address(),
        "0000000000000000000000000000000000000000000000000000000000000001",
    )
    .expect("a store written before the anchor field must still open");
    assert!(safety.anchor_memory(&hash64(0x11)).is_none());
    drop(safety);

    // Opening it did not rewrite it into a shape the previous version could
    // not read back.
    let after = std::fs::read_to_string(target.join("operations.json")).unwrap();
    assert_eq!(raw, after);
}

/// The record is not a sidecar and is not `#[serde(skip)]`. Blanking it with a
/// text editor makes the next bill look like a first bill, which resets the
/// ratchet to whatever the Hub declares. It must be inside `state_commitment`.
#[test]
fn erasing_the_anchor_record_with_a_text_editor_breaks_the_store_open() {
    let rig = Rig::new();
    let witness = Witness::new("anchor-w1", "witness-one", 0x41);
    let binding = hash64(0x51);
    let bill = hash64(0x61);

    let mut safety = rig.open();
    safety
        .accept_anchored_bill(
            &binding,
            &rig.hub_identity,
            &bill,
            1,
            &[witness.sign(witness.receipt(&rig.hub_identity, &binding, 1, &bill, 7))],
            0,
        )
        .unwrap();
    drop(safety);

    let path = rig.state_file();
    let raw = std::fs::read_to_string(&path).unwrap();
    assert!(raw.contains("anchor_witness_memory"));
    let mut value: serde_json::Value = serde_json::from_str(&raw).unwrap();
    value
        .as_object_mut()
        .unwrap()
        .remove("anchor_witness_memory");
    std::fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();

    let error = rig.open_error();
    assert!(
        error.contains("RecoveryRequired"),
        "unexpected error: {error}"
    );
}

// ---------------------------------------------------------------------------
// 2. VERIFY — a receipt that does not verify is not a receipt.
// ---------------------------------------------------------------------------

/// The Hub types `witness_id`. Overlapping on it would be defeated in one
/// line: claim the honest witness's label while signing with your own key.
/// The recovered address is what enters the set, so the claim buys nothing.
#[test]
fn claiming_a_witness_label_while_signing_with_another_key_is_a_drop_not_an_overlap() {
    let rig = Rig::new();
    let honest = Witness::new("anchor-honest", "honest-witness", 0x41);
    let mut impostor = Witness::new("anchor-impostor", "honest-witness", 0x41);
    impostor.label = honest.label.clone();
    impostor.instance = honest.instance.clone();
    let binding = hash64(0x51);

    let mut safety = rig.open();
    let bill1 = hash64(0x61);
    safety
        .accept_anchored_bill(
            &binding,
            &rig.hub_identity,
            &bill1,
            1,
            &[honest.sign(honest.receipt(&rig.hub_identity, &binding, 1, &bill1, 7))],
            0,
        )
        .unwrap();

    // Same label, same instance id, different signing key.
    let bill2 = hash64(0x62);
    let error = safety
        .accept_anchored_bill(
            &binding,
            &rig.hub_identity,
            &bill2,
            2,
            &[impostor.sign(impostor.receipt(&rig.hub_identity, &binding, 2, &bill2, 8))],
            0,
        )
        .expect_err("an impostor must not satisfy overlap");
    assert!(
        error.to_string().contains(ANCHOR_WITNESS_DECISION_REQUIRED),
        "unexpected error: {error}"
    );
    let change = safety.pending_anchor_decision(&binding).unwrap();
    assert!(change.is_zero_overlap());
    assert_eq!(change.dropped.len(), 1);
    assert_eq!(
        change.dropped[0].signer_address,
        honest.account.address(),
        "the dropped witness is identified by the key that provably signed"
    );
}

#[test]
fn a_receipt_whose_signature_was_tampered_with_is_refused() {
    let rig = Rig::new();
    let witness = Witness::new("anchor-w1", "witness-one", 0x41);
    let binding = hash64(0x51);
    let bill = hash64(0x61);
    let mut signed = witness.sign(witness.receipt(&rig.hub_identity, &binding, 1, &bill, 7));
    // Flip the last nibble of the signature, leaving the carried public key
    // intact so only the ECDSA check can catch it.
    let mut chars: Vec<char> = signed.signature_hex.chars().collect();
    let last = chars.len() - 1;
    chars[last] = if chars[last] == 'a' { 'b' } else { 'a' };
    signed.signature_hex = chars.into_iter().collect();

    let mut safety = rig.open();
    let error = safety
        .accept_anchored_bill(&binding, &rig.hub_identity, &bill, 1, &[signed], 0)
        .expect_err("a bad signature is not a receipt");
    assert!(
        error.to_string().contains("does not verify"),
        "unexpected error: {error}"
    );
    assert!(safety.anchor_memory(&binding).is_none());
}

/// A receipt is only evidence for the exact bill, channel, Hub and serial it
/// names. Replaying one for a different bill at the same serial is the whole
/// point of the attack, so this must be a hard refusal and never a prompt.
#[test]
fn a_receipt_bound_to_another_bill_channel_or_hub_is_refused() {
    let rig = Rig::new();
    let witness = Witness::new("anchor-w1", "witness-one", 0x41);
    let binding = hash64(0x51);
    let bill = hash64(0x61);
    let other_bill = hash64(0x62);
    let other_binding = hash64(0x52);
    let mut safety = rig.open();

    let wrong_bill = witness.sign(witness.receipt(&rig.hub_identity, &binding, 1, &other_bill, 7));
    let error = safety
        .accept_anchored_bill(&binding, &rig.hub_identity, &bill, 1, &[wrong_bill], 0)
        .expect_err("replay onto another bill must be refused");
    assert!(
        error.to_string().contains("different bill"),
        "unexpected error: {error}"
    );

    let wrong_channel =
        witness.sign(witness.receipt(&rig.hub_identity, &other_binding, 1, &bill, 7));
    let error = safety
        .accept_anchored_bill(&binding, &rig.hub_identity, &bill, 1, &[wrong_channel], 0)
        .expect_err("a receipt for another channel must be refused");
    assert!(
        error.to_string().contains("different channel"),
        "unexpected error: {error}"
    );

    let other_hub = WalletAccount::create("anchor-other-hub").unwrap().address();
    let wrong_hub = witness.sign(witness.receipt(&other_hub, &binding, 1, &bill, 7));
    let error = safety
        .accept_anchored_bill(&binding, &rig.hub_identity, &bill, 1, &[wrong_hub], 0)
        .expect_err("a receipt for another Hub must be refused");
    assert!(
        error.to_string().contains("different Hub"),
        "unexpected error: {error}"
    );

    let wrong_serial = witness.sign(witness.receipt(&rig.hub_identity, &binding, 2, &bill, 7));
    let error = safety
        .accept_anchored_bill(&binding, &rig.hub_identity, &bill, 1, &[wrong_serial], 0)
        .expect_err("a receipt for another serial must be refused");
    assert!(
        error.to_string().contains("different serial"),
        "unexpected error: {error}"
    );

    assert!(safety.anchor_memory(&binding).is_none());
}

/// One bad receipt refuses the whole envelope, so a Hub cannot pad with junk
/// to obscure which receipt is the real one.
#[test]
fn one_unverifiable_receipt_refuses_the_whole_envelope() {
    let rig = Rig::new();
    let good = Witness::new("anchor-w1", "witness-one", 0x41);
    let bad = Witness::new("anchor-w2", "witness-two", 0x42);
    let binding = hash64(0x51);
    let bill = hash64(0x61);
    let mut junk = bad.sign(bad.receipt(&rig.hub_identity, &binding, 1, &bill, 3));
    junk.receipt.counter_value += 1; // now signed over different bytes

    let mut safety = rig.open();
    let error = safety
        .accept_anchored_bill(
            &binding,
            &rig.hub_identity,
            &bill,
            1,
            &[
                good.sign(good.receipt(&rig.hub_identity, &binding, 1, &bill, 7)),
                junk,
            ],
            0,
        )
        .expect_err("padding with junk must refuse the envelope");
    assert!(
        error.to_string().contains("does not verify"),
        "unexpected error: {error}"
    );
    assert!(safety.anchor_memory(&binding).is_none());
}

// ---------------------------------------------------------------------------
// 3. DECIDE — overlap, and what happens when it is gone.
// ---------------------------------------------------------------------------

#[test]
fn the_first_bill_records_a_baseline_silently_and_the_second_ratchets() {
    let rig = Rig::new();
    let witness = Witness::new("anchor-w1", "witness-one", 0x41);
    let binding = hash64(0x51);
    let mut safety = rig.open();

    let bill1 = hash64(0x61);
    safety
        .accept_anchored_bill(
            &binding,
            &rig.hub_identity,
            &bill1,
            1,
            &[witness.sign(witness.receipt(&rig.hub_identity, &binding, 1, &bill1, 7))],
            0,
        )
        .unwrap();
    assert!(safety.pending_anchor_decision(&binding).is_none());
    let memory = safety.anchor_memory(&binding).unwrap();
    assert_eq!(memory.accepted_serial, 1);
    assert_eq!(memory.witnesses.len(), 1);
    let record = memory.witnesses.values().next().unwrap();
    assert_eq!(record.signer_address, witness.account.address());
    assert_eq!(record.highest_counter_value, 7);
    assert_eq!(record.witness_id, "witness-one");

    let bill2 = hash64(0x62);
    safety
        .accept_anchored_bill(
            &binding,
            &rig.hub_identity,
            &bill2,
            2,
            &[witness.sign(witness.receipt(&rig.hub_identity, &binding, 2, &bill2, 8))],
            0,
        )
        .unwrap();
    assert!(safety.pending_anchor_decision(&binding).is_none());
    let memory = safety.anchor_memory(&binding).unwrap();
    assert_eq!(memory.accepted_serial, 2);
    assert_eq!(memory.accepted_bill_commitment, bill2);
    assert_eq!(
        memory
            .witnesses
            .values()
            .next()
            .unwrap()
            .highest_counter_value,
        8
    );

    // The record survives a close and reopen: it is durable, journalled and
    // inside the state commitment.
    drop(safety);
    let safety = rig.open();
    assert_eq!(safety.anchor_memory(&binding).unwrap().accepted_serial, 2);
}

/// The exact case ADR-001 declares undetectable Hub-side: the operator stops
/// both, restores Hub and witness together, and restarts. Same instance id,
/// counter exactly where the Hub expects it. The counterparty's memory was in
/// neither backup set, so the counter going backwards is visible here.
#[test]
fn a_witness_counter_that_goes_backwards_is_a_hard_refusal_not_a_decision() {
    let rig = Rig::new();
    let witness = Witness::new("anchor-w1", "witness-one", 0x41);
    let binding = hash64(0x51);
    let mut safety = rig.open();

    let bill1 = hash64(0x61);
    safety
        .accept_anchored_bill(
            &binding,
            &rig.hub_identity,
            &bill1,
            1,
            &[witness.sign(witness.receipt(&rig.hub_identity, &binding, 1, &bill1, 40))],
            0,
        )
        .unwrap();

    let bill2 = hash64(0x62);
    let error = safety
        .accept_anchored_bill(
            &binding,
            &rig.hub_identity,
            &bill2,
            2,
            &[witness.sign(witness.receipt(&rig.hub_identity, &binding, 2, &bill2, 12))],
            0,
        )
        .expect_err("a restored witness counter must be refused");
    assert!(
        error
            .to_string()
            .contains("rollback_anchor_witness_behind_hub"),
        "unexpected error: {error}"
    );
    assert!(
        safety.pending_anchor_decision(&binding).is_none(),
        "a witness contradicting itself is not a user choice"
    );
    assert_eq!(safety.anchor_memory(&binding).unwrap().accepted_serial, 1);
}

/// Re-spending at or below the accepted head is the attack itself.
#[test]
fn a_bill_at_or_below_the_accepted_head_is_refused() {
    let rig = Rig::new();
    let witness = Witness::new("anchor-w1", "witness-one", 0x41);
    let binding = hash64(0x51);
    let mut safety = rig.open();

    let bill5 = hash64(0x65);
    safety
        .accept_anchored_bill(
            &binding,
            &rig.hub_identity,
            &bill5,
            5,
            &[witness.sign(witness.receipt(&rig.hub_identity, &binding, 5, &bill5, 40))],
            0,
        )
        .unwrap();

    // A different bill at the same serial, with a perfectly monotone counter.
    let forked = hash64(0x66);
    let error = safety
        .accept_anchored_bill(
            &binding,
            &rig.hub_identity,
            &forked,
            5,
            &[witness.sign(witness.receipt(&rig.hub_identity, &binding, 5, &forked, 41))],
            0,
        )
        .expect_err("a fork at the accepted serial must be refused");
    assert!(
        error
            .to_string()
            .contains("rollback_anchor_witness_behind_hub"),
        "unexpected error: {error}"
    );

    // Re-presenting the exact accepted head is idempotent: this is the crash
    // window between the Hub co-signing and the wallet persisting.
    safety
        .accept_anchored_bill(
            &binding,
            &rig.hub_identity,
            &bill5,
            5,
            &[witness.sign(witness.receipt(&rig.hub_identity, &binding, 5, &bill5, 42))],
            0,
        )
        .unwrap();
    assert_eq!(safety.anchor_memory(&binding).unwrap().accepted_serial, 5);
}

/// The recorded head is the one place a bill was handed back as accepted with
/// the whole rule skipped.
///
/// The crash-window door has to exist — a wallet that died between the Hub
/// signing and its own persist must be able to re-accept that head or the
/// channel is stuck. But it opened before the counter ratchet and before the
/// drop comparison, so a Hub could re-serve the head having dropped every
/// witness, or with a counter that had gone backwards after a Hub+witness
/// co-restore, and be told yes with nothing checked. It must be the *narrow*
/// door: same head, and still fully covered.
#[test]
fn re_affirming_the_recorded_head_still_runs_the_whole_rule() {
    let rig = Rig::new();
    let witness = Witness::new("anchor-w1", "witness-one", 0x41);
    let binding = hash64(0x51);
    let bill = hash64(0x65);
    let mut safety = rig.open();
    safety
        .accept_anchored_bill(
            &binding,
            &rig.hub_identity,
            &bill,
            5,
            &[witness.sign(witness.receipt(&rig.hub_identity, &binding, 5, &bill, 40))],
            0,
        )
        .unwrap();

    // The same head, with every witness gone. This used to return Ok.
    let error = safety
        .accept_anchored_bill(&binding, &rig.hub_identity, &bill, 5, &[], 0)
        .expect_err("re-affirming the head with no witnesses at all must reach a human");
    assert!(
        error.to_string().contains(ANCHOR_WITNESS_DECISION_REQUIRED),
        "unexpected error: {error}"
    );
    let parked = safety
        .pending_anchor_decision(&binding)
        .expect("the change must be parked durably");
    assert!(parked.is_zero_overlap());
    safety
        .resolve_anchor_witness_change(&binding, AnchorWitnessDecision::AcceptNewWitnessSet)
        .unwrap();

    // And a counter that went backwards at the head is still a hard refusal.
    let rig = Rig::new();
    let binding = hash64(0x52);
    let mut safety = rig.open();
    safety
        .accept_anchored_bill(
            &binding,
            &rig.hub_identity,
            &bill,
            5,
            &[witness.sign(witness.receipt(&rig.hub_identity, &binding, 5, &bill, 40))],
            0,
        )
        .unwrap();
    let error = safety
        .accept_anchored_bill(
            &binding,
            &rig.hub_identity,
            &bill,
            5,
            &[witness.sign(witness.receipt(&rig.hub_identity, &binding, 5, &bill, 39))],
            0,
        )
        .expect_err("a witness contradicting itself at the head must be refused");
    assert!(
        error
            .to_string()
            .contains("rollback_anchor_witness_behind_hub"),
        "unexpected error: {error}"
    );

    // The honest crash-window replay — same head, same receipts — still works,
    // which is the whole reason the door exists.
    safety
        .accept_anchored_bill(
            &binding,
            &rig.hub_identity,
            &bill,
            5,
            &[witness.sign(witness.receipt(&rig.hub_identity, &binding, 5, &bill, 40))],
            0,
        )
        .unwrap();
    assert_eq!(safety.anchor_memory(&binding).unwrap().accepted_serial, 5);
}

/// The cheapest attack on the counterparty ratchet is not cryptographic: it is
/// `rm -rf` on the store directory. A missing file is not a corrupt file, so
/// nothing inside the store can notice — a fresh store opens clean and the
/// next bill takes the first-bill branch, where the witness set is whatever
/// the Hub declares.
///
/// The only thing that can tell "new channel" from "lost memory" is a record
/// held somewhere else. The caller states the highest serial it can prove from
/// its own store, and a missing memory above zero is refused.
#[test]
fn deleting_the_store_does_not_reset_the_ratchet_when_the_wallet_remembers_paying() {
    let rig = Rig::new();
    let attacker = Witness::new("anchor-attacker", "witness-one", 0x41);
    let binding = hash64(0x51);
    let bill = hash64(0x67);

    // A brand-new store — exactly what deleting the directory produces — and a
    // wallet whose own payment history says this channel is at serial 46.
    let mut safety = rig.open();
    let error = safety
        .accept_anchored_bill(
            &binding,
            &rig.hub_identity,
            &bill,
            47,
            &[attacker.sign(attacker.receipt(&rig.hub_identity, &binding, 47, &bill, 900))],
            46,
        )
        .expect_err("a lost memory must not be re-baselined on the Hub's word");
    assert!(
        error
            .to_string()
            .contains("rollback_anchor_memory_behind_wallet"),
        "unexpected error: {error}"
    );
    assert!(
        safety.anchor_memory(&binding).is_none(),
        "a refusal must not write a baseline"
    );

    // A genuinely new channel — nothing known, nothing claimed — still starts.
    safety
        .accept_anchored_bill(
            &binding,
            &rig.hub_identity,
            &bill,
            47,
            &[attacker.sign(attacker.receipt(&rig.hub_identity, &binding, 47, &bill, 900))],
            0,
        )
        .unwrap();
}

/// Restoring the wallet's own L2 store from an older *coherent* snapshot —
/// state, journal and checkpoint together — opens clean, because nothing in it
/// disagrees with anything else in it. It is simply behind. This is the exact
/// mirror of the Hub-side restore the whole ADR exists to catch, and it needs
/// the counterparty's disk rather than the Hub's.
///
/// The wallet's own payment history is in a different store, under a different
/// key, with its own journal, and was not in that backup set.
#[test]
fn an_anchor_memory_behind_the_wallets_own_history_is_refused() {
    let rig = Rig::new();
    let witness = Witness::new("anchor-w1", "witness-one", 0x41);
    let binding = hash64(0x51);
    let bill = hash64(0x65);
    let mut safety = rig.open();
    safety
        .accept_anchored_bill(
            &binding,
            &rig.hub_identity,
            &bill,
            5,
            &[witness.sign(witness.receipt(&rig.hub_identity, &binding, 5, &bill, 40))],
            0,
        )
        .unwrap();

    // The store says 5. The rest of the wallet says 9. Only one of those two
    // was in the backup that was restored.
    let next = hash64(0x66);
    let error = safety
        .accept_anchored_bill(
            &binding,
            &rig.hub_identity,
            &next,
            10,
            &[witness.sign(witness.receipt(&rig.hub_identity, &binding, 10, &next, 41))],
            9,
        )
        .expect_err("an anchor memory behind the wallet's own history must be refused");
    assert!(
        error
            .to_string()
            .contains("rollback_anchor_memory_behind_wallet"),
        "unexpected error: {error}"
    );
    assert_eq!(
        safety.anchor_memory(&binding).unwrap().accepted_serial,
        5,
        "nothing may be written by a refusal"
    );

    // A floor the memory already covers changes nothing.
    safety
        .accept_anchored_bill(
            &binding,
            &rig.hub_identity,
            &next,
            10,
            &[witness.sign(witness.receipt(&rig.hub_identity, &binding, 10, &next, 41))],
            5,
        )
        .unwrap();
}

/// The predicate is "no recorded witness silently disappears", not "at least
/// one survives". A Hub running its own witness E alongside an honest W would
/// satisfy "at least one" forever while dropping W — the only witness that
/// actually holds the serial it wants to re-spend.
#[test]
fn padding_the_set_then_dropping_the_honest_witness_still_reaches_a_human() {
    let rig = Rig::new();
    let honest = Witness::new("anchor-honest", "honest-witness", 0x41);
    let hub_owned = Witness::new("anchor-hub-owned", "hub-witness", 0x42);
    let binding = hash64(0x51);
    let mut safety = rig.open();

    let bill1 = hash64(0x61);
    safety
        .accept_anchored_bill(
            &binding,
            &rig.hub_identity,
            &bill1,
            1,
            &[
                honest.sign(honest.receipt(&rig.hub_identity, &binding, 1, &bill1, 7)),
                hub_owned.sign(hub_owned.receipt(&rig.hub_identity, &binding, 1, &bill1, 3)),
            ],
            0,
        )
        .unwrap();
    assert_eq!(safety.anchor_memory(&binding).unwrap().witnesses.len(), 2);

    // Now drop the honest one. The intersection is still non-empty.
    let bill2 = hash64(0x62);
    let error = safety
        .accept_anchored_bill(
            &binding,
            &rig.hub_identity,
            &bill2,
            2,
            &[hub_owned.sign(hub_owned.receipt(&rig.hub_identity, &binding, 2, &bill2, 4))],
            0,
        )
        .expect_err("shedding the honest witness must reach a human");
    assert!(
        error.to_string().contains(ANCHOR_WITNESS_DECISION_REQUIRED),
        "unexpected error: {error}"
    );
    let change = safety.pending_anchor_decision(&binding).unwrap();
    assert!(
        !change.is_zero_overlap(),
        "this is a partial drop, and it must still prompt"
    );
    assert_eq!(change.dropped.len(), 1);
    assert_eq!(change.dropped[0].signer_address, honest.account.address());
    assert_eq!(change.retained.len(), 1);
    assert_eq!(
        safety.anchor_memory(&binding).unwrap().accepted_serial,
        1,
        "the channel must not advance while parked"
    );
}

/// Re-provisioning a witness store with the same key gives the same address
/// and a counter back at zero. Keyed on the address alone the amnesia attack
/// would pass overlap; keyed on `(address, instance)` it is a drop.
#[test]
fn a_reprovisioned_witness_store_is_a_drop_even_with_the_same_key() {
    let rig = Rig::new();
    let witness = Witness::new("anchor-w1", "witness-one", 0x41);
    let binding = hash64(0x51);
    let mut safety = rig.open();

    let bill1 = hash64(0x61);
    safety
        .accept_anchored_bill(
            &binding,
            &rig.hub_identity,
            &bill1,
            1,
            &[witness.sign(witness.receipt(&rig.hub_identity, &binding, 1, &bill1, 40))],
            0,
        )
        .unwrap();

    let rebuilt = witness.reprovisioned(0x99);
    assert_eq!(rebuilt.account.address(), witness.account.address());
    let bill2 = hash64(0x62);
    let error = safety
        .accept_anchored_bill(
            &binding,
            &rig.hub_identity,
            &bill2,
            2,
            &[rebuilt.sign(rebuilt.receipt(&rig.hub_identity, &binding, 2, &bill2, 1))],
            0,
        )
        .expect_err("a fresh witness store is a new member");
    assert!(
        error.to_string().contains(ANCHOR_WITNESS_DECISION_REQUIRED),
        "unexpected error: {error}"
    );
    let change = safety.pending_anchor_decision(&binding).unwrap();
    assert!(change.is_zero_overlap());
    assert_eq!(change.dropped[0].witness_instance_id, hash64(0x41));
    assert_eq!(change.offered[0].witness_instance_id, hash64(0x99));
}

/// Absent must deserialise to the same value as empty, so omitting the
/// envelope is not a bypass — it is the loudest prompt in the system.
#[test]
fn shipping_no_receipts_after_a_recorded_set_is_the_loudest_prompt() {
    let rig = Rig::new();
    let witness = Witness::new("anchor-w1", "witness-one", 0x41);
    let binding = hash64(0x51);
    let mut safety = rig.open();

    let bill1 = hash64(0x61);
    safety
        .accept_anchored_bill(
            &binding,
            &rig.hub_identity,
            &bill1,
            1,
            &[witness.sign(witness.receipt(&rig.hub_identity, &binding, 1, &bill1, 7))],
            0,
        )
        .unwrap();

    let bill2 = hash64(0x62);
    let error = safety
        .accept_anchored_bill(&binding, &rig.hub_identity, &bill2, 2, &[], 0)
        .expect_err("an empty receipt set must never silently reset the ratchet");
    assert!(
        error.to_string().contains(ANCHOR_WITNESS_DECISION_REQUIRED),
        "unexpected error: {error}"
    );
    let change = safety.pending_anchor_decision(&binding).unwrap();
    assert!(change.is_zero_overlap());
    assert!(change.offered.is_empty());
    assert!(
        change
            .headline()
            .contains("no longer shares any witness with the one that signed your last bill")
    );
}

/// A Hub with no anchor at all is a durable statement, not a hole: recorded on
/// the first bill, and non-empty afterwards can never silently become empty.
#[test]
fn an_unanchored_hub_is_recorded_on_the_first_bill_and_does_not_block() {
    let rig = Rig::new();
    let binding = hash64(0x51);
    let mut safety = rig.open();
    let bill1 = hash64(0x61);
    safety
        .accept_anchored_bill(&binding, &rig.hub_identity, &bill1, 1, &[], 0)
        .unwrap();
    let memory = safety.anchor_memory(&binding).unwrap();
    assert!(memory.witnesses.is_empty());
    assert_eq!(memory.accepted_serial, 1);

    // empty -> non-empty is a strengthening, and is silent.
    let witness = Witness::new("anchor-w1", "witness-one", 0x41);
    let bill2 = hash64(0x62);
    safety
        .accept_anchored_bill(
            &binding,
            &rig.hub_identity,
            &bill2,
            2,
            &[witness.sign(witness.receipt(&rig.hub_identity, &binding, 2, &bill2, 7))],
            0,
        )
        .unwrap();
    assert_eq!(safety.anchor_memory(&binding).unwrap().witnesses.len(), 1);
}

/// Parked is neither a silent accept nor an automatic halt: the channel does
/// not advance, the wallet stays usable, and the decision survives a restart.
#[test]
fn a_parked_decision_blocks_advancement_and_survives_a_restart() {
    let rig = Rig::new();
    let w1 = Witness::new("anchor-w1", "witness-one", 0x41);
    let w2 = Witness::new("anchor-w2", "witness-two", 0x42);
    let binding = hash64(0x51);

    let mut safety = rig.open();
    let bill1 = hash64(0x61);
    safety
        .accept_anchored_bill(
            &binding,
            &rig.hub_identity,
            &bill1,
            1,
            &[w1.sign(w1.receipt(&rig.hub_identity, &binding, 1, &bill1, 7))],
            0,
        )
        .unwrap();
    let bill2 = hash64(0x62);
    safety
        .accept_anchored_bill(
            &binding,
            &rig.hub_identity,
            &bill2,
            2,
            &[w2.sign(w2.receipt(&rig.hub_identity, &binding, 2, &bill2, 3))],
            0,
        )
        .expect_err("a rotation must reach a human");
    drop(safety);

    let mut safety = rig.open();
    let change = safety
        .pending_anchor_decision(&binding)
        .expect("the parked decision must survive a restart");
    assert_eq!(change.serial, 2);
    assert_eq!(change.last_accepted_serial, 1);

    // A later bill cannot slip past the park.
    let bill3 = hash64(0x63);
    let error = safety
        .accept_anchored_bill(
            &binding,
            &rig.hub_identity,
            &bill3,
            3,
            &[w1.sign(w1.receipt(&rig.hub_identity, &binding, 3, &bill3, 9))],
            0,
        )
        .expect_err("a parked channel must not advance");
    assert!(
        error.to_string().contains(ANCHOR_WITNESS_DECISION_REQUIRED),
        "unexpected error: {error}"
    );
    assert_eq!(safety.anchor_memory(&binding).unwrap().accepted_serial, 1);
}

#[test]
fn accepting_adopts_the_new_set_and_retires_the_dropped_one_without_erasing_it() {
    let rig = Rig::new();
    let w1 = Witness::new("anchor-w1", "witness-one", 0x41);
    let w2 = Witness::new("anchor-w2", "witness-two", 0x42);
    let binding = hash64(0x51);
    let mut safety = rig.open();

    let bill1 = hash64(0x61);
    safety
        .accept_anchored_bill(
            &binding,
            &rig.hub_identity,
            &bill1,
            1,
            &[w1.sign(w1.receipt(&rig.hub_identity, &binding, 1, &bill1, 7))],
            0,
        )
        .unwrap();
    let bill2 = hash64(0x62);
    safety
        .accept_anchored_bill(
            &binding,
            &rig.hub_identity,
            &bill2,
            2,
            &[w2.sign(w2.receipt(&rig.hub_identity, &binding, 2, &bill2, 3))],
            0,
        )
        .unwrap_err();

    safety
        .resolve_anchor_witness_change(&binding, AnchorWitnessDecision::AcceptNewWitnessSet)
        .unwrap();
    drop(safety);

    let safety = rig.open();
    let memory = safety.anchor_memory(&binding).unwrap();
    assert!(safety.pending_anchor_decision(&binding).is_none());
    assert_eq!(memory.accepted_serial, 2);
    assert_eq!(memory.accepted_bill_commitment, bill2);
    assert_eq!(memory.witnesses.len(), 1);
    assert_eq!(
        memory.witnesses.values().next().unwrap().signer_address,
        w2.account.address()
    );
    assert_eq!(memory.retired.len(), 1, "the drop must not be erased");
    assert_eq!(
        memory.retired.values().next().unwrap().signer_address,
        w1.account.address()
    );
    let decision = memory.last_decision.unwrap();
    assert_eq!(
        decision.decision,
        AnchorWitnessDecision::AcceptNewWitnessSet
    );
    assert_eq!(decision.change.serial, 2);
}

#[test]
fn closing_latches_the_channel_on_its_last_accepted_head() {
    let rig = Rig::new();
    let w1 = Witness::new("anchor-w1", "witness-one", 0x41);
    let w2 = Witness::new("anchor-w2", "witness-two", 0x42);
    let binding = hash64(0x51);
    let mut safety = rig.open();

    let bill1 = hash64(0x61);
    safety
        .accept_anchored_bill(
            &binding,
            &rig.hub_identity,
            &bill1,
            1,
            &[w1.sign(w1.receipt(&rig.hub_identity, &binding, 1, &bill1, 7))],
            0,
        )
        .unwrap();
    let bill2 = hash64(0x62);
    safety
        .accept_anchored_bill(
            &binding,
            &rig.hub_identity,
            &bill2,
            2,
            &[w2.sign(w2.receipt(&rig.hub_identity, &binding, 2, &bill2, 3))],
            0,
        )
        .unwrap_err();

    safety
        .resolve_anchor_witness_change(&binding, AnchorWitnessDecision::CloseChannel)
        .unwrap();
    let memory = safety.anchor_memory(&binding).unwrap();
    assert!(memory.closing);
    assert_eq!(
        memory.accepted_serial, 1,
        "close runs against the last accepted head, whose receipt set is intact"
    );
    assert_eq!(memory.accepted_bill_commitment, bill1);
    assert_eq!(
        memory.last_decision.unwrap().decision,
        AnchorWitnessDecision::CloseChannel
    );

    // A closing channel does not quietly resume.
    let bill3 = hash64(0x63);
    let error = safety
        .accept_anchored_bill(
            &binding,
            &rig.hub_identity,
            &bill3,
            3,
            &[w2.sign(w2.receipt(&rig.hub_identity, &binding, 3, &bill3, 4))],
            0,
        )
        .expect_err("a closing channel must not advance");
    assert!(
        error.to_string().contains("closing"),
        "unexpected error: {error}"
    );
}

/// Two channels under the same Hub keep independent memories, keyed by the
/// binding commitment rather than the channel id.
#[test]
fn each_binding_keeps_its_own_ratchet() {
    let rig = Rig::new();
    let w1 = Witness::new("anchor-w1", "witness-one", 0x41);
    let w2 = Witness::new("anchor-w2", "witness-two", 0x42);
    let a = hash64(0x51);
    let b = hash64(0x52);
    let mut safety = rig.open();

    let bill = hash64(0x61);
    safety
        .accept_anchored_bill(
            &a,
            &rig.hub_identity,
            &bill,
            1,
            &[w1.sign(w1.receipt(&rig.hub_identity, &a, 1, &bill, 7))],
            0,
        )
        .unwrap();
    // A brand-new binding has nothing to compare against and is silent, even
    // with a completely different witness. That residual is stated, not
    // papered over.
    safety
        .accept_anchored_bill(
            &b,
            &rig.hub_identity,
            &bill,
            1,
            &[w2.sign(w2.receipt(&rig.hub_identity, &b, 1, &bill, 2))],
            0,
        )
        .unwrap();

    let expected: BTreeMap<&str, &str> = [(a.as_str(), "witness-one"), (b.as_str(), "witness-two")]
        .into_iter()
        .collect();
    for (binding, label) in expected {
        let memory = safety.anchor_memory(binding).unwrap();
        assert_eq!(memory.witnesses.values().next().unwrap().witness_id, label);
    }
}

/// Retiring a witness must not un-ratchet it.
///
/// Accepting a set change moves the dropped records to `retired` rather than
/// erasing them, and the reason given is that the event has to survive in the
/// record. That is only half of what `retired` is for. If the counter ratchet
/// reads `witnesses` alone, a retired witness is, to the ratchet, a witness the
/// wallet has never seen - so the amnesia attack simply gains one extra step:
/// swap the witness once, get the prompt accepted (which is the answer a user
/// gives when the swap looks legitimate), then bring the original store back
/// rebuilt from nothing, its counter at zero, and it is treated as new.
///
/// The record is right there on disk. It has to be read.
#[test]
fn a_retired_witness_that_comes_back_with_a_reset_counter_is_still_refused() {
    let rig = Rig::new();
    let w1 = Witness::new("anchor-w1", "witness-one", 0x41);
    let w2 = Witness::new("anchor-w2", "witness-two", 0x42);
    let binding = hash64(0x51);
    let mut safety = rig.open();

    // The wallet watches w1 reach counter 40 on this channel.
    let bill1 = hash64(0x61);
    safety
        .accept_anchored_bill(
            &binding,
            &rig.hub_identity,
            &bill1,
            1,
            &[w1.sign(w1.receipt(&rig.hub_identity, &binding, 1, &bill1, 40))],
            0,
        )
        .unwrap();

    // The Hub moves to w2. The human accepts, which is the whole point of the
    // prompt existing: this is what a legitimate rotation looks like.
    let bill2 = hash64(0x62);
    safety
        .accept_anchored_bill(
            &binding,
            &rig.hub_identity,
            &bill2,
            2,
            &[w2.sign(w2.receipt(&rig.hub_identity, &binding, 2, &bill2, 3))],
            0,
        )
        .unwrap_err();
    safety
        .resolve_anchor_witness_change(&binding, AnchorWitnessDecision::AcceptNewWitnessSet)
        .unwrap();
    let memory = safety.anchor_memory(&binding).unwrap();
    assert_eq!(memory.retired.len(), 1);
    assert_eq!(memory.witnesses.len(), 1);
    assert_eq!(
        memory.retired.values().next().unwrap().signer_address,
        w1.account.address()
    );

    // w1 comes back with the *same* key and the *same* store instance - so the
    // overlap key is identical and it is not a new witness - but its counter is
    // back at 2. That is a store rebuilt from nothing.
    let bill3 = hash64(0x63);
    let error = safety
        .accept_anchored_bill(
            &binding,
            &rig.hub_identity,
            &bill3,
            3,
            &[
                w2.sign(w2.receipt(&rig.hub_identity, &binding, 3, &bill3, 4)),
                w1.sign(w1.receipt(&rig.hub_identity, &binding, 3, &bill3, 2)),
            ],
            0,
        )
        .expect_err("a retired witness is still a witness this wallet has watched")
        .to_string();
    assert!(
        error.contains("rollback_anchor_witness_behind_hub"),
        "unexpected error: {error}"
    );

    // And the refusal is hard: nothing was parked and the head did not move.
    let memory = safety.anchor_memory(&binding).unwrap();
    assert_eq!(memory.accepted_serial, 2);
    assert_eq!(memory.accepted_bill_commitment, bill2);
    assert!(memory.pending_decision.is_none());

    // The same witness returning *ahead* of where it was retired is fine. The
    // rule is a ratchet, not a ban.
    safety
        .accept_anchored_bill(
            &binding,
            &rig.hub_identity,
            &bill3,
            3,
            &[
                w2.sign(w2.receipt(&rig.hub_identity, &binding, 3, &bill3, 4)),
                w1.sign(w1.receipt(&rig.hub_identity, &binding, 3, &bill3, 41)),
            ],
            0,
        )
        .expect("a witness that really did move forward is not the amnesia case");
    let memory = safety.anchor_memory(&binding).unwrap();
    assert_eq!(memory.accepted_serial, 3);
}

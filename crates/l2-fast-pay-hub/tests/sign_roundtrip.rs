use basis::method::verify_signature;
use field::Address;
use l2_fast_pay_hub::channel_id::derive_channel_id;
use l2_fast_pay_hub::node::{ChannelInfo, ChannelPartyBalance, ChannelSide};
use l2_fast_pay_hub::wire::{
    ChannelPayCompleteDocuments, ChannelWireInput, build_same_channel_bill,
};
use sys::Account;

fn sample_channel(id: &str, left: &str, right: &str, left_mei: &str) -> ChannelInfo {
    ChannelInfo {
        ret: 0,
        id: id.to_owned(),
        status: 0,
        reuse_version: 1,
        left: ChannelPartyBalance {
            address: left.into(),
            hacash: left_mei.into(),
            satoshi: 42_000,
        },
        right: ChannelPartyBalance {
            address: right.into(),
            hacash: "1.001".into(),
            satoshi: 0,
        },
        challenging: None,
    }
}

#[test]
fn hub_and_payer_sign_same_channel_bill() {
    let alice = Account::create_by("alice-l2-sign-test").unwrap();
    let hub = Account::create_by("hub-l2-sign-test").unwrap();
    let channel_id = derive_channel_id(&alice.readable(), &hub.readable(), 1);

    let mut doc = build_same_channel_bill(
        &ChannelWireInput {
            channel: sample_channel(&channel_id, alice.readable(), hub.readable(), "8.499"),
            channel_id_hex: channel_id,
            left_balance_mei: 7.498,
            right_balance_mei: 2.002,
            left_satoshi: 42_000,
            right_satoshi: 0,
            bill_auto_number: 1,
        },
        ChannelSide::Left,
        1.001,
        1_700_000_000,
    )
    .unwrap();

    doc.chain_payment
        .fill_sign_by_account(&hub)
        .expect("hub sign");
    doc.chain_payment
        .fill_sign_by_account(&alice)
        .expect("payer sign");

    assert!(doc.chain_payment.all_slots_filled());

    let hash = doc.chain_payment.sign_stuff_hash();
    let alice_addr = Address::from(*alice.address());
    let hub_addr = Address::from(*hub.address());
    assert!(
        verify_signature(&hash, &alice_addr, &doc.chain_payment.must_signs[0])
            || verify_signature(&hash, &alice_addr, &doc.chain_payment.must_signs[1])
    );
    assert!(
        verify_signature(&hash, &hub_addr, &doc.chain_payment.must_signs[0])
            || verify_signature(&hash, &hub_addr, &doc.chain_payment.must_signs[1])
    );

    let hex = doc.to_bill_hex();
    let parsed = ChannelPayCompleteDocuments::from_bill_hex(&hex).unwrap();
    assert!(parsed.chain_payment.all_slots_filled());
    assert_eq!(parsed.prove_bodies[0].left_satoshi.not_empty.as_ref()[0], 1);
}

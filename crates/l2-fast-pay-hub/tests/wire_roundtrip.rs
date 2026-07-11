use l2_fast_pay_hub::channel_id::derive_channel_id;
use l2_fast_pay_hub::node::{ChannelInfo, ChannelPartyBalance};
use l2_fast_pay_hub::wire::{
    build_cross_channel_bill, ChannelPayCompleteDocuments, ChannelWireInput,
};

fn sample_channel(id: &str, left: &str, right: &str, left_mei: &str) -> ChannelInfo {
    ChannelInfo {
        ret: 0,
        id: id.to_owned(),
        status: 0,
        reuse_version: 1,
        left: ChannelPartyBalance {
            address: left.into(),
            hacash: left_mei.into(),
            satoshi: 0,
        },
        right: ChannelPartyBalance {
            address: right.into(),
            hacash: "0".into(),
            satoshi: 0,
        },
        challenging: None,
    }
}

#[test]
fn channel_pay_complete_documents_roundtrip() {
    let alice_id = derive_channel_id("1Alice", "1Hub", 1);
    let bob_id = derive_channel_id("1Bob", "1Hub", 1);

    let payer = ChannelWireInput {
        channel: sample_channel(&alice_id, "1Alice", "1Hub", "8.499"),
        channel_id_hex: alice_id,
        left_balance_mei: 8.499,
        right_balance_mei: 1.001,
        left_satoshi: 0,
        right_satoshi: 0,
        bill_auto_number: 1,
    };
    let payee = ChannelWireInput {
        channel: sample_channel(&bob_id, "1Bob", "1Hub", "3.5"),
        channel_id_hex: bob_id,
        left_balance_mei: 3.5,
        right_balance_mei: 0.0,
        left_satoshi: 0,
        right_satoshi: 0,
        bill_auto_number: 1,
    };

    let doc = build_cross_channel_bill(&payer, 1.501, &payee, 1.5, 1_700_000_000).unwrap();
    let hex = doc.to_bill_hex();
    assert!(hex.len() > 64);

    let parsed = ChannelPayCompleteDocuments::from_bill_hex(&hex).unwrap();
    assert_eq!(parsed.prove_bodies.len(), 2);
    assert_eq!(parsed.chain_payment.prove_hash_checkers.len(), 2);
    assert_eq!(parsed.chain_payment.must_sign_addresses.len(), 3);
}
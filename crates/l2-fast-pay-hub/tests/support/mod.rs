use basis::interface::Transaction;
use field::{AddrHac, Address, Amount, ChannelId, Field, Serialize as _, Uint4};
use l2_fast_pay_hub::channel_id::derive_channel_id;
use l2_fast_pay_hub::l1_channel::{
    L1_CHANNEL_OPEN_SCHEMA, L1ChannelOpenRequest, request_commitment, transaction_commitment,
};
use mint::action::ChannelOpen;
use protocol::action::{ChainAllow, ChainIDList};
use protocol::transaction::TransactionType2;
use sys::Account;

pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

pub const PILOT_CHAIN_ID: u32 = 7;
pub const PILOT_NETWORK_KIND: &str = "local_pilot_v1";
pub const PILOT_PROFILE_ID: &str = "hpay-local-pilot-chain-v1";
pub const PILOT_BLOCK_ONE: &str =
    "000087f67e55660eaefed72e0b9499147556a33a34f18fa48900f4a2fa30cd29";
pub const PILOT_INSTANCE: &str = "9ebd8657a72faed35ed4d6e309fab2ef259f054e4820684fab6c6b848e4438f3";

pub fn channel_open_request(user: &Account, hub: &Account) -> L1ChannelOpenRequest {
    channel_open_request_for_reuse(user, hub, 1)
}

pub fn channel_open_request_for_reuse(
    user: &Account,
    hub: &Account,
    reuse_version: u64,
) -> L1ChannelOpenRequest {
    assert!(reuse_version > 0);
    l2_fast_pay_hub::protocol_registry::ensure_hacash_protocol_setup();
    let channel_id = derive_channel_id(user.readable(), hub.readable(), 1);
    let mut action = ChannelOpen::new();
    action.channel_id =
        ChannelId::from(<[u8; 16]>::try_from(hex::decode(&channel_id).unwrap()).unwrap());
    action.left_bill = AddrHac {
        address: Address::from_readable(user.readable()).unwrap(),
        amount: Amount::from("0.01").unwrap(),
    };
    action.right_bill = AddrHac {
        address: Address::from_readable(hub.readable()).unwrap(),
        amount: Amount::from("0").unwrap(),
    };
    let now = now_unix();
    let transaction_timestamp = now.saturating_add(reuse_version.saturating_sub(1));
    let mut tx = TransactionType2::new_by(
        Address::from_readable(user.readable()).unwrap(),
        Amount::from("0.0001").unwrap(),
        transaction_timestamp,
    );
    let mut guard = ChainAllow::new();
    guard.chains = ChainIDList::from_list(vec![Uint4::from(PILOT_CHAIN_ID)]).unwrap();
    tx.push_action(Box::new(guard)).unwrap();
    tx.push_action(Box::new(action)).unwrap();
    tx.fill_sign(user).unwrap();
    let partial_transaction_hex = hex::encode(tx.serialize());
    let mut request = L1ChannelOpenRequest {
        schema: L1_CHANNEL_OPEN_SCHEMA.into(),
        network: PILOT_NETWORK_KIND.into(),
        chain_id: PILOT_CHAIN_ID,
        mainnet: false,
        block_1_hash: PILOT_BLOCK_ONE.into(),
        node_profile_id: PILOT_PROFILE_ID.into(),
        network_instance_id: PILOT_INSTANCE.into(),
        transaction_format_version: 2,
        operation_id: uuid::Uuid::new_v4().to_string(),
        idempotency_key: uuid::Uuid::new_v4().to_string(),
        created_unix: now,
        expires_unix: now + 60,
        hub_address: hub.readable().into(),
        channel_id,
        expected_reuse_version: reuse_version,
        partial_transaction_commitment: transaction_commitment(&partial_transaction_hex).unwrap(),
        partial_transaction_hex,
        authorization_public_key_hex: hex::encode(user.public_key().serialize_compressed()),
        authorization_signature_hex: String::new(),
    };
    let commitment: [u8; 32] = hex::decode(request_commitment(&request).unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    request.authorization_signature_hex = hex::encode(user.do_sign(&commitment));
    request
}

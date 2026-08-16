//! Strict, transaction-bound L1 channel co-signing primitives.
//!
//! This module never broadcasts. State/recovery policy lives in `HubState`; this
//! layer only accepts an exact, already user-signed Hacash transaction and adds
//! the configured Hub signature after independently decoding every field.

use basis::interface::TransactionRead;
use field::Address;
use mint::action::ChannelOpen;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sys::Account;

use crate::error::{HubError, HubResult};

pub const L1_CHANNEL_OPEN_SCHEMA: &str = "hpay-l1-channel-open/3";
pub const HACASH_MAINNET_CHAIN_ID: u32 = 0;
pub const MAX_CHANNEL_TRANSACTION_BYTES: usize = 64 * 1024;
pub const MAX_CHANNEL_NETWORK_FEE_ZHU: u64 = 1_000_000;
const REQUEST_MAX_LIFETIME_SECONDS: u64 = 300;
const TRANSACTION_MAX_AGE_SECONDS: u64 = 600;
const CLOCK_FUTURE_SKEW_SECONDS: u64 = 30;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct L1ChannelNetworkBinding {
    pub network_kind: String,
    pub chain_id: u32,
    pub mainnet: bool,
    pub block_1_hash: String,
    pub node_profile_id: String,
    pub network_instance_id: String,
    pub transaction_format_version: u64,
}

impl L1ChannelNetworkBinding {
    pub fn from_node_identity(
        network_kind: &str,
        mainnet: bool,
        chain_id: u32,
        block_1_hash: &str,
        node_profile_id: &str,
        network_instance_id: Option<&str>,
        transaction_format_version: u64,
    ) -> HubResult<Self> {
        let binding = Self {
            network_kind: network_kind.to_owned(),
            chain_id,
            mainnet,
            block_1_hash: block_1_hash.to_owned(),
            node_profile_id: node_profile_id.to_owned(),
            network_instance_id: network_instance_id.unwrap_or_default().to_owned(),
            transaction_format_version,
        };
        binding.validate()?;
        Ok(binding)
    }

    pub fn validate(&self) -> HubResult<()> {
        if self.mainnet != (self.chain_id == HACASH_MAINNET_CHAIN_ID) {
            return Err(HubError::Node(
                "channel mainnet flag and chain id disagree".into(),
            ));
        }
        if self.network_kind.is_empty()
            || self.node_profile_id.is_empty()
            || self.transaction_format_version != 2
        {
            return Err(HubError::Node(
                "channel network identity is incomplete or unsupported".into(),
            ));
        }
        if !is_lower_hex(&self.block_1_hash, 32) {
            return Err(HubError::Node(
                "channel block 1 hash must be exactly 32-byte lowercase hex".into(),
            ));
        }
        if self.network_instance_id.len() != 64
            || !self
                .network_instance_id
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(HubError::Node(
                "channel network instance id must be exactly 32-byte lowercase hex".into(),
            ));
        }
        if self.network_instance_id
            != canonical_network_instance_id(
                &self.network_kind,
                self.chain_id,
                self.mainnet,
                &self.block_1_hash,
                &self.node_profile_id,
                self.transaction_format_version,
            )
        {
            return Err(HubError::Node(
                "channel network instance id does not match its immutable identity".into(),
            ));
        }
        Ok(())
    }

    fn matches_request(&self, request: &L1ChannelOpenRequest) -> bool {
        request.network == self.network_kind
            && request.chain_id == self.chain_id
            && request.mainnet == self.mainnet
            && request.block_1_hash == self.block_1_hash
            && request.node_profile_id == self.node_profile_id
            && request.network_instance_id == self.network_instance_id
            && request.transaction_format_version == self.transaction_format_version
    }
}

fn is_lower_hex(value: &str, bytes: usize) -> bool {
    value.len() == bytes * 2
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub fn canonical_network_instance_id(
    network_kind: &str,
    chain_id: u32,
    mainnet: bool,
    block_1_hash: &str,
    node_profile_id: &str,
    transaction_format_version: u64,
) -> String {
    fn push_field(bytes: &mut Vec<u8>, value: &str) {
        bytes.extend_from_slice(&(value.len() as u64).to_be_bytes());
        bytes.extend_from_slice(value.as_bytes());
    }
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"HPAY/NETWORK-INSTANCE/V1");
    push_field(&mut bytes, network_kind);
    bytes.extend_from_slice(&chain_id.to_be_bytes());
    bytes.push(u8::from(mainnet));
    push_field(&mut bytes, block_1_hash);
    push_field(&mut bytes, node_profile_id);
    bytes.extend_from_slice(&transaction_format_version.to_be_bytes());
    hex::encode(Sha256::digest(bytes))
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct L1ChannelOpenRequest {
    pub schema: String,
    pub network: String,
    pub chain_id: u32,
    pub mainnet: bool,
    pub block_1_hash: String,
    pub node_profile_id: String,
    pub network_instance_id: String,
    pub transaction_format_version: u64,
    pub operation_id: String,
    pub idempotency_key: String,
    pub created_unix: u64,
    pub expires_unix: u64,
    pub hub_address: String,
    pub channel_id: String,
    pub expected_reuse_version: u64,
    pub partial_transaction_hex: String,
    pub partial_transaction_commitment: String,
    pub authorization_public_key_hex: String,
    pub authorization_signature_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct L1ChannelOpenResponse {
    pub schema: String,
    pub operation_id: String,
    pub channel_id: String,
    pub status: String,
    pub signed_transaction_hex: String,
    pub signed_transaction_commitment: String,
    pub transaction_hash: String,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct L1ChannelOpenStatusResponse {
    pub schema: String,
    pub operation_id: String,
    pub channel_id: String,
    pub status: String,
    pub transaction_hash: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedChannelOpenIntent {
    pub channel_id: String,
    pub expected_reuse_version: u64,
    pub user_address: String,
    pub user_deposit_zhu: u64,
    pub network_fee_zhu: u64,
    pub transaction_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedChannelOpen {
    pub channel_id: String,
    pub user_address: String,
    pub user_deposit_zhu: u64,
    pub network_fee_zhu: u64,
    pub transaction_hash: String,
    pub signed_transaction_hex: String,
    pub signed_transaction_commitment: String,
}

pub fn transaction_commitment(body_hex: &str) -> HubResult<String> {
    let raw = decode_hex(body_hex)?;
    Ok(hex::encode(Sha256::digest(raw)))
}

pub fn request_commitment(request: &L1ChannelOpenRequest) -> HubResult<String> {
    let mut digest = Sha256::new();
    digest.update(b"HPAY/L1/CHANNEL-OPEN/REQUEST/V3");
    for field in [
        request.network.as_bytes(),
        &request.chain_id.to_be_bytes(),
        &[u8::from(request.mainnet)],
        request.block_1_hash.as_bytes(),
        request.node_profile_id.as_bytes(),
        request.network_instance_id.as_bytes(),
        &request.transaction_format_version.to_be_bytes(),
        request.operation_id.as_bytes(),
        request.idempotency_key.as_bytes(),
        &request.created_unix.to_be_bytes(),
        &request.expires_unix.to_be_bytes(),
        request.hub_address.as_bytes(),
        request.channel_id.as_bytes(),
        &request.expected_reuse_version.to_be_bytes(),
        request.partial_transaction_commitment.as_bytes(),
    ] {
        digest.update((field.len() as u64).to_be_bytes());
        digest.update(field);
    }
    Ok(hex::encode(digest.finalize()))
}

pub fn validate_and_cosign_channel_open(
    request: &L1ChannelOpenRequest,
    hub_signer: &Account,
    expected_network: &L1ChannelNetworkBinding,
    max_channel_funding_hac_zhu: u64,
    now_unix: u64,
) -> HubResult<ValidatedChannelOpen> {
    let (mut tx, intent) = parse_and_validate_channel_open(
        request,
        hub_signer.readable(),
        expected_network,
        max_channel_funding_hac_zhu,
        now_unix,
    )?;
    let unsigned_hash = tx.hash();
    tx.fill_sign(hub_signer)
        .map_err(|error| HubError::Payment(format!("Hub channel co-sign failed: {error}")))?;
    if tx.hash() != unsigned_hash || tx.signs().len() != 2 {
        return Err(HubError::State(
            "Hub channel co-sign changed the transaction intent".into(),
        ));
    }
    tx.verify_signature().map_err(|error| {
        HubError::State(format!("Hub channel co-sign verification failed: {error}"))
    })?;
    let signed = tx.serialize();
    Ok(ValidatedChannelOpen {
        channel_id: intent.channel_id,
        user_address: intent.user_address,
        user_deposit_zhu: intent.user_deposit_zhu,
        network_fee_zhu: intent.network_fee_zhu,
        transaction_hash: intent.transaction_hash,
        signed_transaction_hex: hex::encode(&signed),
        signed_transaction_commitment: hex::encode(Sha256::digest(&signed)),
    })
}

pub fn validate_channel_open(
    request: &L1ChannelOpenRequest,
    expected_hub_address: &str,
    expected_network: &L1ChannelNetworkBinding,
    max_channel_funding_hac_zhu: u64,
    now_unix: u64,
) -> HubResult<ValidatedChannelOpenIntent> {
    let (_, intent) = parse_and_validate_channel_open(
        request,
        expected_hub_address,
        expected_network,
        max_channel_funding_hac_zhu,
        now_unix,
    )?;
    Ok(intent)
}

fn parse_and_validate_channel_open(
    request: &L1ChannelOpenRequest,
    expected_hub_address: &str,
    expected_network: &L1ChannelNetworkBinding,
    max_channel_funding_hac_zhu: u64,
    now_unix: u64,
) -> HubResult<(
    Box<dyn basis::interface::Transaction>,
    ValidatedChannelOpenIntent,
)> {
    validate_request_envelope(request, expected_hub_address, expected_network, now_unix)?;
    let raw = decode_hex(&request.partial_transaction_hex)?;
    if raw.len() > MAX_CHANNEL_TRANSACTION_BYTES {
        return Err(HubError::Payment(
            "channel-open transaction exceeds the Hub size limit".into(),
        ));
    }
    let actual_commitment = hex::encode(Sha256::digest(&raw));
    if actual_commitment != request.partial_transaction_commitment {
        return Err(HubError::Payment(
            "partial channel-open transaction commitment mismatch".into(),
        ));
    }

    crate::protocol_registry::ensure_hacash_protocol_setup();
    let (tx, consumed) = protocol::transaction::transaction_create(&raw)
        .map_err(|error| HubError::Payment(format!("invalid channel-open transaction: {error}")))?;
    if consumed != raw.len() {
        return Err(HubError::Payment(
            "channel-open transaction contains trailing bytes".into(),
        ));
    }
    protocol::action::precheck_tx_actions(tx.ty(), tx.actions()).map_err(|error| {
        HubError::Payment(format!("channel-open action topology rejected: {error}"))
    })?;
    if tx.ty() != 2 {
        return Err(HubError::Payment(
            "channel-open must use a Type 2 transaction".into(),
        ));
    }
    if tx.actions().len() != 2 || tx.actions()[0].kind() != 0x0411 || tx.actions()[1].kind() != 2 {
        return Err(HubError::Payment(
            "channel-open must contain exact ChainAllow then action 2".into(),
        ));
    }
    let guard = protocol::action::ChainAllow::downcast(&tx.actions()[0])
        .ok_or_else(|| HubError::Payment("ChainAllow action codec mismatch".into()))?;
    let chains = guard.chains.as_list();
    if chains.len() != 1 || chains[0].uint() != expected_network.chain_id {
        return Err(HubError::Payment(format!(
            "ChainAllow must bind exactly chain {}",
            expected_network.chain_id
        )));
    }
    let action = ChannelOpen::downcast(&tx.actions()[1])
        .ok_or_else(|| HubError::Payment("channel-open action codec mismatch".into()))?;
    let user = action.left_bill.address;
    let hub = action.right_bill.address;
    let expected_hub = Address::from_readable(&request.hub_address)
        .map_err(|error| HubError::Payment(format!("invalid Hub address: {error}")))?;
    if tx.main() != user {
        return Err(HubError::Payment(
            "channel-open fee payer must be the user on the left side".into(),
        ));
    }
    if hub != expected_hub {
        return Err(HubError::Payment(
            "channel-open right side does not match this Hub signer".into(),
        ));
    }
    if !action.right_bill.amount.is_zero() {
        return Err(HubError::Payment(
            "mainnet pilot requires an exact zero Hub deposit".into(),
        ));
    }
    if action.left_bill.amount.is_zero() || action.left_bill.amount.is_negative() {
        return Err(HubError::Payment(
            "channel-open user deposit must be positive".into(),
        ));
    }
    let user_deposit_zhu = action
        .left_bill
        .amount
        .to_zhu_u64()
        .map_err(|error| HubError::Payment(format!("invalid user deposit: {error}")))?;
    if user_deposit_zhu == 0 || user_deposit_zhu > max_channel_funding_hac_zhu {
        return Err(HubError::Payment(format!(
            "channel funding exceeds the Hub cap: requested {user_deposit_zhu} zhu, cap {max_channel_funding_hac_zhu} zhu"
        )));
    }
    let fee_zhu = tx
        .fee()
        .to_zhu_u64()
        .map_err(|error| HubError::Payment(format!("invalid channel network fee: {error}")))?;
    if fee_zhu == 0 || fee_zhu > MAX_CHANNEL_NETWORK_FEE_ZHU {
        return Err(HubError::Payment(format!(
            "channel network fee must be positive and at most {MAX_CHANNEL_NETWORK_FEE_ZHU} zhu"
        )));
    }
    let channel_id = hex::encode(action.channel_id.as_bytes());
    if channel_id != request.channel_id.to_ascii_lowercase()
        || channel_id != derive_channel_id(&user.to_readable(), &hub.to_readable(), 1)
    {
        return Err(HubError::Payment(
            "channel-open channel ID is not the deterministic user/Hub ID".into(),
        ));
    }
    let tx_timestamp = tx.timestamp().uint();
    if tx_timestamp > now_unix.saturating_add(CLOCK_FUTURE_SKEW_SECONDS)
        || now_unix.saturating_sub(tx_timestamp) > TRANSACTION_MAX_AGE_SECONDS
    {
        return Err(HubError::Payment(
            "channel-open transaction timestamp is outside the signing window".into(),
        ));
    }

    let mut required = tx
        .req_sign()
        .map_err(|error| HubError::Payment(format!("channel signer analysis failed: {error}")))?
        .into_iter()
        .collect::<Vec<_>>();
    required.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
    let mut expected = vec![user, hub];
    expected.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
    if required != expected {
        return Err(HubError::Payment(
            "channel-open signer set must be exactly user and Hub".into(),
        ));
    }
    require_exact_user_partial_signature(tx.as_read(), &user, &hub)?;
    verify_request_authorization(request, &user)?;
    let transaction_hash = hex::encode(tx.hash().as_bytes());
    Ok((
        tx,
        ValidatedChannelOpenIntent {
            channel_id,
            expected_reuse_version: request.expected_reuse_version,
            user_address: user.to_readable(),
            user_deposit_zhu,
            network_fee_zhu: fee_zhu,
            transaction_hash,
        },
    ))
}
fn verify_request_authorization(
    request: &L1ChannelOpenRequest,
    expected_user: &Address,
) -> HubResult<()> {
    let public_key = hex::decode(&request.authorization_public_key_hex).map_err(|_| {
        HubError::Payment("channel-open authorization public key is not hex".into())
    })?;
    let public_key: [u8; 33] = public_key.try_into().map_err(|_| {
        HubError::Payment("channel-open authorization public key must be 33 bytes".into())
    })?;
    let signature = hex::decode(&request.authorization_signature_hex)
        .map_err(|_| HubError::Payment("channel-open authorization signature is not hex".into()))?;
    let signature: [u8; 64] = signature.try_into().map_err(|_| {
        HubError::Payment("channel-open authorization signature must be 64 bytes".into())
    })?;
    let signer = Address::from(Account::get_address_by_public_key(public_key));
    if signer != *expected_user {
        return Err(HubError::Payment(
            "channel-open request authorization does not belong to the user".into(),
        ));
    }
    let commitment = hex::decode(request_commitment(request)?)
        .map_err(|_| HubError::State("channel-open request commitment is invalid".into()))?;
    let commitment: [u8; 32] = commitment
        .try_into()
        .map_err(|_| HubError::State("channel-open request commitment must be 32 bytes".into()))?;
    if !Account::verify_signature(&commitment, &public_key, &signature) {
        return Err(HubError::Payment(
            "channel-open request authorization signature is invalid".into(),
        ));
    }
    Ok(())
}
fn require_exact_user_partial_signature(
    tx: &dyn TransactionRead,
    user: &Address,
    hub: &Address,
) -> HubResult<()> {
    if tx.signs().len() != 1 {
        return Err(HubError::Payment(
            "partial channel-open transaction must contain exactly one user signature".into(),
        ));
    }
    let signature = &tx.signs()[0];
    let signer = Address::from(Account::get_address_by_public_key(*signature.publickey));
    if signer != *user || signer == *hub {
        return Err(HubError::Payment(
            "partial channel-open transaction is not signed only by the user".into(),
        ));
    }
    let verified = protocol::transaction::verify_target_signature(user, tx)
        .map_err(|error| HubError::Payment(format!("user channel signature invalid: {error}")))?;
    if !verified {
        return Err(HubError::Payment(
            "user channel signature was not verified".into(),
        ));
    }
    Ok(())
}

fn validate_request_envelope(
    request: &L1ChannelOpenRequest,
    expected_hub: &str,
    expected_network: &L1ChannelNetworkBinding,
    now_unix: u64,
) -> HubResult<()> {
    if request.expected_reuse_version != 1 {
        return Err(HubError::Payment(
            "Fast Pay pilot requires a fresh one-use channel with reuse version 1".into(),
        ));
    }
    expected_network.validate()?;
    if request.schema != L1_CHANNEL_OPEN_SCHEMA || !expected_network.matches_request(request) {
        return Err(HubError::Payment(
            "unsupported L1 channel-open schema or live network binding mismatch".into(),
        ));
    }
    let operation = uuid::Uuid::parse_str(request.operation_id.trim())
        .map_err(|_| HubError::Payment("operation_id must be a UUID".into()))?;
    if operation.is_nil() {
        return Err(HubError::Payment("operation_id must not be nil".into()));
    }
    let key = request.idempotency_key.trim();
    if !(16..=128).contains(&key.len())
        || !key
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        return Err(HubError::Payment(
            "idempotency_key must be 16-128 safe ASCII characters".into(),
        ));
    }
    if request.hub_address != expected_hub {
        return Err(HubError::Payment(
            "channel-open request targets a different Hub".into(),
        ));
    }
    if request.created_unix > now_unix.saturating_add(CLOCK_FUTURE_SKEW_SECONDS)
        || request.expires_unix <= now_unix
        || request.expires_unix <= request.created_unix
        || request.expires_unix.saturating_sub(request.created_unix) > REQUEST_MAX_LIFETIME_SECONDS
    {
        return Err(HubError::Payment(
            "channel-open request is expired or outside the allowed signing window".into(),
        ));
    }
    if request.channel_id.len() != 32
        || !request
            .channel_id
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
        || request.partial_transaction_commitment.len() != 64
        || !request
            .partial_transaction_commitment
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(HubError::Payment(
            "channel ID or transaction commitment is malformed".into(),
        ));
    }
    Ok(())
}

fn derive_channel_id(left: &str, right: &str, reuse_version: u64) -> String {
    let seed = format!("{left}|{right}|{reuse_version}");
    let hash = Sha256::digest(seed.as_bytes());
    hex::encode(&hash[..16])
}

fn decode_hex(body_hex: &str) -> HubResult<Vec<u8>> {
    if body_hex.len() > MAX_CHANNEL_TRANSACTION_BYTES.saturating_mul(2) {
        return Err(HubError::Payment(
            "channel transaction exceeds the Hub size limit".into(),
        ));
    }
    let raw = hex::decode(body_hex)
        .map_err(|error| HubError::Payment(format!("channel transaction hex: {error}")))?;
    if raw.is_empty() {
        return Err(HubError::Payment(
            "channel transaction body is empty".into(),
        ));
    }
    Ok(raw)
}

#[cfg(test)]
mod tests {
    use basis::interface::Transaction;
    use field::{AddrHac, Amount, ChannelId, Field, Serialize as _, Uint4};
    use mint::action::ChannelOpen;
    use protocol::action::{ChainAllow, ChainIDList};
    use protocol::transaction::TransactionType2;

    use super::*;

    fn account(byte: u8) -> Account {
        Account::create_by(&hex::encode([byte; 32])).unwrap()
    }

    fn mainnet_binding() -> L1ChannelNetworkBinding {
        L1ChannelNetworkBinding::from_node_identity(
            "mainnet",
            true,
            0,
            crate::node::HACASH_MAINNET_BLOCK_ONE_HASH,
            "hacash-mainnet",
            Some(&canonical_network_instance_id(
                "mainnet",
                0,
                true,
                crate::node::HACASH_MAINNET_BLOCK_ONE_HASH,
                "hacash-mainnet",
                2,
            )),
            2,
        )
        .unwrap()
    }

    fn signed_request(right_amount: &str) -> (L1ChannelOpenRequest, Account) {
        crate::protocol_registry::ensure_hacash_protocol_setup();
        let user = account(7);
        let hub = account(9);
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
            amount: Amount::from(right_amount).unwrap(),
        };
        let now = crate::node::now_unix();
        let mut tx = TransactionType2::new_by(
            Address::from_readable(user.readable()).unwrap(),
            Amount::from("0.0001").unwrap(),
            now,
        );
        let mut guard = ChainAllow::new();
        guard.chains = ChainIDList::from_list(vec![Uint4::from(0)]).unwrap();
        tx.push_action(Box::new(guard)).unwrap();
        tx.push_action(Box::new(action)).unwrap();
        tx.fill_sign(&user).unwrap();
        let partial_transaction_hex = hex::encode(tx.serialize());
        let request = L1ChannelOpenRequest {
            schema: L1_CHANNEL_OPEN_SCHEMA.into(),
            network: "mainnet".into(),
            chain_id: 0,
            mainnet: true,
            block_1_hash: crate::node::HACASH_MAINNET_BLOCK_ONE_HASH.into(),
            node_profile_id: "hacash-mainnet".into(),
            network_instance_id: mainnet_binding().network_instance_id,
            transaction_format_version: 2,
            operation_id: uuid::Uuid::new_v4().to_string(),
            idempotency_key: "channel-open-test-key-0001".into(),
            created_unix: now,
            expires_unix: now + 60,
            hub_address: hub.readable().into(),
            channel_id,
            expected_reuse_version: 1,
            partial_transaction_commitment: transaction_commitment(&partial_transaction_hex)
                .unwrap(),
            partial_transaction_hex,
            authorization_public_key_hex: String::new(),
            authorization_signature_hex: String::new(),
        };
        let mut request = request;
        let commitment: [u8; 32] = hex::decode(request_commitment(&request).unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        request.authorization_public_key_hex =
            hex::encode(user.public_key().serialize_compressed());
        request.authorization_signature_hex = hex::encode(user.do_sign(&commitment));
        (request, hub)
    }

    #[test]
    fn exact_user_signed_zero_hub_deposit_is_cosigned() {
        let (request, hub) = signed_request("0");
        let result = validate_and_cosign_channel_open(
            &request,
            &hub,
            &mainnet_binding(),
            100_000_000,
            request.created_unix,
        )
        .unwrap();
        let raw = hex::decode(&result.signed_transaction_hex).unwrap();
        let (tx, consumed) = protocol::transaction::transaction_create(&raw).unwrap();
        assert_eq!(consumed, raw.len());
        assert_eq!(tx.signs().len(), 2);
        tx.verify_signature().unwrap();
    }

    #[test]
    fn nonzero_hub_deposit_and_tampered_commitment_are_rejected() {
        let (request, hub) = signed_request("0.001");
        assert!(
            validate_and_cosign_channel_open(
                &request,
                &hub,
                &mainnet_binding(),
                100_000_000,
                request.created_unix,
            )
            .is_err()
        );

        let (mut request, hub) = signed_request("0");
        request.partial_transaction_commitment = "00".repeat(32);
        assert!(
            validate_and_cosign_channel_open(
                &request,
                &hub,
                &mainnet_binding(),
                100_000_000,
                request.created_unix,
            )
            .is_err()
        );
    }

    #[test]
    fn reused_channel_incarnation_is_rejected_before_cosigning() {
        let (mut request, hub) = signed_request("0");
        request.expected_reuse_version = 2;
        let error = validate_and_cosign_channel_open(
            &request,
            &hub,
            &mainnet_binding(),
            1_000_000,
            request.created_unix,
        )
        .unwrap_err();
        assert!(error.to_string().contains("fresh one-use channel"));
    }
}

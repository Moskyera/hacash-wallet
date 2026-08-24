//! Strict cooperative Action 3 plus optional Action 14 settlement validation.
//!
//! The active Hacash Action 3 restores the original L1 distribution. HubState
//! must therefore freeze the channel and prove that an optional, immediately
//! following Action 14 transfers exactly the authoritative L2 principal delta
//! before calling this signer.

use basis::interface::TransactionRead;
use field::{AddrOrPtr, Address};
use mint::action::ChannelClose;
use protocol::action::HacFromToTrs;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sys::Account;

use crate::error::{HubError, HubResult};
use crate::l1_channel::{
    L1ChannelNetworkBinding, MAX_CHANNEL_NETWORK_FEE_ZHU, MAX_CHANNEL_TRANSACTION_BYTES,
    transaction_commitment,
};

pub const L1_CHANNEL_CLOSE_SCHEMA: &str = "hpay-l1-channel-close/2";
/// Status reported when the Hub countersigned a delta-zero close and handed
/// the exact bytes back to the owner instead of broadcasting them. The channel
/// is still open, still usable, and no L1 transaction has been submitted.
///
/// This is not a trustless exit. The Hub chooses to countersign once, at the
/// start, and nothing in Hacash can compel it; and once the owner holds these
/// bytes the Hub carries the whole exposure, because the owner can spend the
/// channel down and still recover the full deposit at open. It is acceptable
/// only in this bounded pilot, where the owner runs the Hub.
pub const L1_CHANNEL_CLOSE_VOUCHER_STATUS: &str = "voucher_issued";
const REQUEST_MAX_LIFETIME_SECONDS: u64 = 300;
const TRANSACTION_MAX_AGE_SECONDS: u64 = 600;
const CLOCK_FUTURE_SKEW_SECONDS: u64 = 30;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct L1ChannelCloseRequest {
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
    pub user_address: String,
    pub channel_id: String,
    pub reuse_version: u64,
    pub open_height: u64,
    pub partial_transaction_hex: String,
    pub partial_transaction_commitment: String,
    pub authorization_public_key_hex: String,
    pub authorization_signature_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct L1ChannelCloseResponse {
    pub schema: String,
    pub operation_id: String,
    pub channel_id: String,
    pub reuse_version: u64,
    pub open_height: u64,
    pub status: String,
    pub transaction_hash: Option<String>,
    /// The exact fully countersigned close bytes, present only on the voucher
    /// path (`status == L1_CHANNEL_CLOSE_VOUCHER_STATUS`), where the Hub
    /// returns the transaction instead of broadcasting it.
    ///
    /// The cooperative-close path never fills this in: there the Hub owns the
    /// broadcast, so handing the bytes back would put a second copy of a live
    /// close in the owner's hands. Absent and skipped in that case, so a
    /// cooperative-close response is byte-identical to what it was before this
    /// field existed and older Hubs still deserialize here.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signed_transaction_hex: Option<String>,
    /// SHA-256 over the exact bytes in `signed_transaction_hex`, so the wallet
    /// can pin what it stored without re-deriving it from a parse.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signed_transaction_commitment: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpectedChannelIncarnation {
    pub channel_id: String,
    pub user_address: String,
    pub hub_address: String,
    pub reuse_version: u64,
    pub open_height: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedChannelClose {
    pub channel_id: String,
    pub user_address: String,
    pub reuse_version: u64,
    pub open_height: u64,
    pub transaction_hash: String,
    pub signed_transaction_hex: String,
    pub signed_transaction_commitment: String,
}

pub fn close_request_commitment(request: &L1ChannelCloseRequest) -> HubResult<String> {
    let mut digest = Sha256::new();
    digest.update(b"HPAY/L1/CHANNEL-CLOSE/REQUEST/V2");
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
        request.user_address.as_bytes(),
        request.channel_id.as_bytes(),
        &request.reuse_version.to_be_bytes(),
        &request.open_height.to_be_bytes(),
        request.partial_transaction_commitment.as_bytes(),
    ] {
        digest.update((field.len() as u64).to_be_bytes());
        digest.update(field);
    }
    Ok(hex::encode(digest.finalize()))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedChannelCloseIntent {
    pub channel_id: String,
    pub user_address: String,
    pub reuse_version: u64,
    pub open_height: u64,
    pub transaction_hash: String,
    pub network_fee_zhu: u64,
    pub settlement: ChannelCloseSettlement,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChannelCloseSettlement {
    OriginalDistribution,
    PrincipalTransfer {
        from_address: String,
        to_address: String,
        amount_millimeis: u64,
    },
}

pub fn validate_channel_close(
    request: &L1ChannelCloseRequest,
    expected: &ExpectedChannelIncarnation,
    expected_network: &L1ChannelNetworkBinding,
    now_unix: u64,
) -> HubResult<ValidatedChannelCloseIntent> {
    let (_, transaction_hash, network_fee_zhu, settlement) =
        parse_and_validate_channel_close(request, expected, expected_network, now_unix)?;
    Ok(ValidatedChannelCloseIntent {
        channel_id: expected.channel_id.clone(),
        user_address: expected.user_address.clone(),
        reuse_version: expected.reuse_version,
        open_height: expected.open_height,
        transaction_hash,
        network_fee_zhu,
        settlement,
    })
}
pub(crate) fn validate_and_cosign_channel_close(
    request: &L1ChannelCloseRequest,
    expected: &ExpectedChannelIncarnation,
    expected_settlement: &ChannelCloseSettlement,
    hub_signer: &Account,
    expected_network: &L1ChannelNetworkBinding,
    now_unix: u64,
) -> HubResult<ValidatedChannelClose> {
    if hub_signer.readable() != expected.hub_address {
        return Err(HubError::State(
            "configured Hub close signer does not match the channel".into(),
        ));
    }
    let (mut tx, transaction_hash, _, actual_settlement) =
        parse_and_validate_channel_close(request, expected, expected_network, now_unix)?;
    if &actual_settlement != expected_settlement {
        return Err(HubError::State(
            "authoritative channel-close settlement changed before signing".into(),
        ));
    }
    let intent_hash = tx.hash();
    tx.fill_sign(hub_signer)
        .map_err(|error| HubError::Payment(format!("Hub channel-close co-sign failed: {error}")))?;
    if tx.hash() != intent_hash || tx.signs().len() != 2 {
        return Err(HubError::State(
            "Hub channel-close signing changed the intent or signer count".into(),
        ));
    }
    let user = Address::from_readable(&expected.user_address)
        .map_err(|error| HubError::State(format!("invalid expected user: {error}")))?;
    let hub = Address::from_readable(&expected.hub_address)
        .map_err(|error| HubError::State(format!("invalid expected Hub: {error}")))?;
    let user_verified = protocol::transaction::verify_target_signature(&user, tx.as_read())
        .map_err(|error| {
            HubError::State(format!(
                "final channel-close user signature invalid: {error}"
            ))
        })?;
    let hub_verified =
        protocol::transaction::verify_target_signature(&hub, tx.as_read()).map_err(|error| {
            HubError::State(format!(
                "final channel-close Hub signature invalid: {error}"
            ))
        })?;
    if !user_verified || !hub_verified {
        return Err(HubError::State(
            "final channel-close transaction is missing a verified party signature".into(),
        ));
    }
    let signed = tx.serialize();
    Ok(ValidatedChannelClose {
        channel_id: expected.channel_id.clone(),
        user_address: expected.user_address.clone(),
        reuse_version: expected.reuse_version,
        open_height: expected.open_height,
        transaction_hash,
        signed_transaction_hex: hex::encode(&signed),
        signed_transaction_commitment: hex::encode(Sha256::digest(&signed)),
    })
}

fn parse_and_validate_channel_close(
    request: &L1ChannelCloseRequest,
    expected: &ExpectedChannelIncarnation,
    expected_network: &L1ChannelNetworkBinding,
    now_unix: u64,
) -> HubResult<(
    Box<dyn basis::interface::Transaction>,
    String,
    u64,
    ChannelCloseSettlement,
)> {
    validate_envelope(request, expected, expected_network, now_unix)?;
    let raw = hex::decode(&request.partial_transaction_hex)
        .map_err(|error| HubError::Payment(format!("channel-close transaction hex: {error}")))?;
    if raw.is_empty() || raw.len() > MAX_CHANNEL_TRANSACTION_BYTES {
        return Err(HubError::Payment(
            "channel-close transaction is empty or oversized".into(),
        ));
    }
    if transaction_commitment(&request.partial_transaction_hex)?
        != request.partial_transaction_commitment
    {
        return Err(HubError::Payment(
            "partial channel-close transaction commitment mismatch".into(),
        ));
    }
    crate::protocol_registry::ensure_hacash_protocol_setup();
    let (tx, consumed) = protocol::transaction::transaction_create(&raw).map_err(|error| {
        HubError::Payment(format!("invalid channel-close transaction: {error}"))
    })?;
    if consumed != raw.len() {
        return Err(HubError::Payment(
            "channel-close transaction contains trailing bytes".into(),
        ));
    }
    protocol::action::precheck_tx_actions(tx.ty(), tx.actions()).map_err(|error| {
        HubError::Payment(format!("channel-close action topology rejected: {error}"))
    })?;
    if tx.ty() != 2 {
        return Err(HubError::Payment(
            "channel-close must be a Type 2 transaction".into(),
        ));
    }
    let actions = tx.actions();
    let topology_valid = match actions.len() {
        2 => actions[0].kind() == 0x0411 && actions[1].kind() == 3,
        3 => actions[0].kind() == 0x0411 && actions[1].kind() == 3 && actions[2].kind() == 14,
        _ => false,
    };
    if !topology_valid {
        return Err(HubError::Payment(
            "channel-close actions must be exactly [ChainAllow,3] or [ChainAllow,3,14]".into(),
        ));
    }
    let guard = protocol::action::ChainAllow::downcast(&actions[0])
        .ok_or_else(|| HubError::Payment("ChainAllow action codec mismatch".into()))?;
    let chains = guard.chains.as_list();
    if chains.len() != 1 || chains[0].uint() != expected_network.chain_id {
        return Err(HubError::Payment(format!(
            "ChainAllow must bind exactly chain {}",
            expected_network.chain_id
        )));
    }
    let action = ChannelClose::downcast(&tx.actions()[1])
        .ok_or_else(|| HubError::Payment("channel-close action codec mismatch".into()))?;
    if hex::encode(action.channel_id.as_bytes()) != expected.channel_id.to_ascii_lowercase() {
        return Err(HubError::Payment(
            "channel-close action targets a different channel".into(),
        ));
    }
    let user = Address::from_readable(&expected.user_address)
        .map_err(|error| HubError::Payment(format!("invalid channel user: {error}")))?;
    let hub = Address::from_readable(&expected.hub_address)
        .map_err(|error| HubError::Payment(format!("invalid channel Hub: {error}")))?;
    let settlement = if actions.len() == 2 {
        ChannelCloseSettlement::OriginalDistribution
    } else {
        validate_principal_transfer(
            HacFromToTrs::downcast(&actions[2]).ok_or_else(|| {
                HubError::Payment("channel-close action 14 codec mismatch".into())
            })?,
            &user,
            &hub,
        )?
    };
    if tx.main() != user {
        return Err(HubError::Payment(
            "channel-close fee payer must be the channel user".into(),
        ));
    }
    let fee_zhu = tx
        .fee()
        .to_zhu_u64()
        .map_err(|error| HubError::Payment(format!("invalid channel-close fee: {error}")))?;
    if fee_zhu == 0 || fee_zhu > MAX_CHANNEL_NETWORK_FEE_ZHU {
        return Err(HubError::Payment(format!(
            "channel-close fee must be positive and at most {MAX_CHANNEL_NETWORK_FEE_ZHU} zhu"
        )));
    }
    let tx_timestamp = tx.timestamp().uint();
    if tx_timestamp > now_unix.saturating_add(CLOCK_FUTURE_SKEW_SECONDS)
        || now_unix.saturating_sub(tx_timestamp) > TRANSACTION_MAX_AGE_SECONDS
    {
        return Err(HubError::Payment(
            "channel-close transaction timestamp is outside the signing window".into(),
        ));
    }
    require_exact_user_partial_signature(tx.as_read(), &user, &hub)?;
    verify_request_authorization(request, &user)?;
    let transaction_hash = hex::encode(tx.hash().as_bytes());
    Ok((tx, transaction_hash, fee_zhu, settlement))
}

fn validate_principal_transfer(
    transfer: &HacFromToTrs,
    user: &Address,
    hub: &Address,
) -> HubResult<ChannelCloseSettlement> {
    let from = match transfer.from {
        AddrOrPtr::Val1(address) => address,
        AddrOrPtr::Val2(_) => {
            return Err(HubError::Payment(
                "channel-close principal transfer cannot use an address pointer".into(),
            ));
        }
    };
    let to = match transfer.to {
        AddrOrPtr::Val1(address) => address,
        AddrOrPtr::Val2(_) => {
            return Err(HubError::Payment(
                "channel-close principal transfer cannot use an address pointer".into(),
            ));
        }
    };
    if !((from == *user && to == *hub) || (from == *hub && to == *user)) {
        return Err(HubError::Payment(
            "channel-close principal transfer must be exactly between the channel parties".into(),
        ));
    }
    let amount_zhu = transfer.hacash.to_zhu_u64().map_err(|error| {
        HubError::Payment(format!(
            "invalid channel-close principal transfer amount: {error}"
        ))
    })?;
    if amount_zhu == 0 || amount_zhu % crate::readiness::ZHU_PER_MILLIMEI != 0 {
        return Err(HubError::Payment(
            "channel-close principal transfer must be a positive exact millimei amount".into(),
        ));
    }
    Ok(ChannelCloseSettlement::PrincipalTransfer {
        from_address: from.to_readable(),
        to_address: to.to_readable(),
        amount_millimeis: amount_zhu / crate::readiness::ZHU_PER_MILLIMEI,
    })
}

fn validate_envelope(
    request: &L1ChannelCloseRequest,
    expected: &ExpectedChannelIncarnation,
    expected_network: &L1ChannelNetworkBinding,
    now_unix: u64,
) -> HubResult<()> {
    expected_network.validate()?;
    if request.schema != L1_CHANNEL_CLOSE_SCHEMA
        || request.network != expected_network.network_kind
        || request.chain_id != expected_network.chain_id
        || request.mainnet != expected_network.mainnet
        || request.block_1_hash != expected_network.block_1_hash
        || request.node_profile_id != expected_network.node_profile_id
        || request.network_instance_id != expected_network.network_instance_id
        || request.transaction_format_version != expected_network.transaction_format_version
    {
        return Err(HubError::Payment(
            "unsupported L1 channel-close schema or live network binding mismatch".into(),
        ));
    }
    let operation = uuid::Uuid::parse_str(&request.operation_id)
        .map_err(|_| HubError::Payment("operation_id must be a UUID".into()))?;
    let key = request.idempotency_key.as_str();
    if operation.is_nil()
        || operation.to_string() != request.operation_id
        || request.channel_id != expected.channel_id
        || request.channel_id.len() != 32
        || !request
            .channel_id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || !(16..=128).contains(&key.len())
        || !key
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        return Err(HubError::Payment(
            "channel-close operation identity is malformed".into(),
        ));
    }
    if request.created_unix > now_unix.saturating_add(CLOCK_FUTURE_SKEW_SECONDS)
        || request.expires_unix <= now_unix
        || request.expires_unix <= request.created_unix
        || request.expires_unix.saturating_sub(request.created_unix) > REQUEST_MAX_LIFETIME_SECONDS
    {
        return Err(HubError::Payment(
            "channel-close request is expired or outside the signing window".into(),
        ));
    }
    if request.hub_address != expected.hub_address
        || request.user_address != expected.user_address
        || request.reuse_version != expected.reuse_version
        || request.open_height != expected.open_height
    {
        return Err(HubError::Payment(
            "channel-close request targets a different channel incarnation".into(),
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
            "channel-close ID or transaction commitment is malformed".into(),
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
            "partial channel-close transaction must contain exactly one user signature".into(),
        ));
    }
    let signer = Address::from(Account::get_address_by_public_key(*tx.signs()[0].publickey));
    if signer != *user || signer == *hub {
        return Err(HubError::Payment(
            "partial channel-close transaction is not signed only by the user".into(),
        ));
    }
    let verified = protocol::transaction::verify_target_signature(user, tx).map_err(|error| {
        HubError::Payment(format!("user channel-close signature invalid: {error}"))
    })?;
    if !verified {
        return Err(HubError::Payment(
            "user channel-close signature was not verified".into(),
        ));
    }
    Ok(())
}

fn verify_request_authorization(
    request: &L1ChannelCloseRequest,
    expected_user: &Address,
) -> HubResult<()> {
    let public_key: [u8; 33] = hex::decode(&request.authorization_public_key_hex)
        .map_err(|_| HubError::Payment("channel-close authorization public key is not hex".into()))?
        .try_into()
        .map_err(|_| {
            HubError::Payment("channel-close authorization public key must be 33 bytes".into())
        })?;
    let signature: [u8; 64] = hex::decode(&request.authorization_signature_hex)
        .map_err(|_| HubError::Payment("channel-close authorization signature is not hex".into()))?
        .try_into()
        .map_err(|_| {
            HubError::Payment("channel-close authorization signature must be 64 bytes".into())
        })?;
    if Address::from(Account::get_address_by_public_key(public_key)) != *expected_user {
        return Err(HubError::Payment(
            "channel-close request authorization does not belong to the user".into(),
        ));
    }
    let commitment: [u8; 32] = hex::decode(close_request_commitment(request)?)
        .map_err(|_| HubError::State("channel-close request commitment is invalid".into()))?
        .try_into()
        .map_err(|_| HubError::State("channel-close commitment must be 32 bytes".into()))?;
    if !Account::verify_signature(&commitment, &public_key, &signature) {
        return Err(HubError::Payment(
            "channel-close request authorization signature is invalid".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use basis::interface::Transaction;
    use field::{AddrOrPtr, Address, Amount, ChannelId, Field, Serialize as _, Uint4};
    use mint::action::ChannelClose;
    use protocol::action::{ChainAllow, ChainIDList, HacFromToTrs};
    use protocol::transaction::TransactionType2;

    use super::*;

    fn account(byte: u8) -> Account {
        Account::create_by(&hex::encode([byte; 32])).unwrap()
    }

    fn binding() -> L1ChannelNetworkBinding {
        L1ChannelNetworkBinding::from_node_identity(
            "mainnet",
            true,
            0,
            crate::node::HACASH_MAINNET_BLOCK_ONE_HASH,
            "hacash-mainnet",
            Some(&crate::l1_channel::canonical_network_instance_id(
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

    #[derive(Clone, Copy)]
    enum TestParty {
        User,
        Hub,
        Other,
    }

    fn make_request_with_transfer(
        transfer: Option<(TestParty, TestParty, &str)>,
    ) -> (L1ChannelCloseRequest, ExpectedChannelIncarnation, Account) {
        crate::protocol_registry::ensure_hacash_protocol_setup();
        let user = account(17);
        let hub = account(19);
        let other = account(23);
        let channel_id = "00112233445566778899aabbccddeeff".to_string();
        let mut action = ChannelClose::new();
        action.channel_id =
            ChannelId::from(<[u8; 16]>::try_from(hex::decode(&channel_id).unwrap()).unwrap());
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
        if let Some((from, to, amount)) = transfer {
            let address = |party| match party {
                TestParty::User => Address::from_readable(user.readable()).unwrap(),
                TestParty::Hub => Address::from_readable(hub.readable()).unwrap(),
                TestParty::Other => Address::from_readable(other.readable()).unwrap(),
            };
            let mut principal = HacFromToTrs::new();
            principal.from = AddrOrPtr::from_addr(address(from));
            principal.to = AddrOrPtr::from_addr(address(to));
            principal.hacash = Amount::from(amount).unwrap();
            tx.push_action(Box::new(principal)).unwrap();
        }
        tx.fill_sign(&user).unwrap();
        let partial_transaction_hex = hex::encode(tx.serialize());
        let expected = ExpectedChannelIncarnation {
            channel_id: channel_id.clone(),
            user_address: user.readable().into(),
            hub_address: hub.readable().into(),
            reuse_version: 3,
            open_height: 765_500,
        };
        let mut request = L1ChannelCloseRequest {
            schema: L1_CHANNEL_CLOSE_SCHEMA.into(),
            network: "mainnet".into(),
            chain_id: 0,
            mainnet: true,
            block_1_hash: binding().block_1_hash,
            node_profile_id: binding().node_profile_id,
            network_instance_id: binding().network_instance_id,
            transaction_format_version: 2,
            operation_id: uuid::Uuid::new_v4().to_string(),
            idempotency_key: "channel-close-test-key-0001".into(),
            created_unix: now,
            expires_unix: now + 60,
            hub_address: expected.hub_address.clone(),
            user_address: expected.user_address.clone(),
            channel_id,
            reuse_version: expected.reuse_version,
            open_height: expected.open_height,
            partial_transaction_commitment: transaction_commitment(&partial_transaction_hex)
                .unwrap(),
            partial_transaction_hex,
            authorization_public_key_hex: hex::encode(user.public_key().serialize_compressed()),
            authorization_signature_hex: String::new(),
        };
        let commitment: [u8; 32] = hex::decode(close_request_commitment(&request).unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        request.authorization_signature_hex = hex::encode(user.do_sign(&commitment));
        (request, expected, hub)
    }

    fn make_request() -> (L1ChannelCloseRequest, ExpectedChannelIncarnation, Account) {
        make_request_with_transfer(None)
    }

    #[test]
    fn exact_action3_requires_and_verifies_user_and_hub_signatures() {
        let (request, expected, hub) = make_request();
        let result = validate_and_cosign_channel_close(
            &request,
            &expected,
            &ChannelCloseSettlement::OriginalDistribution,
            &hub,
            &binding(),
            request.created_unix,
        )
        .unwrap();
        let raw = hex::decode(result.signed_transaction_hex).unwrap();
        let (tx, consumed) = protocol::transaction::transaction_create(&raw).unwrap();
        assert_eq!(consumed, raw.len());
        assert_eq!(tx.signs().len(), 2);
        let user = Address::from_readable(&expected.user_address).unwrap();
        let hub = Address::from_readable(&expected.hub_address).unwrap();
        protocol::transaction::verify_target_signature(&user, tx.as_read()).unwrap();
        protocol::transaction::verify_target_signature(&hub, tx.as_read()).unwrap();
    }

    #[test]
    fn changed_channel_incarnation_or_commitment_is_rejected() {
        let (request, mut expected, hub) = make_request();
        expected.reuse_version += 1;
        assert!(
            validate_and_cosign_channel_close(
                &request,
                &expected,
                &ChannelCloseSettlement::OriginalDistribution,
                &hub,
                &binding(),
                request.created_unix,
            )
            .is_err()
        );
        let (mut request, expected, hub) = make_request();
        request.partial_transaction_commitment = "00".repeat(32);
        assert!(
            validate_and_cosign_channel_close(
                &request,
                &expected,
                &ChannelCloseSettlement::OriginalDistribution,
                &hub,
                &binding(),
                request.created_unix,
            )
            .is_err()
        );
    }

    #[test]
    fn operation_and_channel_identifiers_must_be_canonical() {
        let (mut request, expected, _) = make_request();
        request.operation_id = format!(" {} ", request.operation_id);
        assert!(
            validate_channel_close(&request, &expected, &binding(), request.created_unix).is_err()
        );

        let (mut request, expected, _) = make_request();
        request.channel_id = request.channel_id.to_ascii_uppercase();
        assert!(
            validate_channel_close(&request, &expected, &binding(), request.created_unix).is_err()
        );
    }

    #[test]
    fn cosigner_refuses_a_settlement_other_than_the_authoritative_one() {
        let (request, expected, hub) =
            make_request_with_transfer(Some((TestParty::User, TestParty::Hub, "0.001")));
        assert!(
            validate_and_cosign_channel_close(
                &request,
                &expected,
                &ChannelCloseSettlement::OriginalDistribution,
                &hub,
                &binding(),
                request.created_unix,
            )
            .is_err()
        );
    }

    #[test]
    fn exact_action3_plus_action14_principal_delta_is_accepted() {
        let (request, expected, _) =
            make_request_with_transfer(Some((TestParty::User, TestParty::Hub, "0.001")));
        let intent =
            validate_channel_close(&request, &expected, &binding(), request.created_unix).unwrap();
        assert_eq!(
            intent.settlement,
            ChannelCloseSettlement::PrincipalTransfer {
                from_address: expected.user_address.clone(),
                to_address: expected.hub_address.clone(),
                amount_millimeis: 1,
            }
        );

        let (request, expected, _) =
            make_request_with_transfer(Some((TestParty::Hub, TestParty::User, "0.002")));
        let intent =
            validate_channel_close(&request, &expected, &binding(), request.created_unix).unwrap();
        assert_eq!(
            intent.settlement,
            ChannelCloseSettlement::PrincipalTransfer {
                from_address: expected.hub_address.clone(),
                to_address: expected.user_address.clone(),
                amount_millimeis: 2,
            }
        );
    }

    #[test]
    fn action14_rejects_outsiders_and_non_millimei_amounts() {
        let (request, expected, _) =
            make_request_with_transfer(Some((TestParty::User, TestParty::Other, "0.001")));
        assert!(
            validate_channel_close(&request, &expected, &binding(), request.created_unix).is_err()
        );

        let (request, expected, _) =
            make_request_with_transfer(Some((TestParty::User, TestParty::Hub, "0.0001")));
        assert!(
            validate_channel_close(&request, &expected, &binding(), request.created_unix).is_err()
        );
    }
}

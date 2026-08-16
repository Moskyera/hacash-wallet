//! Durable fee-free payment progression for the shared HVM registry profile.

use basis::method::verify_signature;
use field::{Hash, Serialize as FieldSerialize};

use serde::{Deserialize, Serialize};

use crate::error::{HubError, HubResult};
use crate::hvm_channel::{parse_address, parse_signature};
use crate::hvm_ledger::HvmBillProgressionStatus;
use crate::hvm_registry::{
    HVM_REGISTRY_BILL_SCHEMA, HvmRegistryBillV2, HvmRegistryBindingV2, HvmRegistryRecoveryBundleV2,
};
use crate::l1_channel::L1ChannelNetworkBinding;

pub const HVM_REGISTRY_PAYMENT_REQUEST_SCHEMA: &str = "hpay-hvm-registry-payment-request/2";
pub const HVM_REGISTRY_PAYMENT_STATUS_SCHEMA: &str = "hpay-hvm-registry-payment-status/2";
pub const HVM_REGISTRY_CHANNEL_STATUS_SCHEMA: &str = "hpay-hvm-registry-channel-status/2";
pub const HVM_REGISTRY_PAYMENT_MAX_LIFETIME_SECONDS: u64 = 5 * 60;
const HVM_REGISTRY_PAYER_AUTHORIZATION_DOMAIN: &[u8] = b"HPAY/HVM-REGISTRY/PAYER-AUTHORIZATION/V1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HvmRegistryPaymentRequestV2 {
    pub schema: String,
    pub operation_id: String,
    pub idempotency_key: String,
    #[serde(default = "missing_network_binding")]
    pub network_binding: L1ChannelNetworkBinding,
    pub binding_commitment: String,
    #[serde(default)]
    pub previous_bill_commitment: String,
    #[serde(default)]
    pub unsigned_bill_hash: String,
    pub payer: String,
    /// Registry V2 credits only the bound Hub balance. This is therefore the
    /// exact Hub-owned service identity, not a third-party payout destination.
    pub recipient: String,
    pub amount_zhu: u64,
    #[serde(default)]
    pub network_fee_zhu: u64,
    #[serde(default)]
    pub wallet_fee_zhu: u64,
    pub hub_fee_zhu: u64,
    #[serde(default)]
    pub total_debit_zhu: u64,
    pub proposed_bill: HvmRegistryBillV2,
    pub created_unix: u64,
    pub expires_unix: u64,
    #[serde(default)]
    pub payer_authorization_signature_hex: String,
}

impl HvmRegistryPaymentRequestV2 {
    #[allow(clippy::too_many_arguments)]
    pub fn build_unsigned(
        network_binding: &L1ChannelNetworkBinding,
        binding: &HvmRegistryBindingV2,
        previous: &HvmRegistryBillV2,
        operation_id: &str,
        idempotency_key: &str,
        recipient: &str,
        amount_zhu: u64,
        created_unix: u64,
        expires_unix: u64,
    ) -> HubResult<Self> {
        network_binding.validate()?;
        binding.validate()?;
        previous.validate_fully_signed(binding)?;
        let left_balance_zhu = previous
            .left_balance_zhu
            .checked_sub(amount_zhu)
            .ok_or_else(|| {
                HubError::Payment("registry payment exceeds the current left balance".into())
            })?;
        let hub_balance_zhu = previous
            .hub_balance_zhu
            .checked_add(amount_zhu)
            .ok_or_else(|| HubError::Payment("registry payment balance overflow".into()))?;
        let binding_commitment = binding.commitment()?;
        let proposed_bill = HvmRegistryBillV2 {
            schema: HVM_REGISTRY_BILL_SCHEMA.into(),
            binding_commitment: binding_commitment.clone(),
            serial: previous
                .serial
                .checked_add(1)
                .ok_or_else(|| HubError::Payment("registry bill serial overflow".into()))?,
            left_balance_zhu,
            hub_balance_zhu,
            left_signature_hex: String::new(),
            hub_signature_hex: String::new(),
        };
        let unsigned_bill_hash = hex::encode(proposed_bill.signing_hash(binding)?.serialize());
        let request = Self {
            schema: HVM_REGISTRY_PAYMENT_REQUEST_SCHEMA.into(),
            operation_id: operation_id.to_owned(),
            idempotency_key: idempotency_key.to_owned(),
            network_binding: network_binding.clone(),
            binding_commitment: binding_commitment.clone(),
            previous_bill_commitment: previous.commitment()?,
            unsigned_bill_hash,
            payer: binding.left_address.clone(),
            recipient: recipient.to_owned(),
            amount_zhu,
            network_fee_zhu: 0,
            wallet_fee_zhu: 0,
            hub_fee_zhu: 0,
            total_debit_zhu: amount_zhu,
            proposed_bill,
            created_unix,
            expires_unix,
            payer_authorization_signature_hex: String::new(),
        };
        request.validate_unsigned_against(binding, previous, created_unix)?;
        Ok(request)
    }

    pub fn validate_unsigned_against(
        &self,
        binding: &HvmRegistryBindingV2,
        previous: &HvmRegistryBillV2,
        now_unix: u64,
    ) -> HubResult<()> {
        self.validate_transition_against(binding, previous, now_unix)?;
        if !self.proposed_bill.left_signature_hex.is_empty()
            || !self.proposed_bill.hub_signature_hex.is_empty()
            || !self.payer_authorization_signature_hex.is_empty()
        {
            return Err(HubError::Payment(
                "unsigned registry request already contains a signature".into(),
            ));
        }
        Ok(())
    }

    pub fn validate_against(
        &self,
        binding: &HvmRegistryBindingV2,
        previous: &HvmRegistryBillV2,
        now_unix: u64,
    ) -> HubResult<()> {
        self.validate_transition_against(binding, previous, now_unix)?;
        self.proposed_bill.validate_left_signed(binding)?;
        self.validate_payer_authorization(binding, previous)
    }

    fn validate_transition_against(
        &self,
        binding: &HvmRegistryBindingV2,
        previous: &HvmRegistryBillV2,
        now_unix: u64,
    ) -> HubResult<()> {
        self.network_binding.validate()?;
        let previous_bill_commitment = previous.commitment()?;
        let unsigned_bill_hash = hex::encode(self.proposed_bill.signing_hash(binding)?.serialize());
        let network_matches_binding = self.network_binding.chain_id == binding.chain_id
            && self.network_binding.mainnet == (binding.network_mode == "mainnet")
            && self.network_binding.network_instance_id == binding.network_instance_id;
        if self.schema != HVM_REGISTRY_PAYMENT_REQUEST_SCHEMA
            || self.operation_id.trim().is_empty()
            || self.idempotency_key.trim().is_empty()
            || !network_matches_binding
            || self.binding_commitment != binding.commitment()?
            || self.previous_bill_commitment != previous_bill_commitment
            || self.unsigned_bill_hash != unsigned_bill_hash
            || self.payer != binding.left_address
            || self.recipient != binding.right_hub_address
            || self.amount_zhu == 0
            || self.network_fee_zhu != 0
            || self.wallet_fee_zhu != 0
            || self.hub_fee_zhu != 0
            || self.total_debit_zhu != self.amount_zhu
            || self.created_unix > now_unix
            || now_unix >= self.expires_unix
            || self.expires_unix.saturating_sub(self.created_unix)
                > HVM_REGISTRY_PAYMENT_MAX_LIFETIME_SECONDS
        {
            return Err(HubError::Payment(
                "registry payment identity, expiry or fee policy is invalid".into(),
            ));
        }
        previous.validate_fully_signed(binding)?;
        self.proposed_bill.signing_hash(binding)?;
        let expected_left = previous
            .left_balance_zhu
            .checked_sub(self.amount_zhu)
            .ok_or_else(|| {
                HubError::Payment("registry payment exceeds the current left balance".into())
            })?;
        let expected_hub = previous
            .hub_balance_zhu
            .checked_add(self.amount_zhu)
            .ok_or_else(|| HubError::Payment("registry payment balance overflow".into()))?;
        if !self.proposed_bill.hub_signature_hex.is_empty()
            || self.proposed_bill.serial != previous.serial.checked_add(1).unwrap_or_default()
            || self.proposed_bill.left_balance_zhu != expected_left
            || self.proposed_bill.hub_balance_zhu != expected_hub
        {
            return Err(HubError::Payment(
                "registry bill is not the exact next fee-free transition".into(),
            ));
        }
        Ok(())
    }

    /// Domain-separated authorization over the entire economic and replay
    /// context. The ordinary bill signature stays independent for on-chain
    /// challenge handling; this signature proves the exact service request
    /// that the payer authorized.
    pub fn payer_authorization_hash(
        &self,
        binding: &HvmRegistryBindingV2,
        previous: &HvmRegistryBillV2,
    ) -> HubResult<Hash> {
        binding.validate()?;
        self.network_binding.validate()?;
        previous.validate_fully_signed(binding)?;
        let binding_bytes = serde_json::to_vec(binding)
            .map_err(|error| HubError::State(format!("registry binding encode failed: {error}")))?;
        let network_bytes = serde_json::to_vec(&self.network_binding).map_err(|error| {
            HubError::State(format!("registry network binding encode failed: {error}"))
        })?;
        let unsigned_bill_hash = self.proposed_bill.signing_hash(binding)?;
        let unsigned_bill_hash_bytes = unsigned_bill_hash.serialize();
        let mut bytes = Vec::with_capacity(768);
        bytes.extend_from_slice(HVM_REGISTRY_PAYER_AUTHORIZATION_DOMAIN);
        for field in [
            network_bytes.as_slice(),
            binding_bytes.as_slice(),
            self.binding_commitment.as_bytes(),
            self.previous_bill_commitment.as_bytes(),
            unsigned_bill_hash_bytes.as_slice(),
            self.operation_id.as_bytes(),
            self.idempotency_key.as_bytes(),
            self.payer.as_bytes(),
            self.recipient.as_bytes(),
        ] {
            push_authorization_field(&mut bytes, field)?;
        }
        for value in [
            self.amount_zhu,
            self.network_fee_zhu,
            self.wallet_fee_zhu,
            self.hub_fee_zhu,
            self.total_debit_zhu,
            self.created_unix,
            self.expires_unix,
        ] {
            bytes.extend_from_slice(&value.to_be_bytes());
        }
        Ok(Hash::from(sys::sha3(bytes)))
    }

    pub fn validate_payer_authorization(
        &self,
        binding: &HvmRegistryBindingV2,
        previous: &HvmRegistryBillV2,
    ) -> HubResult<()> {
        let hash = self.payer_authorization_hash(binding, previous)?;
        let payer = parse_address(&self.payer, "registry payment payer")?;
        let signature = parse_signature(&self.payer_authorization_signature_hex)?;
        if !verify_signature(&hash, &payer, &signature) {
            return Err(HubError::Payment(
                "registry payer authorization does not match the bound payer".into(),
            ));
        }
        Ok(())
    }

    pub fn commitment(&self) -> HubResult<String> {
        let bytes = serde_json::to_vec(self)
            .map_err(|error| HubError::State(format!("registry request encode failed: {error}")))?;
        Ok(hex::encode(sys::sha2(bytes)))
    }
}

fn push_authorization_field(bytes: &mut Vec<u8>, field: &[u8]) -> HubResult<()> {
    let length = u64::try_from(field.len())
        .map_err(|_| HubError::State("registry authorization field is too large".into()))?;
    bytes.extend_from_slice(&length.to_be_bytes());
    bytes.extend_from_slice(field);
    Ok(())
}

fn missing_network_binding() -> L1ChannelNetworkBinding {
    L1ChannelNetworkBinding {
        network_kind: String::new(),
        chain_id: u32::MAX,
        mainnet: false,
        block_1_hash: String::new(),
        node_profile_id: String::new(),
        network_instance_id: String::new(),
        transaction_format_version: 0,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HvmRegistryChannelStatusV2 {
    pub schema: String,
    pub binding_commitment: String,
    pub recovery_bundle: HvmRegistryRecoveryBundleV2,
    pub activation_snapshot_commitment: String,
    pub minimum_required_live_blocks: u64,
    pub minimum_required_recover_blocks: u64,
    pub latest_fully_signed_bill: HvmRegistryBillV2,
    pub activated_unix: u64,
    pub updated_unix: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HvmRegistryPaymentStatusV2 {
    pub schema: String,
    pub operation_id: String,
    pub request_commitment: String,
    pub status: String,
    pub request: HvmRegistryPaymentRequestV2,
    pub fully_signed_bill: Option<HvmRegistryBillV2>,
    pub updated_unix: u64,
    pub recovery_required: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct PersistedHvmRegistryLedger {
    pub binding_commitment: String,
    pub latest_fully_signed_bill: HvmRegistryBillV2,
    pub updated_unix: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct PersistedHvmRegistryProgression {
    pub request: HvmRegistryPaymentRequestV2,
    pub request_commitment: String,
    pub previous_bill: HvmRegistryBillV2,
    pub fully_signed_bill: Option<HvmRegistryBillV2>,
    pub status: HvmBillProgressionStatus,
    pub observed_height_before_signing: Option<u64>,
    pub updated_unix: u64,
    pub last_error: Option<String>,
}

pub(crate) fn validate_registry_progression(
    progression: &PersistedHvmRegistryProgression,
    binding: &HvmRegistryBindingV2,
    ledger: &PersistedHvmRegistryLedger,
) -> HubResult<()> {
    if progression.request_commitment != progression.request.commitment()?
        || progression.request.binding_commitment != ledger.binding_commitment
        || progression.previous_bill.binding_commitment != ledger.binding_commitment
    {
        return Err(HubError::State(
            "persisted registry progression commitment is inconsistent".into(),
        ));
    }
    progression.previous_bill.validate_fully_signed(binding)?;
    progression.request.validate_against(
        binding,
        &progression.previous_bill,
        progression.request.created_unix,
    )?;
    match progression.status {
        HvmBillProgressionStatus::UserProposalPersisted
        | HvmBillProgressionStatus::HubSignatureMayExist => {
            if progression.fully_signed_bill.is_some()
                || !progression
                    .request
                    .proposed_bill
                    .hub_signature_hex
                    .is_empty()
                || ledger.latest_fully_signed_bill != progression.previous_bill
            {
                return Err(HubError::State(
                    "unresolved registry progression changed its ledger base".into(),
                ));
            }
        }
        HvmBillProgressionStatus::FullySigned => {
            let signed = progression.fully_signed_bill.as_ref().ok_or_else(|| {
                HubError::State("completed registry progression has no signed bill".into())
            })?;
            signed.validate_fully_signed(binding)?;
            if ledger.latest_fully_signed_bill != *signed {
                return Err(HubError::State(
                    "completed registry progression is not the durable ledger head".into(),
                ));
            }
        }
        HvmBillProgressionStatus::RecoveryRequired => {
            if let Some(signed) = progression.fully_signed_bill.as_ref() {
                signed.validate_fully_signed(binding)?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hvm_registry::{
        HPAY_REGISTRY_BYTECODE_SHA3, HPAY_REGISTRY_SETTLEMENT_PROFILE, HVM_REGISTRY_BINDING_SCHEMA,
    };
    use crate::l1_channel::canonical_network_instance_id;
    use field::{Address, Serialize as FieldSerialize, Sign};
    use sys::Account;

    fn fixture() -> (
        Account,
        Account,
        L1ChannelNetworkBinding,
        HvmRegistryBindingV2,
        HvmRegistryBillV2,
    ) {
        let left = Account::create_by("registry-ledger-left").unwrap();
        let hub = Account::create_by("registry-ledger-hub").unwrap();
        // The network instance id is not free-form: it must equal the digest the
        // network identity derives, and it is now mandatory. This fixture used to
        // pass None, which became an empty string and failed once that check was
        // tightened.
        //
        // Derived here with the same function production uses rather than written
        // out as a literal, so a change to the derivation moves the fixture with
        // it instead of breaking these five tests again.
        const NETWORK_KIND: &str = "local_pilot_v1";
        const PROFILE_ID: &str = "registry-ledger-profile";
        const CHAIN_ID: u32 = 7;
        const TX_FORMAT: u64 = 2;
        let block_1_hash = "11".repeat(32);
        let instance_id = canonical_network_instance_id(
            NETWORK_KIND,
            CHAIN_ID,
            false,
            &block_1_hash,
            PROFILE_ID,
            TX_FORMAT,
        );
        let network = L1ChannelNetworkBinding::from_node_identity(
            NETWORK_KIND,
            false,
            CHAIN_ID,
            &block_1_hash,
            PROFILE_ID,
            Some(&instance_id),
            TX_FORMAT,
        )
        .unwrap();
        let binding = HvmRegistryBindingV2 {
            schema: HVM_REGISTRY_BINDING_SCHEMA.into(),
            settlement_profile: HPAY_REGISTRY_SETTLEMENT_PROFILE.into(),
            network_mode: "testnet".into(),
            chain_id: 7,
            network_instance_id: network.network_instance_id.clone(),
            contract_address: Address::create_contract([8; 20]).to_readable(),
            deployment_tx_hash: "22".repeat(32),
            deployment_height: 10,
            bytecode_sha3: HPAY_REGISTRY_BYTECODE_SHA3.into(),
            channel_id: "33".repeat(16),
            reuse_version: 0,
            left_address: left.readable().to_owned(),
            right_hub_address: hub.readable().to_owned(),
            left_deposit_zhu: 1_000,
            right_hub_deposit_zhu: 0,
            challenge_blocks: 12,
        };
        let mut bill = HvmRegistryBillV2 {
            schema: HVM_REGISTRY_BILL_SCHEMA.into(),
            binding_commitment: binding.commitment().unwrap(),
            serial: 1,
            left_balance_zhu: 1_000,
            hub_balance_zhu: 0,
            left_signature_hex: String::new(),
            hub_signature_hex: String::new(),
        };
        let hash = bill.signing_hash(&binding).unwrap();
        bill.left_signature_hex = hex::encode(Sign::create_by(&left, &hash).serialize());
        bill.hub_signature_hex = hex::encode(Sign::create_by(&hub, &hash).serialize());
        (left, hub, network, binding, bill)
    }

    fn sign_request(
        request: &mut HvmRegistryPaymentRequestV2,
        binding: &HvmRegistryBindingV2,
        previous: &HvmRegistryBillV2,
        left: &Account,
    ) {
        let bill_hash = request.proposed_bill.signing_hash(binding).unwrap();
        request.proposed_bill.left_signature_hex =
            hex::encode(Sign::create_by(left, &bill_hash).serialize());
        let authorization_hash = request.payer_authorization_hash(binding, previous).unwrap();
        request.payer_authorization_signature_hex =
            hex::encode(Sign::create_by(left, &authorization_hash).serialize());
    }

    #[test]
    fn unsigned_builder_is_exact_and_fee_free() {
        let (_, _, network, binding, previous) = fixture();
        let recipient = binding.right_hub_address.clone();
        let request = HvmRegistryPaymentRequestV2::build_unsigned(
            &network, &binding, &previous, "op-1", "idem-1", &recipient, 100, 10, 20,
        )
        .unwrap();
        assert_eq!(request.recipient, binding.right_hub_address);
        assert_eq!(request.network_fee_zhu, 0);
        assert_eq!(request.wallet_fee_zhu, 0);
        assert_eq!(request.hub_fee_zhu, 0);
        assert_eq!(request.total_debit_zhu, 100);
        assert_eq!(
            request.previous_bill_commitment,
            previous.commitment().unwrap()
        );
        assert_eq!(request.proposed_bill.serial, 2);
        assert_eq!(request.proposed_bill.left_balance_zhu, 900);
        assert_eq!(request.proposed_bill.hub_balance_zhu, 100);
        assert!(
            request
                .validate_unsigned_against(&binding, &previous, 10)
                .is_ok()
        );
    }

    #[test]
    fn progression_rejects_a_changed_ledger_head() {
        let (left, _, network, binding, previous) = fixture();
        let recipient = binding.right_hub_address.clone();
        let mut request = HvmRegistryPaymentRequestV2::build_unsigned(
            &network, &binding, &previous, "op-1", "idem-1", &recipient, 100, 10, 20,
        )
        .unwrap();
        sign_request(&mut request, &binding, &previous, &left);
        let progression = PersistedHvmRegistryProgression {
            request_commitment: request.commitment().unwrap(),
            request,
            previous_bill: previous.clone(),
            fully_signed_bill: None,
            status: HvmBillProgressionStatus::UserProposalPersisted,
            observed_height_before_signing: Some(11),
            updated_unix: 10,
            last_error: None,
        };
        let mut ledger = PersistedHvmRegistryLedger {
            binding_commitment: binding.commitment().unwrap(),
            latest_fully_signed_bill: previous.clone(),
            updated_unix: 10,
        };
        assert!(validate_registry_progression(&progression, &binding, &ledger).is_ok());
        ledger.latest_fully_signed_bill.serial = 2;
        assert!(validate_registry_progression(&progression, &binding, &ledger).is_err());
    }

    #[test]
    fn payer_authorization_binds_every_payment_and_replay_field() {
        let (left, _, network, binding, previous) = fixture();
        let recipient = binding.right_hub_address.clone();
        let mut request = HvmRegistryPaymentRequestV2::build_unsigned(
            &network, &binding, &previous, "op-1", "idem-1", &recipient, 100, 10, 20,
        )
        .unwrap();
        sign_request(&mut request, &binding, &previous, &left);
        request.validate_against(&binding, &previous, 11).unwrap();

        type Mutation = Box<dyn Fn(&mut HvmRegistryPaymentRequestV2)>;
        let mutations: Vec<Mutation> = vec![
            Box::new(|value| value.operation_id.push('x')),
            Box::new(|value| value.idempotency_key.push('x')),
            Box::new(|value| value.network_binding.node_profile_id.push('x')),
            Box::new(|value| value.binding_commitment = "aa".repeat(32)),
            Box::new(|value| value.previous_bill_commitment = "bb".repeat(32)),
            Box::new(|value| value.unsigned_bill_hash = "cc".repeat(32)),
            Box::new(|value| value.payer.push('x')),
            Box::new(|value| value.recipient.push('x')),
            Box::new(|value| value.amount_zhu += 1),
            Box::new(|value| value.network_fee_zhu = 1),
            Box::new(|value| value.wallet_fee_zhu = 1),
            Box::new(|value| value.hub_fee_zhu = 1),
            Box::new(|value| value.total_debit_zhu += 1),
            Box::new(|value| value.proposed_bill.left_balance_zhu -= 1),
            Box::new(|value| value.created_unix += 1),
            Box::new(|value| value.expires_unix += 1),
            Box::new(|value| {
                value
                    .payer_authorization_signature_hex
                    .replace_range(0..2, "00")
            }),
        ];
        for mutate in mutations {
            let mut changed = request.clone();
            mutate(&mut changed);
            assert!(changed.validate_against(&binding, &previous, 11).is_err());
        }

        let mut changed_binding = binding.clone();
        changed_binding.channel_id = "dd".repeat(16);
        assert!(
            request
                .validate_against(&changed_binding, &previous, 11)
                .is_err()
        );
    }

    #[test]
    fn payer_authorization_rejects_missing_wrong_key_and_changed_previous_bill() {
        let (left, hub, network, binding, previous) = fixture();
        let recipient = binding.right_hub_address.clone();
        let mut request = HvmRegistryPaymentRequestV2::build_unsigned(
            &network, &binding, &previous, "op-1", "idem-1", &recipient, 100, 10, 20,
        )
        .unwrap();
        let bill_hash = request.proposed_bill.signing_hash(&binding).unwrap();
        request.proposed_bill.left_signature_hex =
            hex::encode(Sign::create_by(&left, &bill_hash).serialize());
        assert!(request.validate_against(&binding, &previous, 11).is_err());

        let authorization_hash = request
            .payer_authorization_hash(&binding, &previous)
            .unwrap();
        request.payer_authorization_signature_hex =
            hex::encode(Sign::create_by(&hub, &authorization_hash).serialize());
        assert!(request.validate_against(&binding, &previous, 11).is_err());

        request.payer_authorization_signature_hex =
            hex::encode(Sign::create_by(&left, &authorization_hash).serialize());
        let mut changed_previous = request.proposed_bill.clone();
        changed_previous.hub_signature_hex.clear();
        let changed_hash = changed_previous.signing_hash(&binding).unwrap();
        changed_previous.hub_signature_hex =
            hex::encode(Sign::create_by(&hub, &changed_hash).serialize());
        assert!(
            request
                .validate_against(&binding, &changed_previous, 11)
                .is_err()
        );
    }

    #[test]
    fn payment_expiry_is_exact_and_never_exceeds_five_minutes() {
        let (left, _, network, binding, previous) = fixture();
        let recipient = binding.right_hub_address.clone();
        assert!(
            HvmRegistryPaymentRequestV2::build_unsigned(
                &network,
                &binding,
                &previous,
                "op-too-long",
                "idem-too-long",
                &recipient,
                100,
                10,
                311,
            )
            .is_err()
        );
        let mut request = HvmRegistryPaymentRequestV2::build_unsigned(
            &network, &binding, &previous, "op-1", "idem-1", &recipient, 100, 10, 310,
        )
        .unwrap();
        sign_request(&mut request, &binding, &previous, &left);
        assert!(request.validate_against(&binding, &previous, 309).is_ok());
        assert!(request.validate_against(&binding, &previous, 310).is_err());
    }
}

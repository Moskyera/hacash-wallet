//! Separate, durable payment progression for the HPAY HVM settlement profile.
//! Native ChannelPay ledgers never enter this module.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{HubError, HubResult};
use crate::hvm_channel::{HVM_CHANNEL_BILL_SCHEMA, HvmChannelBillV1, HvmChannelBindingV1};

pub const HVM_PAYMENT_REQUEST_SCHEMA: &str = "hpay-hvm-payment-request/1";
pub const HVM_PAYMENT_STATUS_SCHEMA: &str = "hpay-hvm-payment-status/1";
pub const HVM_CHANNEL_STATUS_SCHEMA: &str = "hpay-hvm-channel-status/1";
pub const HVM_COSIGNED_BILL_SCHEMA: &str = "hpay-hvm-cosigned-bill/1";

/// What the per-channel V1 co-sign route answers with: the bill, and the
/// witness receipts that authorised it.
///
/// The reasoning is the same as for the registry profile - see
/// [`HvmRegistryCosignedBillV2`] - and it applies here for the same reason the
/// anchor covers this path at all: this profile reaches the signing key exactly
/// as the registry profile does, so a design that carried receipts only on V2
/// would leave V1 fully exposed.
///
/// [`HvmRegistryCosignedBillV2`]: crate::hvm_registry_ledger::HvmRegistryCosignedBillV2
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HvmCosignedBillV1 {
    pub schema: String,
    pub bill: HvmChannelBillV1,
    #[serde(default)]
    pub anchor_receipts: Vec<crate::rollback_anchor::SignedHubWitnessReceiptV1>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HvmPaymentStatusV1 {
    pub schema: String,
    pub operation_id: String,
    pub request_commitment: String,
    pub status: String,
    pub request: HvmPaymentRequestV1,
    pub fully_signed_bill: Option<HvmChannelBillV1>,
    /// The receipts for `fully_signed_bill`, for the crash window between the
    /// Hub signing and the wallet persisting.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub anchor_receipts: Vec<crate::rollback_anchor::SignedHubWitnessReceiptV1>,
    pub updated_unix: u64,
    pub recovery_required: bool,
}

/// Public, read-only evidence for one exact activated HVM channel.
///
/// It contains only on-chain/public channel material and signatures. A wallet
/// must still verify the recovery bundle cryptographically and query its pinned
/// full node for a fresh 18-lease runtime snapshot before any key use.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HvmChannelStatusV1 {
    pub schema: String,
    pub binding_commitment: String,
    pub recovery_bundle: crate::hvm_channel::HvmChannelRecoveryBundleV1,
    pub activation_snapshot_commitment: String,
    pub minimum_required_live_blocks: u64,
    pub minimum_required_recover_blocks: u64,
    pub latest_fully_signed_bill: HvmChannelBillV1,
    /// The witness receipts that authorised `latest_fully_signed_bill`, for
    /// the crash window between the Hub signing and the wallet persisting.
    /// Empty and skipped on an unanchored Hub.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub latest_anchor_receipts: Vec<crate::rollback_anchor::SignedHubWitnessReceiptV1>,
    pub activated_unix: u64,
    pub updated_unix: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HvmPaymentRequestV1 {
    pub schema: String,
    pub operation_id: String,
    pub idempotency_key: String,
    pub binding_commitment: String,
    pub payer: String,
    pub recipient: String,
    pub amount_zhu: u64,
    pub hub_fee_zhu: u64,
    pub proposed_bill: HvmChannelBillV1,
    pub created_unix: u64,
    pub expires_unix: u64,
}

impl HvmPaymentRequestV1 {
    /// Construct the exact unsigned next fee-free HVM ledger transition.
    ///
    /// This helper never receives or touches a key. A restricted wallet signer
    /// must compare the complete binding and approved intent, sign only the
    /// returned bill hash, attach the left signature and call
    /// [`Self::validate_against`] before any network request is persisted.
    #[allow(clippy::too_many_arguments)]
    pub fn build_unsigned(
        binding: &HvmChannelBindingV1,
        previous: &HvmChannelBillV1,
        operation_id: &str,
        idempotency_key: &str,
        recipient: &str,
        amount_zhu: u64,
        created_unix: u64,
        expires_unix: u64,
    ) -> HubResult<Self> {
        binding.validate()?;
        previous.validate_fully_signed(binding)?;
        let left_balance_zhu = previous
            .left_balance_zhu
            .checked_sub(amount_zhu)
            .ok_or_else(|| {
                HubError::Payment("HVM payment exceeds the current left balance".into())
            })?;
        let right_balance_zhu = previous
            .right_balance_zhu
            .checked_add(amount_zhu)
            .ok_or_else(|| HubError::Payment("HVM payment balance overflow".into()))?;
        let binding_commitment = binding.commitment()?;
        let request = Self {
            schema: HVM_PAYMENT_REQUEST_SCHEMA.to_owned(),
            operation_id: operation_id.to_owned(),
            idempotency_key: idempotency_key.to_owned(),
            binding_commitment: binding_commitment.clone(),
            payer: binding.left_address.clone(),
            recipient: recipient.to_owned(),
            amount_zhu,
            hub_fee_zhu: 0,
            proposed_bill: HvmChannelBillV1 {
                schema: HVM_CHANNEL_BILL_SCHEMA.to_owned(),
                binding_commitment,
                serial: previous
                    .serial
                    .checked_add(1)
                    .ok_or_else(|| HubError::Payment("HVM bill serial overflow".into()))?,
                left_balance_zhu,
                right_balance_zhu,
                left_signature_hex: String::new(),
                right_signature_hex: String::new(),
            },
            created_unix,
            expires_unix,
        };
        request.validate_unsigned_against(binding, previous, created_unix)?;
        Ok(request)
    }

    /// Validate a pre-sign request. Both signature slots must still be empty.
    pub fn validate_unsigned_against(
        &self,
        binding: &HvmChannelBindingV1,
        previous: &HvmChannelBillV1,
        now_unix: u64,
    ) -> HubResult<()> {
        self.validate_transition_against(binding, previous, now_unix)?;
        if !self.proposed_bill.left_signature_hex.is_empty()
            || !self.proposed_bill.right_signature_hex.is_empty()
        {
            return Err(HubError::Payment(
                "unsigned HVM payment request already contains a signature".into(),
            ));
        }
        Ok(())
    }

    pub fn validate_against(
        &self,
        binding: &HvmChannelBindingV1,
        previous: &HvmChannelBillV1,
        now_unix: u64,
    ) -> HubResult<()> {
        self.validate_transition_against(binding, previous, now_unix)?;
        self.proposed_bill.validate_left_signed(binding)
    }

    fn validate_transition_against(
        &self,
        binding: &HvmChannelBindingV1,
        previous: &HvmChannelBillV1,
        now_unix: u64,
    ) -> HubResult<()> {
        if self.schema != HVM_PAYMENT_REQUEST_SCHEMA
            || self.operation_id.trim().is_empty()
            || self.idempotency_key.trim().is_empty()
            || self.binding_commitment != binding.commitment()?
            || self.payer != binding.left_address
            || self.recipient.trim().is_empty()
            || self.amount_zhu == 0
            || self.hub_fee_zhu != 0
            || self.created_unix > now_unix
            || now_unix >= self.expires_unix
        {
            return Err(HubError::Payment(
                "HVM payment request identity, expiry or fee policy is invalid".into(),
            ));
        }
        previous.validate_fully_signed(binding)?;
        self.proposed_bill.signing_hash(binding)?;
        let expected_left_balance = previous
            .left_balance_zhu
            .checked_sub(self.amount_zhu)
            .ok_or_else(|| {
                HubError::Payment("HVM payment exceeds the current left balance".into())
            })?;
        let expected_right_balance = previous
            .right_balance_zhu
            .checked_add(self.amount_zhu)
            .ok_or_else(|| HubError::Payment("HVM payment balance overflow".into()))?;
        if !self.proposed_bill.right_signature_hex.is_empty()
            || self.proposed_bill.serial != previous.serial.checked_add(1).unwrap_or_default()
            || self.proposed_bill.left_balance_zhu != expected_left_balance
            || self.proposed_bill.right_balance_zhu != expected_right_balance
        {
            return Err(HubError::Payment(
                "HVM payment bill is not the exact next fee-free ledger transition".into(),
            ));
        }
        Ok(())
    }

    pub fn commitment(&self) -> HubResult<String> {
        let bytes = serde_json::to_vec(self)
            .map_err(|error| HubError::State(format!("HVM request encode failed: {error}")))?;
        Ok(hex::encode(Sha256::digest(bytes)))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum HvmBillProgressionStatus {
    UserProposalPersisted,
    HubSignatureMayExist,
    FullySigned,
    RecoveryRequired,
}

impl HvmBillProgressionStatus {
    pub(crate) fn is_unresolved(&self) -> bool {
        !matches!(self, Self::FullySigned)
    }

    pub(crate) const fn as_str(&self) -> &'static str {
        match self {
            Self::UserProposalPersisted => "user_proposal_persisted",
            Self::HubSignatureMayExist => "hub_signature_may_exist",
            Self::FullySigned => "fully_signed",
            Self::RecoveryRequired => "recovery_required",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct PersistedHvmChannelLedger {
    pub binding_commitment: String,
    pub latest_fully_signed_bill: HvmChannelBillV1,
    /// Absent on every ledger written before the anchor carried its receipts
    /// onward, and skipped when empty, so the state commitment of an
    /// unanchored Hub is byte-identical to what it was.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub latest_anchor_receipts: Vec<crate::rollback_anchor::SignedHubWitnessReceiptV1>,
    pub updated_unix: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct PersistedHvmBillProgression {
    pub request: HvmPaymentRequestV1,
    pub request_commitment: String,
    pub previous_bill: HvmChannelBillV1,
    pub fully_signed_bill: Option<HvmChannelBillV1>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub anchor_receipts: Vec<crate::rollback_anchor::SignedHubWitnessReceiptV1>,
    pub status: HvmBillProgressionStatus,
    pub observed_height_before_signing: Option<u64>,
    pub updated_unix: u64,
    pub last_error: Option<String>,
}

pub(crate) fn validate_progression(
    progression: &PersistedHvmBillProgression,
    binding: &HvmChannelBindingV1,
    ledger: &PersistedHvmChannelLedger,
) -> HubResult<()> {
    if progression.request_commitment != progression.request.commitment()?
        || progression.request.binding_commitment != ledger.binding_commitment
        || progression.previous_bill.binding_commitment != ledger.binding_commitment
    {
        return Err(HubError::State(
            "persisted HVM payment progression commitment is inconsistent".into(),
        ));
    }
    progression.previous_bill.validate_fully_signed(binding)?;
    progression
        .request
        .proposed_bill
        .validate_left_signed(binding)?;
    match progression.status {
        HvmBillProgressionStatus::UserProposalPersisted
        | HvmBillProgressionStatus::HubSignatureMayExist => {
            if progression.fully_signed_bill.is_some()
                || !progression
                    .request
                    .proposed_bill
                    .right_signature_hex
                    .is_empty()
                || ledger.latest_fully_signed_bill != progression.previous_bill
            {
                return Err(HubError::State(
                    "unresolved HVM progression changed its durable ledger base".into(),
                ));
            }
        }
        HvmBillProgressionStatus::FullySigned => {
            let signed = progression.fully_signed_bill.as_ref().ok_or_else(|| {
                HubError::State("completed HVM progression has no durable signed bill".into())
            })?;
            signed.validate_fully_signed(binding)?;
            if ledger.latest_fully_signed_bill != *signed {
                return Err(HubError::State(
                    "completed HVM progression is not the durable ledger head".into(),
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
    use field::{Address, Serialize as FieldSerialize, Sign};
    use sys::Account;
    use vm::ContractAddress;

    fn fixture() -> (Account, HvmChannelBindingV1, HvmChannelBillV1) {
        let left = Account::create_by("hpay-hvm-unsigned-builder-left").unwrap();
        let right = Account::create_by("hpay-hvm-unsigned-builder-right").unwrap();
        let binding = HvmChannelBindingV1 {
            schema: crate::hvm_channel::HVM_CHANNEL_BINDING_SCHEMA.into(),
            settlement_profile: crate::node::HPAY_CHANNEL_EXIT_SETTLEMENT_PROFILE.into(),
            network_mode: "mainnet".into(),
            chain_id: 0,
            network_instance_id: "11".repeat(32),
            contract_address: ContractAddress::from_unchecked(Address::create_contract([7; 20]))
                .to_readable(),
            deployment_tx_hash: "22".repeat(32),
            deployment_height: crate::node::HACASH_MAINNET_MIN_SAFE_HEIGHT,
            bytecode_sha3: crate::node::HPAY_CHANNEL_EXIT_BYTECODE_SHA3.into(),
            channel_id: "33".repeat(16),
            reuse_version: 1,
            left_address: left.readable().into(),
            right_hub_address: right.readable().into(),
            left_deposit_zhu: 100_000_000,
            right_hub_deposit_zhu: 0,
            challenge_blocks: 12,
        };
        let mut previous = HvmChannelBillV1 {
            schema: HVM_CHANNEL_BILL_SCHEMA.into(),
            binding_commitment: binding.commitment().unwrap(),
            serial: 1,
            left_balance_zhu: binding.left_deposit_zhu,
            right_balance_zhu: 0,
            left_signature_hex: String::new(),
            right_signature_hex: String::new(),
        };
        let hash = previous.signing_hash(&binding).unwrap();
        previous.left_signature_hex = hex::encode(Sign::create_by(&left, &hash).serialize());
        previous.right_signature_hex = hex::encode(Sign::create_by(&right, &hash).serialize());
        previous.validate_fully_signed(&binding).unwrap();
        (left, binding, previous)
    }

    #[test]
    fn unsigned_builder_creates_only_the_exact_next_fee_free_transition() {
        let (left, binding, previous) = fixture();
        let mut request = HvmPaymentRequestV1::build_unsigned(
            &binding,
            &previous,
            "operation-1",
            "idempotency-1",
            "provider.example",
            100_000,
            10,
            20,
        )
        .unwrap();
        request
            .validate_unsigned_against(&binding, &previous, 10)
            .unwrap();
        assert_eq!(request.hub_fee_zhu, 0);
        assert_eq!(request.proposed_bill.serial, 2);
        assert_eq!(request.proposed_bill.left_balance_zhu, 99_900_000);
        assert_eq!(request.proposed_bill.right_balance_zhu, 100_000);
        assert!(request.validate_against(&binding, &previous, 10).is_err());

        let hash = request.proposed_bill.signing_hash(&binding).unwrap();
        request.proposed_bill.left_signature_hex =
            hex::encode(Sign::create_by(&left, &hash).serialize());
        request.validate_against(&binding, &previous, 10).unwrap();
        assert!(
            request
                .validate_unsigned_against(&binding, &previous, 10)
                .is_err()
        );
    }

    #[test]
    fn unsigned_builder_and_validator_reject_policy_or_transition_mutation() {
        let (_, binding, previous) = fixture();
        for amount in [0, previous.left_balance_zhu + 1] {
            assert!(
                HvmPaymentRequestV1::build_unsigned(
                    &binding,
                    &previous,
                    "operation-2",
                    "idempotency-2",
                    "provider.example",
                    amount,
                    10,
                    20,
                )
                .is_err()
            );
        }
        assert!(
            HvmPaymentRequestV1::build_unsigned(
                &binding,
                &previous,
                "operation-2",
                "idempotency-2",
                "",
                1,
                10,
                20,
            )
            .is_err()
        );
        assert!(
            HvmPaymentRequestV1::build_unsigned(
                &binding,
                &previous,
                "operation-2",
                "idempotency-2",
                "provider.example",
                1,
                10,
                10,
            )
            .is_err()
        );

        let base = HvmPaymentRequestV1::build_unsigned(
            &binding,
            &previous,
            "operation-3",
            "idempotency-3",
            "provider.example",
            1,
            10,
            20,
        )
        .unwrap();
        let mut mutations = Vec::new();
        let mut changed = base.clone();
        changed.hub_fee_zhu = 1;
        mutations.push(changed);
        let mut changed = base.clone();
        changed.proposed_bill.serial += 1;
        mutations.push(changed);
        let mut changed = base.clone();
        changed.proposed_bill.left_balance_zhu -= 1;
        mutations.push(changed);
        let mut changed = base;
        changed.proposed_bill.right_signature_hex = "00".repeat(97);
        mutations.push(changed);
        for request in mutations {
            assert!(
                request
                    .validate_unsigned_against(&binding, &previous, 10)
                    .is_err()
            );
        }
    }
}

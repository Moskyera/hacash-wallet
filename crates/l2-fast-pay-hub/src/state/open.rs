use super::*;
use crate::l1_channel::{
    L1_CHANNEL_OPEN_SCHEMA, L1ChannelOpenRequest, L1ChannelOpenStatusResponse,
};
use crate::node::ChannelInfo;
use crate::storage::{L1ChannelOpenStatus, PersistedL1ChannelOpen};

const SUBMITTED_EXACT_RETRY_GRACE_SECONDS: u64 = 30;
const L1_OPEN_MIN_CONFIRMATIONS: u64 = 6;

pub(super) fn confirmed_open_has_finality_evidence(operation: &PersistedL1ChannelOpen) -> bool {
    operation.status == L1ChannelOpenStatus::Confirmed
        && operation
            .confirmed_block_height
            .is_some_and(|height| height > 0)
        && operation.observed_confirmations >= L1_OPEN_MIN_CONFIRMATIONS
        && terminal_transaction_evidence_is_valid(
            operation.signed_transaction_hex.as_deref(),
            operation.signed_transaction_commitment.as_deref(),
            Some(&operation.transaction_hash),
        )
}

impl HubState {
    pub async fn open_channel(
        &self,
        request: &L1ChannelOpenRequest,
    ) -> HubResult<L1ChannelOpenStatusResponse> {
        let _single_flight = self.open_recovery_lock.lock().await;
        let request_commitment = crate::l1_channel::request_commitment(request)?;
        if let Some(existing) = self.existing_l1_channel_open(request, &request_commitment)? {
            let live_network = self
                .node
                .capabilities()
                .await?
                .l1_channel_network_binding()?;
            crate::l1_channel::validate_channel_open(
                request,
                &self.hub_address,
                &live_network,
                self.mainnet_max_channel_funding_hac_zhu,
                existing.created_unix,
            )?;
            if existing.status.has_durable_signature() {
                {
                    let guard = self
                        .inner
                        .read()
                        .map_err(|_| HubError::State("state lock poisoned".into()))?;
                    self.ensure_l1_open_recovery_allowed(&guard, &existing.operation_id)?;
                }
                return self
                    .resume_channel_open_locked(&existing.operation_id)
                    .await;
            }
        }
        self.ensure_settlement_ready()?;
        let signed = self.cosign_channel_open_inner(request).await?;
        self.resume_channel_open_locked(&signed.operation_id).await
    }

    pub fn is_exact_existing_channel_open(
        &self,
        request: &L1ChannelOpenRequest,
    ) -> HubResult<bool> {
        let commitment = crate::l1_channel::request_commitment(request)?;
        let guard = self
            .inner
            .read()
            .map_err(|_| HubError::State("state lock poisoned".into()))?;
        let Some(_existing) =
            super::existing_l1_channel_open_from_state(&guard, request, &commitment)?
        else {
            return Ok(false);
        };
        Ok(true)
    }

    pub fn channel_open_status(
        &self,
        operation_id: &str,
    ) -> HubResult<L1ChannelOpenStatusResponse> {
        let operation = self.load_channel_open(operation_id)?;
        Ok(channel_open_status_response(&operation))
    }

    async fn resume_channel_open_locked(
        &self,
        operation_id: &str,
    ) -> HubResult<L1ChannelOpenStatusResponse> {
        let mut operation = self.load_channel_open(operation_id)?;
        if confirmed_open_has_finality_evidence(&operation) {
            return Ok(channel_open_status_response(&operation));
        }
        if operation.status == L1ChannelOpenStatus::Confirmed {
            self.recovery_required.store(true, Ordering::Release);
            return Err(HubError::State(
                "RecoveryRequired: legacy confirmed channel-open lacks exact transaction finality evidence"
                    .into(),
            ));
        }
        if !operation.status.has_durable_signature() {
            return Err(HubError::State(
                "channel-open has no durable Hub signature to submit".into(),
            ));
        }
        let expected_network = persisted_open_network_binding(&operation);
        let live_network = self
            .node
            .capabilities()
            .await
            .and_then(|capabilities| capabilities.l1_channel_network_binding());
        if live_network.as_ref().ok() != Some(&expected_network)
            || expected_network.validate().is_err()
        {
            let operation = self.mark_open_recovery_required(
                operation,
                "fullnode network identity differs from the durable channel-open binding".into(),
            )?;
            return Ok(channel_open_status_response(&operation));
        }

        match self.node.query_channel(&operation.channel_id).await {
            Ok(channel) if exact_open_channel_matches(&channel, &operation, &self.hub_address)? => {
                return self.reconcile_open_channel(operation, &channel).await;
            }
            Ok(_) => {
                let operation = self.mark_open_recovery_required(
                    operation,
                    "fullnode returned a different channel incarnation".into(),
                )?;
                return Ok(channel_open_status_response(&operation));
            }
            Err(HubError::NotFound(_))
                if operation.reuse_version == 1
                    && operation.confirmed_block_height.is_none()
                    && operation.observed_confirmations == 0 => {}
            Err(HubError::NotFound(_)) => {
                let operation = self.mark_open_recovery_required(
                    operation,
                    "fullnode no longer proves the previously observed channel-open; possible chain reorganization"
                        .into(),
                )?;
                return Ok(channel_open_status_response(&operation));
            }
            Err(error) => {
                let operation = self.mark_open_recovery_required(operation, error.to_string())?;
                return Ok(channel_open_status_response(&operation));
            }
        }

        if operation.status == L1ChannelOpenStatus::Submitted
            && !submitted_exact_retry_due(operation.updated_unix, crate::node::now_unix())
        {
            return Ok(channel_open_status_response(&operation));
        }

        let required_zhu = u128::from(operation.user_deposit_zhu)
            .checked_add(u128::from(operation.network_fee_zhu))
            .ok_or_else(|| HubError::Payment("channel-open funding requirement overflow".into()))?;
        let available_zhu = self.node.query_balance_zhu(&operation.user_address).await?;
        if available_zhu < required_zhu {
            let operation = self.mark_open_recovery_required(
                operation,
                format!(
                    "channel-open broadcast requires {required_zhu} zhu, available {available_zhu} zhu"
                ),
            )?;
            return Ok(channel_open_status_response(&operation));
        }

        let signed_hex = operation.signed_transaction_hex.clone().ok_or_else(|| {
            HubError::State(
                "RecoveryRequired: a Hub signature may exist but exact open bytes are missing"
                    .into(),
            )
        })?;
        let live_before_submit = self
            .node
            .capabilities()
            .await
            .and_then(|capabilities| capabilities.l1_channel_network_binding());
        if live_before_submit.as_ref().ok() != Some(&expected_network) {
            let operation = self.mark_open_recovery_required(
                operation,
                "fullnode network identity changed before channel-open broadcast".into(),
            )?;
            return Ok(channel_open_status_response(&operation));
        }
        if operation.status != L1ChannelOpenStatus::SubmissionStarted {
            operation = self.transition_open_status(
                operation,
                L1ChannelOpenStatus::SubmissionStarted,
                JournalPhase::L1OpenSubmissionStarted,
                None,
            )?;
        }
        let transaction_hash = operation.transaction_hash.clone();
        match self
            .node
            .submit_transaction_bound(&signed_hex, &transaction_hash, &expected_network)
            .await
        {
            Ok(node_hash) if node_hash.eq_ignore_ascii_case(&transaction_hash) => {
                operation = self.transition_open_status(
                    operation,
                    L1ChannelOpenStatus::Submitted,
                    JournalPhase::L1OpenSubmitted,
                    None,
                )?;
            }
            Ok(_) => {
                let operation = self.mark_open_recovery_required(
                    operation,
                    "fullnode acknowledged a different channel-open transaction".into(),
                )?;
                return Ok(channel_open_status_response(&operation));
            }
            Err(error) => match self.node.query_channel(&operation.channel_id).await {
                Ok(channel)
                    if exact_open_channel_matches(&channel, &operation, &self.hub_address)? =>
                {
                    return self.reconcile_open_channel(operation, &channel).await;
                }
                _ => {
                    let operation =
                        self.mark_open_recovery_required(operation, error.to_string())?;
                    return Ok(channel_open_status_response(&operation));
                }
            },
        }

        match self.node.query_channel(&operation.channel_id).await {
            Ok(channel) if exact_open_channel_matches(&channel, &operation, &self.hub_address)? => {
                self.reconcile_open_channel(operation, &channel).await
            }
            Ok(_) => {
                let operation = self.mark_open_recovery_required(
                    operation,
                    "submitted transaction produced a different channel incarnation".into(),
                )?;
                Ok(channel_open_status_response(&operation))
            }
            Err(HubError::NotFound(_)) => Ok(channel_open_status_response(&operation)),
            Err(_) => Ok(channel_open_status_response(&operation)),
        }
    }

    async fn reconcile_open_channel(
        &self,
        mut operation: PersistedL1ChannelOpen,
        channel: &ChannelInfo,
    ) -> HubResult<L1ChannelOpenStatusResponse> {
        let observation = match self
            .node
            .query_transaction(&operation.transaction_hash)
            .await?
        {
            Some(observation) => observation,
            None if operation.confirmed_block_height.is_none()
                && operation.observed_confirmations == 0 =>
            {
                return Ok(channel_open_status_response(&operation));
            }
            None => {
                let operation = self.mark_open_recovery_required(
                    operation,
                    "previously observed channel-open transaction disappeared; possible chain reorganization"
                        .into(),
                )?;
                return Ok(channel_open_status_response(&operation));
            }
        };
        if observation.pending {
            if operation.confirmed_block_height.is_some() {
                let operation = self.mark_open_recovery_required(
                    operation,
                    "confirmed channel-open transaction returned to pending state".into(),
                )?;
                return Ok(channel_open_status_response(&operation));
            }
            return Ok(channel_open_status_response(&operation));
        }
        let signed_hex = operation.signed_transaction_hex.as_deref().ok_or_else(|| {
            HubError::State("RecoveryRequired: exact signed channel-open bytes are missing".into())
        })?;
        if !observation.body_hex.eq_ignore_ascii_case(signed_hex) {
            let operation = self.mark_open_recovery_required(
                operation,
                "mined channel-open body differs from the durable signed bytes".into(),
            )?;
            return Ok(channel_open_status_response(&operation));
        }
        if observation.block_height != Some(channel.open_height) {
            let operation = self.mark_open_recovery_required(
                operation,
                "channel open height differs from the exact transaction inclusion height".into(),
            )?;
            return Ok(channel_open_status_response(&operation));
        }
        operation.confirmed_block_height = observation.block_height;
        operation.observed_confirmations = observation.confirmations;
        if operation.observed_confirmations < L1_OPEN_MIN_CONFIRMATIONS {
            if !matches!(
                operation.status,
                L1ChannelOpenStatus::SubmissionStarted
                    | L1ChannelOpenStatus::Submitted
                    | L1ChannelOpenStatus::RecoveryRequired
            ) {
                let operation = self.mark_open_recovery_required(
                    operation,
                    "channel-open inclusion appeared before a durable submission marker".into(),
                )?;
                return Ok(channel_open_status_response(&operation));
            }
            let operation = self.transition_open_status(
                operation,
                L1ChannelOpenStatus::Submitted,
                JournalPhase::L1OpenSubmitted,
                None,
            )?;
            return Ok(channel_open_status_response(&operation));
        }
        self.confirm_channel_open(operation)
    }

    fn confirm_channel_open(
        &self,
        operation: PersistedL1ChannelOpen,
    ) -> HubResult<L1ChannelOpenStatusResponse> {
        if operation.confirmed_block_height.is_none()
            || operation.observed_confirmations < L1_OPEN_MIN_CONFIRMATIONS
        {
            return Err(HubError::State(
                "channel-open cannot be confirmed without exact transaction finality evidence"
                    .into(),
            ));
        }
        let mut guard = self
            .inner
            .write()
            .map_err(|_| HubError::State("state lock poisoned".into()))?;
        let mut current = guard
            .l1_channel_opens
            .get(&operation.operation_id)
            .cloned()
            .ok_or_else(|| HubError::State("durable channel-open operation disappeared".into()))?;
        if current.request_commitment != operation.request_commitment {
            return Err(HubError::State(
                "RecoveryRequired: channel-open operation changed before confirmation".into(),
            ));
        }
        if current.status == L1ChannelOpenStatus::Confirmed {
            return Ok(channel_open_status_response(&current));
        }
        if !can_transition_open_status(&current.status, &L1ChannelOpenStatus::Confirmed) {
            return Err(HubError::State(format!(
                "RecoveryRequired: invalid channel-open transition {:?} -> confirmed",
                current.status
            )));
        }
        current.confirmed_block_height = operation.confirmed_block_height;
        current.observed_confirmations = operation.observed_confirmations;
        current.status = L1ChannelOpenStatus::Confirmed;
        current.updated_unix = crate::node::now_unix();
        current.last_error = None;
        let initial_ledger = ChannelLedger {
            left_balance_mei: HacAmount::from_millimeis(
                current.user_deposit_zhu / crate::readiness::ZHU_PER_MILLIMEI,
            ),
            right_balance_mei: HacAmount::ZERO,
            bill_auto_number: 0,
        };
        let mut next = guard.clone();
        if let Some(existing) = next.channels.get(&current.channel_id) {
            if existing != &initial_ledger {
                return Err(HubError::State(
                    "RecoveryRequired: confirmed channel-open ledger anchor differs".into(),
                ));
            }
        } else {
            next.channels
                .insert(current.channel_id.clone(), initial_ledger);
        }
        next.l1_channel_opens
            .insert(current.operation_id.clone(), current.clone());
        self.commit_l1_channel_open_transition(
            &mut guard,
            next,
            &current,
            JournalPhase::L1OpenConfirmed,
        )?;
        Ok(channel_open_status_response(&current))
    }

    fn transition_open_status(
        &self,
        operation: PersistedL1ChannelOpen,
        status: L1ChannelOpenStatus,
        phase: JournalPhase,
        last_error: Option<String>,
    ) -> HubResult<PersistedL1ChannelOpen> {
        let mut guard = self
            .inner
            .write()
            .map_err(|_| HubError::State("state lock poisoned".into()))?;
        let mut current = guard
            .l1_channel_opens
            .get(&operation.operation_id)
            .cloned()
            .ok_or_else(|| HubError::State("durable channel-open operation disappeared".into()))?;
        if current.request_commitment != operation.request_commitment {
            return Err(HubError::State(
                "RecoveryRequired: channel-open operation changed".into(),
            ));
        }
        if current.status == L1ChannelOpenStatus::Confirmed {
            return Ok(current);
        }
        if !can_transition_open_status(&current.status, &status) {
            return Err(HubError::State(format!(
                "RecoveryRequired: invalid channel-open transition {:?} -> {:?}",
                current.status, status
            )));
        }
        let confirmed_block_height = operation.confirmed_block_height;
        let observed_confirmations = operation.observed_confirmations;
        if confirmed_block_height.is_some() {
            current.confirmed_block_height = confirmed_block_height;
            current.observed_confirmations = observed_confirmations;
        }
        current.status = status;
        current.updated_unix = crate::node::now_unix();
        current.last_error = last_error;
        let mut next = guard.clone();
        next.l1_channel_opens
            .insert(current.operation_id.clone(), current.clone());
        self.commit_l1_channel_open_transition(&mut guard, next, &current, phase)?;
        Ok(current)
    }

    fn mark_open_recovery_required(
        &self,
        operation: PersistedL1ChannelOpen,
        error: String,
    ) -> HubResult<PersistedL1ChannelOpen> {
        self.transition_open_status(
            operation,
            L1ChannelOpenStatus::RecoveryRequired,
            JournalPhase::L1OpenRecoveryRequired,
            Some(error),
        )
    }

    fn load_channel_open(&self, operation_id: &str) -> HubResult<PersistedL1ChannelOpen> {
        self.inner
            .read()
            .map_err(|_| HubError::State("state lock poisoned".into()))?
            .l1_channel_opens
            .get(operation_id)
            .cloned()
            .ok_or_else(|| HubError::NotFound(format!("channel open {operation_id}")))
    }
}

fn persisted_open_network_binding(
    operation: &PersistedL1ChannelOpen,
) -> crate::l1_channel::L1ChannelNetworkBinding {
    crate::l1_channel::L1ChannelNetworkBinding {
        network_kind: operation.network.clone(),
        chain_id: operation.chain_id,
        mainnet: operation.mainnet,
        block_1_hash: operation.block_1_hash.clone(),
        node_profile_id: operation.node_profile_id.clone(),
        network_instance_id: operation.network_instance_id.clone(),
        transaction_format_version: operation.transaction_format_version,
    }
}

const MAX_ACTIVE_CHANNEL_OPENS: usize = 64;
const MAX_ACTIVE_OPENS_PER_ADDRESS: usize = 1;

pub(super) fn require_new_open_admission(
    state: &HubPersistedState,
    user_address: &str,
) -> HubResult<()> {
    let active = state
        .l1_channel_opens
        .values()
        .filter(|operation| operation.status.reserves_admission());
    let mut global = 0usize;
    let mut for_address = 0usize;
    for operation in active {
        global = global.saturating_add(1);
        if operation.user_address == user_address {
            for_address = for_address.saturating_add(1);
        }
    }
    if global >= MAX_ACTIVE_CHANNEL_OPENS {
        return Err(HubError::Admission(
            "active channel-open capacity is temporarily exhausted".into(),
        ));
    }
    if for_address >= MAX_ACTIVE_OPENS_PER_ADDRESS {
        return Err(HubError::Admission(
            "this wallet already has an active channel-open operation".into(),
        ));
    }
    Ok(())
}
fn exact_open_channel_matches(
    channel: &ChannelInfo,
    operation: &PersistedL1ChannelOpen,
    hub_address: &str,
) -> HubResult<bool> {
    let left_zhu = crate::node::parse_fin_balance_zhu(&channel.left.hacash)?;
    let right_zhu = crate::node::parse_fin_balance_zhu(&channel.right.hacash)?;
    Ok(channel.id.eq_ignore_ascii_case(&operation.channel_id)
        && channel.is_open()
        && channel.open_height > 0
        && channel.close_height == 0
        && channel.reuse_version == operation.reuse_version
        && channel.challenging.is_none()
        && channel.left.address == operation.user_address
        && channel.right.address == hub_address
        && channel.left.satoshi == 0
        && channel.right.satoshi == 0
        && left_zhu == u128::from(operation.user_deposit_zhu)
        && right_zhu == 0)
}

fn can_transition_open_status(current: &L1ChannelOpenStatus, next: &L1ChannelOpenStatus) -> bool {
    use L1ChannelOpenStatus::*;
    match current {
        ValidatedBeforeSigning => {
            matches!(
                next,
                AbandonedUnsigned | SignatureMayExist | RecoveryRequired
            )
        }
        SignatureMayExist => matches!(next, Signed | RecoveryRequired),
        Signed => matches!(next, SubmissionStarted | RecoveryRequired),
        SubmissionStarted => matches!(next, Submitted | RecoveryRequired),
        Submitted => matches!(
            next,
            SubmissionStarted | Submitted | Confirmed | RecoveryRequired
        ),
        RecoveryRequired => matches!(
            next,
            SubmissionStarted | Submitted | Confirmed | RecoveryRequired
        ),
        Confirmed | AbandonedUnsigned => false,
    }
}

fn submitted_exact_retry_due(updated_unix: u64, now_unix: u64) -> bool {
    now_unix.saturating_sub(updated_unix) >= SUBMITTED_EXACT_RETRY_GRACE_SECONDS
}

fn channel_open_status_response(operation: &PersistedL1ChannelOpen) -> L1ChannelOpenStatusResponse {
    L1ChannelOpenStatusResponse {
        schema: L1_CHANNEL_OPEN_SCHEMA.into(),
        operation_id: operation.operation_id.clone(),
        channel_id: operation.channel_id.clone(),
        status: operation.status.public_name().into(),
        transaction_hash: operation
            .status
            .has_durable_signature()
            .then(|| operation.transaction_hash.clone()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn operation(
        index: usize,
        user_address: &str,
        status: L1ChannelOpenStatus,
    ) -> PersistedL1ChannelOpen {
        PersistedL1ChannelOpen {
            operation_id: format!("operation-{index}"),
            idempotency_key: format!("idempotency-{index}"),
            request_commitment: format!("request-{index}"),
            network: String::new(),
            chain_id: 0,
            mainnet: false,
            block_1_hash: String::new(),
            node_profile_id: String::new(),
            network_instance_id: String::new(),
            transaction_format_version: 0,
            channel_id: format!("channel-{index}"),
            reuse_version: 1,
            user_address: user_address.into(),
            user_deposit_zhu: 1,
            network_fee_zhu: 1,
            partial_transaction_hex: "00".into(),
            partial_transaction_commitment: format!("partial-{index}"),
            transaction_hash: format!("transaction-{index}"),
            signed_transaction_hex: None,
            signed_transaction_commitment: None,
            confirmed_block_height: None,
            observed_confirmations: 0,
            status,
            created_unix: 1,
            expires_unix: 2,
            updated_unix: 1,
            last_error: None,
        }
    }

    #[test]
    fn submitted_retry_has_a_bounded_grace_period() {
        assert!(!submitted_exact_retry_due(100, 129));
        assert!(submitted_exact_retry_due(100, 130));
    }

    #[test]
    fn one_wallet_cannot_reserve_two_unfinished_channel_opens() {
        let mut state = HubPersistedState::default();
        state.l1_channel_opens.insert(
            "operation-1".into(),
            operation(1, "wallet-address", L1ChannelOpenStatus::Signed),
        );
        assert!(matches!(
            require_new_open_admission(&state, "wallet-address"),
            Err(HubError::Admission(_))
        ));
        assert!(require_new_open_admission(&state, "different-address").is_ok());
    }

    #[test]
    fn proven_unsigned_abandoned_open_releases_active_capacity() {
        let mut state = HubPersistedState::default();
        state.l1_channel_opens.insert(
            "operation-1".into(),
            operation(1, "wallet-address", L1ChannelOpenStatus::AbandonedUnsigned),
        );
        assert!(require_new_open_admission(&state, "wallet-address").is_ok());
    }

    #[test]
    fn confirmed_open_releases_active_capacity() {
        let mut state = HubPersistedState::default();
        state.l1_channel_opens.insert(
            "operation-1".into(),
            operation(1, "wallet-address", L1ChannelOpenStatus::Confirmed),
        );
        assert!(require_new_open_admission(&state, "wallet-address").is_ok());
    }

    #[test]
    fn unfinished_operations_exhaust_global_active_capacity() {
        let mut state = HubPersistedState::default();
        for index in 0..MAX_ACTIVE_CHANNEL_OPENS {
            let address = format!("wallet-{index}");
            state.l1_channel_opens.insert(
                format!("operation-{index}"),
                operation(index, &address, L1ChannelOpenStatus::RecoveryRequired),
            );
        }
        assert!(matches!(
            require_new_open_admission(&state, "new-wallet"),
            Err(HubError::Admission(_))
        ));
    }

    #[test]
    fn terminal_history_never_exhausts_active_open_capacity() {
        let mut state = HubPersistedState::default();
        for index in 0..5_000 {
            let status = if index % 2 == 0 {
                L1ChannelOpenStatus::Confirmed
            } else {
                L1ChannelOpenStatus::AbandonedUnsigned
            };
            let address = format!("historical-wallet-{index}");
            state.l1_channel_opens.insert(
                format!("operation-{index}"),
                operation(index, &address, status),
            );
        }
        assert!(require_new_open_admission(&state, "new-wallet").is_ok());
    }

    #[test]
    fn terminal_history_does_not_hide_per_wallet_active_limit() {
        let mut state = HubPersistedState::default();
        for index in 0..5_000 {
            state.l1_channel_opens.insert(
                format!("operation-{index}"),
                operation(index, "wallet-address", L1ChannelOpenStatus::Confirmed),
            );
        }
        state.l1_channel_opens.insert(
            "active-operation".into(),
            operation(
                5_001,
                "wallet-address",
                L1ChannelOpenStatus::RecoveryRequired,
            ),
        );
        assert!(matches!(
            require_new_open_admission(&state, "wallet-address"),
            Err(HubError::Admission(_))
        ));
    }
}

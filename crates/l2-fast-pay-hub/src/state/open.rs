use super::*;
use crate::l1_channel::{
    L1_CHANNEL_OPEN_SCHEMA, L1ChannelOpenRequest, L1ChannelOpenStatusResponse,
};
use crate::node::ChannelInfo;
use crate::storage::{L1ChannelOpenStatus, PersistedL1ChannelOpen};

const SUBMITTED_EXACT_RETRY_GRACE_SECONDS: u64 = 30;
const L1_OPEN_MIN_CONFIRMATIONS: u64 = 6;

/// How many blocks the chain must produce, without including a broadcast
/// channel-open, before the Hub stops holding admission budget for it.
///
/// Blocks and not seconds, deliberately. "This should have been mined by now"
/// is a statement about the chain having had opportunities, and a stalled or
/// unreachable chain has given none. A wall clock cannot say that: it would
/// call an open dead during exactly the outage that stopped it from being
/// included. Counting blocks makes the rule self-correcting - no blocks, no
/// retirements - and it is the same unit the rest of this file already judges
/// finality in.
///
/// 288 blocks is a day at this chain's five minute target. This crate's own
/// scheduler already calls fifteen minutes of silence far past normal
/// (`HVM_SUBMITTED_STALE_SECONDS`); this is ninety-six times that, and every
/// resume or recovery marker on an open re-arms it from the new height.
pub(crate) const OPEN_UNMINED_RETIREMENT_BLOCKS: u64 = 288;

/// The same rule for records written before `broadcast_height` existed.
///
/// Those carry no height to count from, so seconds are the only measure left.
/// It is a strictly weaker rule and it applies to strictly older records - the
/// owner's five day old open among them - which is the whole reason it is here
/// rather than being tightened away.
///
/// Measured from the *later* of creation and the last transition, so an open
/// that anything is still working on is never a candidate.
pub(crate) const OPEN_UNMINED_RETIREMENT_SECONDS: u64 = 86_400;

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

        // Reached only when the chain has just been asked and still does not
        // have this channel. A retired open is one the Hub already decided to
        // stop carrying, so it does not go back on the wire here; the arms
        // above are what take it back, and only on chain evidence.
        if operation.status.is_retired_unmined() {
            return Ok(channel_open_status_response(&operation));
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
        let capabilities_before_submit = self.node.capabilities().await.ok();
        let live_before_submit = capabilities_before_submit
            .as_ref()
            .and_then(|capabilities| capabilities.l1_channel_network_binding().ok());
        if live_before_submit.as_ref() != Some(&expected_network) {
            let operation = self.mark_open_recovery_required(
                operation,
                "fullnode network identity changed before channel-open broadcast".into(),
            )?;
            return Ok(channel_open_status_response(&operation));
        }
        // The height these bytes are about to go on the wire at. Every
        // broadcast attempt re-arms it, so the retirement rule always counts
        // blocks from the most recent chance the chain was given.
        operation.broadcast_height = capabilities_before_submit
            .as_ref()
            .map(|capabilities| capabilities.height);
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
        // Carried the same way, and only forward: the caller sets it
        // immediately before putting bytes on the wire, and a transition that
        // has nothing to say about a broadcast leaves the recorded height
        // alone rather than clearing it.
        if operation.broadcast_height.is_some() {
            current.broadcast_height = operation.broadcast_height;
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

    /// Release admission budget held by channel-opens that the chain says do
    /// not exist.
    ///
    /// **The defect this exists for.** A channel-open reserves its whole
    /// deposit against the pilot aggregate TVL cap from the moment it is
    /// created until it reaches `Confirmed`. Nothing in the tree moved a
    /// signed-and-broadcast-but-never-mined open anywhere else, so one
    /// transaction that failed to be included held its deposit against the cap
    /// forever. On a Hub whose cap is one channel wide, that is one broadcast
    /// away from never opening another channel, and the Hub reports itself
    /// perfectly healthy the whole time.
    ///
    /// **What it takes to retire one.** Every conjunct is required, and any
    /// unavailable answer leaves the reservation standing:
    ///
    /// 1. the operation reserves admission and is not `Confirmed`;
    /// 2. the Hub has never recorded inclusion evidence for it - no confirmed
    ///    block height and no observed confirmations;
    /// 3. the chain has produced [`OPEN_UNMINED_RETIREMENT_BLOCKS`] blocks
    ///    since these bytes went on the wire and included none of them - or,
    ///    for a record written before that height was captured, it has been
    ///    dead still for [`OPEN_UNMINED_RETIREMENT_SECONDS`], measured from the
    ///    later of its creation and its last transition;
    /// 4. the fullnode answers `NotFound` for its channel ID, so no channel
    ///    exists to reconcile against;
    /// 5. the fullnode has never heard of its transaction hash - not in a
    ///    block, and not pending in a mempool.
    ///
    /// A fullnode that errors, or that answers anything other than those two
    /// absences, retires nothing. Not knowing is not evidence.
    ///
    /// **Why releasing the budget is safe.** The reservation is a policy bound,
    /// not a solvency bound: the Hub's own deposit in a channel-open is exactly
    /// zero (`validate_channel_open` refuses any other), so nothing the Hub
    /// owns is at stake in the retired operation. What is at stake is the pilot
    /// cap being overshot if the retired bytes are somehow mined later. That is
    /// bounded by the retired deposit, it is detectable, and it is caught at
    /// the next decision point rather than never: the operation is kept,
    /// `has_durable_signature` stays true, and this sweep keeps asking the
    /// chain about it on every subsequent open. If the channel appears,
    /// `resume_channel_open_locked` reconciles it back into a real ledger.
    ///
    /// Weighed against that: today the failure mode is certain and permanent.
    pub(super) async fn retire_unmined_channel_opens(&self) -> HubResult<Vec<String>> {
        let now = crate::node::now_unix();
        // The tip the retirement is judged against. An unreachable fullnode
        // ends the sweep before a single reservation is touched, which is the
        // same rule as every other conjunct: not knowing is not evidence.
        let tip_height = self.node.capabilities().await?.height;
        let candidates: Vec<PersistedL1ChannelOpen> = {
            let guard = self
                .inner
                .read()
                .map_err(|_| HubError::State("state lock poisoned".into()))?;
            guard
                .l1_channel_opens
                .values()
                .filter(|operation| open_is_retirement_candidate(operation, now, tip_height))
                .cloned()
                .collect()
        };
        let mut retired = Vec::new();
        for operation in candidates {
            match self.node.query_channel(&operation.channel_id).await {
                Err(HubError::NotFound(_)) => {}
                _ => continue,
            }
            match self
                .node
                .query_transaction(&operation.transaction_hash)
                .await
            {
                Ok(None) => {}
                _ => continue,
            }
            let waited = match operation.broadcast_height {
                Some(broadcast_height) => format!(
                    "the chain has produced {} blocks since it was broadcast at height \
                     {broadcast_height} and included it in none of them",
                    tip_height.saturating_sub(broadcast_height)
                ),
                None => format!(
                    "it was broadcast {} seconds ago",
                    now.saturating_sub(open_last_progress_unix(&operation))
                ),
            };
            let reason = format!(
                "channel-open transaction {}: {waited}, the fullnode does not hold it pending \
                 either, and channel {} does not exist; the pilot admission budget it reserved \
                 ({} zhu) is released. The signed bytes are kept and still watched: if that \
                 transaction is ever included, this operation is taken back at the next \
                 channel-open.",
                operation.transaction_hash, operation.channel_id, operation.user_deposit_zhu
            );
            let operation_id = operation.operation_id.clone();
            match self.transition_open_status(
                operation,
                L1ChannelOpenStatus::AbandonedUnmined,
                JournalPhase::L1OpenAbandonedUnmined,
                Some(reason),
            ) {
                Ok(_) => retired.push(operation_id),
                // A concurrent transition won the write lock. The reservation
                // simply stands until the next sweep, which is the safe way to
                // lose this race.
                Err(_) => continue,
            }
        }
        Ok(retired)
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

/// The last moment anything happened to this open, as far as durable state can
/// tell. `updated_unix` defaults to zero on records written before it existed,
/// so creation is the floor.
fn open_last_progress_unix(operation: &PersistedL1ChannelOpen) -> u64 {
    operation.created_unix.max(operation.updated_unix)
}

/// Everything that can be decided about a retirement without asking the chain.
///
/// Kept pure and separate from the sweep so the boundary conditions can be
/// tested without a fullnode, and so the sweep never opens a socket for an
/// operation that was never eligible.
fn open_is_retirement_candidate(
    operation: &PersistedL1ChannelOpen,
    now: u64,
    tip_height: u64,
) -> bool {
    if !operation.status.reserves_admission() {
        return false;
    }
    // Only opens whose bytes are real and final. A `ValidatedBeforeSigning`
    // open is retired by `AbandonedUnsigned`, and a `SignatureMayExist` open is
    // the one case where the Hub does not know whether signed bytes exist at
    // all - that uncertainty is not something a chain absence resolves, so it
    // is deliberately left alone here.
    if !operation.status.has_durable_signature() {
        return false;
    }
    if operation.status == L1ChannelOpenStatus::Confirmed {
        return false;
    }
    // The Hub has seen this in a block before. That is a reorganisation
    // question, which `resume_channel_open_locked` already answers by latching
    // recovery, and never a retirement question.
    if operation.confirmed_block_height.is_some() || operation.observed_confirmations > 0 {
        return false;
    }
    match operation.broadcast_height {
        // The chain has had this many chances to include these bytes and took
        // none of them. A chain that produced no blocks retires nothing.
        Some(broadcast_height) => {
            tip_height.saturating_sub(broadcast_height) >= OPEN_UNMINED_RETIREMENT_BLOCKS
        }
        // Written before the height was recorded. Seconds are all there is.
        None => {
            now.saturating_sub(open_last_progress_unix(operation))
                >= OPEN_UNMINED_RETIREMENT_SECONDS
        }
    }
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
        Signed => matches!(
            next,
            SubmissionStarted | AbandonedUnmined | RecoveryRequired
        ),
        SubmissionStarted => matches!(next, Submitted | AbandonedUnmined | RecoveryRequired),
        Submitted => matches!(
            next,
            SubmissionStarted | Submitted | Confirmed | AbandonedUnmined | RecoveryRequired
        ),
        RecoveryRequired => matches!(
            next,
            SubmissionStarted | Submitted | Confirmed | AbandonedUnmined | RecoveryRequired
        ),
        // Retired, not buried. A retirement is a statement about the chain at
        // one instant - "these bytes are neither in a block nor in a mempool" -
        // and the chain is allowed to contradict it later. If it does, the
        // sweep must be able to take the operation back, which is why every
        // evidence-bearing status is still reachable from here. What is not
        // reachable is a fresh `SubmissionStarted`: the Hub gave these bytes up
        // and does not put them on the wire again. `Submitted` is reachable
        // only because that is the status an already-mined-but-unconfirmed
        // open is reconciled into, never because the Hub rebroadcast anything.
        AbandonedUnmined => matches!(next, Submitted | Confirmed | RecoveryRequired),
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
    use L1ChannelOpenStatus::*;

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
            broadcast_height: None,
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

    /// The owner's Aug 25 record, in the shape their durable state actually
    /// held it: `Submitted`, no inclusion evidence, and no `broadcast_height`,
    /// because the field did not exist when it was written. That record is the
    /// one this whole change exists to release, so the fallback rule is not an
    /// afterthought - it is the rule that has to fire for them.
    fn owners_record(broadcast_height: Option<u64>) -> PersistedL1ChannelOpen {
        let mut operation = operation(1, "1LCY6uQS3iNGy2mKSmhFVU2dHgBQLf74Fx", Submitted);
        operation.user_deposit_zhu = 20_000_000;
        operation.created_unix = 1_787_662_846;
        operation.updated_unix = 1_787_662_846;
        operation.broadcast_height = broadcast_height;
        operation
    }

    #[test]
    fn a_record_written_before_broadcast_height_existed_is_judged_in_seconds() {
        let operation = owners_record(None);
        let broadcast = operation.updated_unix;
        // The owner's own record was five days old.
        assert!(open_is_retirement_candidate(
            &operation,
            broadcast + OPEN_UNMINED_RETIREMENT_SECONDS,
            0
        ));
        assert!(!open_is_retirement_candidate(
            &operation,
            broadcast + OPEN_UNMINED_RETIREMENT_SECONDS - 1,
            0
        ));
        // No height is recorded, so no height can move the answer.
        assert!(!open_is_retirement_candidate(
            &operation,
            broadcast,
            u64::MAX
        ));
    }

    #[test]
    fn a_record_with_a_broadcast_height_is_judged_in_blocks_and_ignores_the_clock() {
        let operation = owners_record(Some(777_754));
        let far_future = operation.updated_unix + OPEN_UNMINED_RETIREMENT_SECONDS * 365;
        assert!(!open_is_retirement_candidate(
            &operation,
            far_future,
            777_754 + OPEN_UNMINED_RETIREMENT_BLOCKS - 1
        ));
        assert!(open_is_retirement_candidate(
            &operation,
            far_future,
            777_754 + OPEN_UNMINED_RETIREMENT_BLOCKS
        ));
        // A stalled chain retires nothing, however long the wall clock runs.
        // That is the whole reason the rule counts blocks.
        assert!(!open_is_retirement_candidate(
            &operation, far_future, 777_754
        ));
    }

    #[test]
    fn a_reorganisation_question_is_never_a_retirement_question() {
        let mut operation = owners_record(Some(777_754));
        operation.confirmed_block_height = Some(777_800);
        assert!(!open_is_retirement_candidate(
            &operation,
            u64::MAX,
            u64::MAX
        ));

        let mut operation = owners_record(Some(777_754));
        operation.observed_confirmations = 1;
        assert!(!open_is_retirement_candidate(
            &operation,
            u64::MAX,
            u64::MAX
        ));
    }

    #[test]
    fn only_an_open_whose_exact_bytes_exist_can_be_retired() {
        for status in [
            ValidatedBeforeSigning,
            AbandonedUnsigned,
            SignatureMayExist,
            Confirmed,
            AbandonedUnmined,
        ] {
            let mut operation = owners_record(Some(777_754));
            operation.status = status.clone();
            assert!(
                !open_is_retirement_candidate(&operation, u64::MAX, u64::MAX),
                "{status:?} must never be retired as unmined"
            );
        }
        for status in [Signed, SubmissionStarted, Submitted, RecoveryRequired] {
            let mut operation = owners_record(Some(777_754));
            operation.status = status.clone();
            assert!(
                open_is_retirement_candidate(&operation, u64::MAX, u64::MAX),
                "{status:?} holds budget for bytes that exist and must be retirable"
            );
        }
    }

    #[test]
    fn a_retired_open_stops_holding_admission_budget_and_keeps_its_signature() {
        assert!(!AbandonedUnmined.reserves_admission());
        assert!(AbandonedUnmined.has_durable_signature());
        assert!(AbandonedUnmined.is_retired_unmined());
        assert!(!Submitted.is_retired_unmined());
        assert_eq!(AbandonedUnmined.public_name(), "abandoned_unmined");
    }

    #[test]
    fn a_retirement_is_reversible_by_chain_evidence_but_never_by_the_hub() {
        assert!(can_transition_open_status(&Submitted, &AbandonedUnmined));
        assert!(can_transition_open_status(
            &RecoveryRequired,
            &AbandonedUnmined
        ));
        assert!(can_transition_open_status(&Signed, &AbandonedUnmined));
        assert!(can_transition_open_status(
            &SubmissionStarted,
            &AbandonedUnmined
        ));
        // Never from a state whose bytes are settled or never existed.
        assert!(!can_transition_open_status(&Confirmed, &AbandonedUnmined));
        assert!(!can_transition_open_status(
            &AbandonedUnsigned,
            &AbandonedUnmined
        ));
        assert!(!can_transition_open_status(
            &ValidatedBeforeSigning,
            &AbandonedUnmined
        ));
        assert!(!can_transition_open_status(
            &SignatureMayExist,
            &AbandonedUnmined
        ));
        // Out of retirement only on evidence, and never back onto the wire.
        assert!(can_transition_open_status(&AbandonedUnmined, &Confirmed));
        assert!(can_transition_open_status(&AbandonedUnmined, &Submitted));
        assert!(can_transition_open_status(
            &AbandonedUnmined,
            &RecoveryRequired
        ));
        assert!(!can_transition_open_status(
            &AbandonedUnmined,
            &SubmissionStarted
        ));
        assert!(!can_transition_open_status(
            &AbandonedUnmined,
            &AbandonedUnsigned
        ));
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

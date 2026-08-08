//! Trusted local-desktop administration for one explicit Agent Wallet.
//!
//! These methods are intentionally separate from the capability-scoped local
//! agent API. They still require the independent Agent Wallet to be unlocked
//! and never accept a Personal Wallet handle.

use std::collections::BTreeSet;

use crate::error::{AgentWalletError, AgentWalletResult};
use crate::journal::AgentJournalEventKind;
use crate::operation::{OperationStatus, PaymentOperationView};
use crate::policy::{AgentPolicy, AgentRecord, AgentStatus};
use crate::types::{AgentId, AgentWalletId};

use super::AgentWalletManager;

const MAX_POLICY_RECIPIENTS: usize = 256;

impl AgentWalletManager {
    pub fn list_agents_admin(
        &mut self,
        wallet_id: &AgentWalletId,
        now: u64,
    ) -> AgentWalletResult<Vec<AgentRecord>> {
        self.ensure_session_active(wallet_id, now)?;
        let session = self.session(wallet_id)?;
        let state =
            self.load_verified_state(wallet_id, &session.state_master, &session.journal_key)?;
        let mut agents: Vec<_> = state.agents.into_values().collect();
        agents.sort_by_key(|agent| (std::cmp::Reverse(agent.paired_at), agent.agent_id.clone()));
        Ok(agents)
    }

    pub fn agent_policy_admin(
        &mut self,
        wallet_id: &AgentWalletId,
        agent_id: &AgentId,
        now: u64,
    ) -> AgentWalletResult<AgentPolicy> {
        self.ensure_session_active(wallet_id, now)?;
        let session = self.session(wallet_id)?;
        let state =
            self.load_verified_state(wallet_id, &session.state_master, &session.journal_key)?;
        state
            .agents
            .get(agent_id.as_str())
            .map(|agent| agent.policy.clone())
            .ok_or(AgentWalletError::AgentNotPaired)
    }

    pub fn update_agent_policy_admin(
        &mut self,
        wallet_id: &AgentWalletId,
        agent_id: &AgentId,
        mut policy: AgentPolicy,
        now: u64,
    ) -> AgentWalletResult<AgentPolicy> {
        self.ensure_session_active(wallet_id, now)?;
        let session = self.session(wallet_id)?;
        let mut state =
            self.load_verified_state(wallet_id, &session.state_master, &session.journal_key)?;
        validate_policy(&policy, &state.network_mode)?;

        let next_policy_epoch = state
            .policy_epoch
            .checked_add(1)
            .ok_or(AgentWalletError::IntegerOverflow)?;
        let agent = state
            .agents
            .get_mut(agent_id.as_str())
            .ok_or(AgentWalletError::AgentNotPaired)?;
        if agent.status != AgentStatus::Active {
            return Err(AgentWalletError::AgentRevoked);
        }
        agent.authorization_epoch = agent
            .authorization_epoch
            .checked_add(1)
            .ok_or(AgentWalletError::IntegerOverflow)?;
        policy.policy_epoch = next_policy_epoch;
        agent.policy = policy.clone();
        state
            .pairing_completion_outbox
            .retain(|_, completion| completion.record().agent_id != *agent_id);
        super::cancel_pre_signing_operations(&mut state, None, "policy_changed")?;
        state.policy_epoch = next_policy_epoch;
        state.authenticated_sessions.clear();
        state.authentication_challenges.clear();
        state.updated_at = now;
        self.persist_event(
            &mut state,
            &session.state_master,
            &session.journal_key,
            AgentJournalEventKind::PolicyChanged,
            None,
            Some(agent_id.as_str().as_bytes()),
            now,
        )?;
        Ok(policy)
    }

    pub fn list_operations_admin(
        &mut self,
        wallet_id: &AgentWalletId,
        now: u64,
    ) -> AgentWalletResult<Vec<PaymentOperationView>> {
        self.ensure_session_active(wallet_id, now)?;
        let session = self.session(wallet_id)?;
        let mut state =
            self.load_verified_state(wallet_id, &session.state_master, &session.journal_key)?;
        self.sweep_expired_pre_signing_operations(
            &mut state,
            &session.state_master,
            &session.journal_key,
            now,
        )?;
        let mut operations: Vec<_> = state
            .operations
            .values()
            .map(super::AgentOperation::view)
            .collect();
        operations.sort_by_key(|operation| {
            (
                std::cmp::Reverse(operation.created_at),
                operation.operation_id.clone(),
            )
        });
        Ok(operations)
    }

    pub fn list_pending_approvals_admin(
        &mut self,
        wallet_id: &AgentWalletId,
        now: u64,
    ) -> AgentWalletResult<Vec<PaymentOperationView>> {
        Ok(self
            .list_operations_admin(wallet_id, now)?
            .into_iter()
            .filter(|operation| {
                operation.status == OperationStatus::ApprovalRequested && operation.expires_at > now
            })
            .collect())
    }
}

fn validate_policy(policy: &AgentPolicy, network_mode: &str) -> AgentWalletResult<()> {
    if policy.allowed_recipients.len() > MAX_POLICY_RECIPIENTS
        || policy.blocked_recipients.len() > MAX_POLICY_RECIPIENTS
        || !policy.approval_mode.requires_explicit_user_action()
    {
        return Err(AgentWalletError::InvalidPaymentRequest);
    }
    let overlap: BTreeSet<_> = policy
        .allowed_recipients
        .intersection(&policy.blocked_recipients)
        .collect();
    if !overlap.is_empty() {
        return Err(AgentWalletError::RecipientNotAllowed);
    }
    for recipient in policy
        .allowed_recipients
        .iter()
        .chain(policy.blocked_recipients.iter())
    {
        hacash_wallet_core::require_address_for_network(recipient, network_mode)
            .map_err(|_| AgentWalletError::RecipientNotAllowed)?;
    }
    Ok(())
}

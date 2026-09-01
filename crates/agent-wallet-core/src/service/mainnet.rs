use serde::{Deserialize, Serialize};

/// Independent gates that must be closed before HPAY may create or spend from
/// an Agent Wallet on Hacash mainnet.
///
/// This is derived build capability, not persisted wallet state and not a
/// provider-controlled health response.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AgentMainnetReadinessBlocker {
    MainnetAccountCreationDisabled,
    HacashL2ProtocolTransportUnavailable,
    AuthenticatedProviderSessionUnavailable,
    ExternalRollbackAnchorUnavailable,
    L1DisputeRecoveryUnverified,
    RealProviderInteroperabilityUnverified,
    IndependentSecurityAuditRequired,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AgentMainnetReadiness {
    pub ready: bool,
    pub blockers: Vec<AgentMainnetReadinessBlocker>,
}

pub(super) fn current_agent_mainnet_readiness() -> AgentMainnetReadiness {
    let blockers = vec![
        AgentMainnetReadinessBlocker::MainnetAccountCreationDisabled,
        AgentMainnetReadinessBlocker::HacashL2ProtocolTransportUnavailable,
        AgentMainnetReadinessBlocker::AuthenticatedProviderSessionUnavailable,
        AgentMainnetReadinessBlocker::ExternalRollbackAnchorUnavailable,
        AgentMainnetReadinessBlocker::L1DisputeRecoveryUnverified,
        AgentMainnetReadinessBlocker::RealProviderInteroperabilityUnverified,
        AgentMainnetReadinessBlocker::IndependentSecurityAuditRequired,
    ];
    AgentMainnetReadiness {
        ready: blockers.is_empty(),
        blockers,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_build_truthfully_fails_closed_for_mainnet() {
        let readiness = current_agent_mainnet_readiness();
        assert!(!readiness.ready);
        assert_eq!(readiness.blockers.len(), 7);
        assert!(
            readiness
                .blockers
                .contains(&AgentMainnetReadinessBlocker::HacashL2ProtocolTransportUnavailable)
        );
        assert!(
            readiness
                .blockers
                .contains(&AgentMainnetReadinessBlocker::IndependentSecurityAuditRequired)
        );
    }
}

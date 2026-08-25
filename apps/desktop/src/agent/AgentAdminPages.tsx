import { useCallback, useEffect, useMemo, useState } from "react";
import {
  agentWalletApi,
  type AgentPermission,
  type AgentPolicy,
  type AgentRecord,
  type AgentWalletOverview,
  type ApprovalCommitment,
  type ApprovalMode,
  type AgentHvmPaymentOperation,
  type PaymentOperation,
  type StrandedWitness,
} from "./api";
import { AgentBackupPanel } from "./AgentBackupPanel";
import { AgentFastPayOperationsPanel } from "./AgentFastPayOperationsPanel";
import { AgentHvmOperationsPanel } from "./AgentHvmOperationsPanel";
import { PilotDiagnosticsPanel } from "./PilotDiagnosticsPanel";
import { WitnessRotationPanel } from "./WitnessRotationPanel";
import {
  APPROVE_OUTCOME_NOTICE,
  approvalOutcome,
  approvalResultNotice,
  emergencyStopControl,
  type AgentWalletWriteReadiness,
} from "./access";
import { DESKTOP_CONTROLS } from "./desktopControls";
import {
  ABANDON_STRANDED_PAYMENT_WARNING,
  APPROVE_TRANSACTION_WARNING,
  EMERGENCY_STOP_WARNING,
  EXIT_WITHOUT_PROVIDER_WARNING,
  FUND_PROVIDER_CHANNEL_WARNING,
  OPEN_PROVIDER_CHANNEL_WARNING,
  REJECT_PAYMENT_WARNING,
  REVOKE_AGENT_WARNING,
} from "./irreversibleActions";
import {
  exitPressResultLine,
  registryExitView,
  type AgentHvmRegistryExitStatus,
} from "./registryExit";
import {
  openPressResultLine,
  registryOpenView,
  type AgentHvmRegistryOpenStatus,
} from "./registryOpen";
import {
  adoptPressResultLine,
  channelNoteFromWallet,
  mergeResumableChannel,
  clearChannelNote,
  fundPressResultLine,
  readChannelNote,
  registryFundingView,
  writeChannelNote,
  type RegistryChannelNote,
} from "./registryFunding";
import { strandedWitnessView } from "./strandedWitness";

export type AgentAdminPage = "agents" | "rules" | "activity" | "providers" | "security";
/** Where a page can send the owner when the control they need lives elsewhere. */
export type AgentDestination =
  | "overview"
  | "agents"
  | "rules"
  | "activity"
  | "providers"
  | "security";
type RunAdminAction = (work: () => Promise<void>) => Promise<void>;
type AdminPageProps = {
  page: AgentAdminPage;
  overview: AgentWalletOverview;
  busy: boolean;
  run: RunAdminAction;
  onInfo: (message: string) => void;
  onRefreshOverview: () => Promise<void>;
  onEmergencyStop: () => void;
  onEnable: () => void;
  /** Gates clearing the emergency stop only. Never the payment prerequisites. */
  localEnableBlockers: AgentWalletWriteReadiness[];
  /**
   * Turns three sentences that named a screen into three controls that open it.
   * Presentation only: it changes which page is shown, nothing else.
   */
  onOpenPage: (page: AgentDestination) => void;
};

const PERMISSIONS: { id: AgentPermission; label: string; detail: string }[] = [
  { id: "read_wallet_info", label: "Read wallet identity", detail: "Address, network and wallet status." },
  { id: "read_balance", label: "Read balance", detail: "Available and reserved HAC only." },
  { id: "create_payment_intent", label: "Request payments", detail: "Creates unsigned intents that still require manual approval." },
  { id: "read_own_operation_status", label: "Read own request", detail: "Status for operations created by this agent." },
  { id: "list_own_operations", label: "List own activity", detail: "No access to another agent's operations." },
  { id: "cancel_own_unsigned_operation", label: "Cancel unsigned requests", detail: "Cannot cancel signed or broadcast transactions." },
];

export default function AgentAdminPages(props: AdminPageProps) {
  if (props.page === "agents") return <AgentsPage {...props} />;
  if (props.page === "rules") return <RulesPage {...props} />;
  if (props.page === "activity") return <ActivityPage {...props} />;
  if (props.page === "security") return <SecurityPage {...props} />;
  return <ProvidersPage />;
}

function AgentsPage({ overview, busy, run, onInfo, onRefreshOverview, onOpenPage }: AdminPageProps) {
  const [agents, setAgents] = useState<AgentRecord[] | null>(null);
  const [error, setError] = useState("");
  const [confirmRevoke, setConfirmRevoke] = useState<string | null>(null);
  const load = useCallback(async () => {
    setError("");
    try { setAgents(await agentWalletApi.listAgents(overview.wallet_id)); }
    catch (reason) { setAgents(null); setError(readableError(reason)); }
  }, [overview.wallet_id]);
  useEffect(() => { void load(); }, [load]);

  return (
    <section>
      <PageHead eyebrow="Local identities" title="Authorized agents" onRefresh={() => void load()} busy={busy} />
      <p className="agent-lead">Each identity has its own capabilities, limits and authorization epoch. Revocation is permanent.</p>
      {error && <LoadFailure message={error} onRetry={() => void load()} />}
      {agents === null && !error && <LoadingState label="Loading agents" />}
      {/* The empty state named an action and offered no control. Pairing a
          local agent lives in the connector panel on Overview. */}
      {agents?.length === 0 && (
        <EmptyState
          title="No agents paired"
          body="No local agent currently has access to this Agent Wallet. Pair local AI agent is inside Local Agent connector on Overview, and it only appears once the connector is running, so start the AI agent connector there first."
          action={DESKTOP_CONTROLS.open_overview_to_pair_agent}
          onAction={() => onOpenPage("overview")}
        />
      )}
      <div className="agent-card-list">
        {agents?.map((agent) => (
          <article className="agent-panel agent-record" key={agent.agent_id}>
            <div className="agent-record-head">
              <div><h2>{agent.name}</h2><p>{agent.version} / {shortId(agent.agent_id)}</p></div>
              <StatusBadge status={agent.status} />
            </div>
            <dl className="agent-detail-grid">
              <Detail label="Paired" value={formatDate(agent.paired_at)} />
              <Detail label="Authorization epoch" value={String(agent.authorization_epoch)} />
              <Detail label="Per request" value={formatUnits(agent.policy.max_per_payment_units)} />
              <Detail label="Daily limit" value={formatUnits(agent.policy.max_daily_units)} />
              <Detail label="Identity fingerprint" value={agent.identity_fingerprint} wide />
            </dl>
            {agent.status === "active" && (
              <div className="agent-confirm-row">
                {confirmRevoke === agent.agent_id ? (
                  <>
                    <div className="agent-warning">{REVOKE_AGENT_WARNING}</div>
                    <button type="button" onClick={() => setConfirmRevoke(null)} disabled={busy}>Cancel</button>
                    <button type="button" className="agent-danger" disabled={busy} onClick={() => void run(async () => {
                      await agentWalletApi.revokeAgent(overview.wallet_id, agent.agent_id);
                      setConfirmRevoke(null);
                      onInfo(agent.name + " has been revoked.");
                      await Promise.all([load(), onRefreshOverview()]);
                    })}>Confirm permanent revoke</button>
                  </>
                ) : (
                  <>
                    {/* Said before the first press, not only after it. */}
                    <p className="agent-muted">Permanent. A revoked agent cannot be restored.</p>
                    <button type="button" className="agent-danger" disabled={busy} onClick={() => setConfirmRevoke(agent.agent_id)}>{DESKTOP_CONTROLS.revoke_agent}</button>
                  </>
                )}
              </div>
            )}
          </article>
        ))}
      </div>
    </section>
  );
}

export type PolicyDraft = {
  maxPerPayment: string;
  maxDaily: string;
  maxPending: string;
  allowedRecipients: string;
  blockedRecipients: string;
  allowUnlistedWithApproval: boolean;
  approvalMode: ApprovalMode;
  permissions: AgentPermission[];
};

export type PolicyReview = {
  agentId: string;
  agentName: string;
  policy: AgentPolicy;
};

export function createPolicyReview(agent: AgentRecord, policy: AgentPolicy): PolicyReview {
  return {
    agentId: agent.agent_id,
    agentName: agent.name,
    policy: {
      ...policy,
      permissions: [...policy.permissions],
      allowed_recipients: [...policy.allowed_recipients],
      blocked_recipients: [...policy.blocked_recipients],
    },
  };
}

function RulesPage({ overview, busy, run, onInfo, onOpenPage }: AdminPageProps) {
  const [agents, setAgents] = useState<AgentRecord[] | null>(null);
  const [agentId, setAgentId] = useState("");
  const [policy, setPolicy] = useState<AgentPolicy | null>(null);
  const [draft, setDraft] = useState<PolicyDraft | null>(null);
  const [review, setReview] = useState<PolicyReview | null>(null);
  const [error, setError] = useState("");
  const loadAgents = useCallback(async () => {
    setError("");
    try {
      const next = await agentWalletApi.listAgents(overview.wallet_id);
      setAgents(next);
      setAgentId((current) => next.some((agent) => agent.agent_id === current && agent.status === "active") ? current : next.find((agent) => agent.status === "active")?.agent_id ?? "");
    } catch (reason) { setAgents(null); setError(readableError(reason)); }
  }, [overview.wallet_id]);
  useEffect(() => { void loadAgents(); }, [loadAgents]);
  useEffect(() => {
    setPolicy(null); setDraft(null); setReview(null);
    if (!agentId) return;
    void agentWalletApi.getPolicy(overview.wallet_id, agentId).then((next) => { setPolicy(next); setDraft(policyToDraft(next)); }).catch((reason) => setError(readableError(reason)));
  }, [agentId, overview.wallet_id]);
  const validation = useMemo(() => draft ? validateDraft(draft, policy?.policy_epoch ?? 0) : { policy: null, error: "" }, [draft, policy?.policy_epoch]);
  const selectedAgent = agents?.find((agent) => agent.agent_id === agentId);
  const unsupportedApprovalMode = draft?.approvalMode !== undefined && draft.approvalMode !== "desktop_manual";

  return (
    <section>
      <PageHead eyebrow="Default deny" title="Agent rules" onRefresh={() => void loadAgents()} busy={busy} />
      <p className="agent-lead">Policy changes invalidate this agent's active sessions. All payment modes continue to require an explicit user decision.</p>
      {error && <LoadFailure message={error} onRetry={() => void loadAgents()} />}
      {agents?.every((agent) => agent.status !== "active") && (
        <EmptyState
          title="No active agent"
          body="Pair an agent before defining spending permissions. Pair local AI agent is inside Local Agent connector on Overview, and it only appears once the connector is running, so start the AI agent connector there first."
          action={DESKTOP_CONTROLS.open_overview_to_pair_agent}
          onAction={() => onOpenPage("overview")}
        />
      )}
      {agents && agents.some((agent) => agent.status === "active") && (
        <label className="agent-field">Agent<select value={agentId} onChange={(event) => setAgentId(event.target.value)} disabled={busy || !!review}>{agents.filter((agent) => agent.status === "active").map((agent) => <option key={agent.agent_id} value={agent.agent_id}>{agent.name}</option>)}</select></label>
      )}
      {selectedAgent && draft && (
        <div className="agent-policy-layout">
          <section className="agent-panel">
            <h2>Limits</h2>
            <div className="agent-form-grid">
              <PolicyInput label="Maximum per request (HAC)" value={draft.maxPerPayment} onChange={(value) => setDraft({ ...draft, maxPerPayment: value })} disabled={busy || !!review || unsupportedApprovalMode} />
              <PolicyInput label="Maximum per day (HAC)" value={draft.maxDaily} onChange={(value) => setDraft({ ...draft, maxDaily: value })} disabled={busy || !!review || unsupportedApprovalMode} />
              <PolicyInput label="Maximum pending requests" type="number" value={draft.maxPending} onChange={(value) => setDraft({ ...draft, maxPending: value })} disabled={busy || !!review || unsupportedApprovalMode} />
              <label className="agent-field">Approval device<input aria-label="Approval device" value={approvalModeLabel(draft.approvalMode)} readOnly disabled /></label>
            </div>
            {unsupportedApprovalMode ? (
              <>
                <div className="agent-warning" role="alert">This existing policy uses a mobile approval mode that is not production-ready. It is preserved unchanged and this policy is read-only. Agent payments remain blocked until a supported approval path is available.</div>
                {/* This screen has no control that can move the agent to a
                    supported mode: every field is disabled and validateDraft
                    refuses any mode but desktop_manual, so Review policy change
                    can never enable. There IS a route out, and naming it with
                    its cost is the difference between a read-only policy and a
                    dead end. */}
                <p className="agent-warning" role="status">
                  Nothing on this screen can change that mode. The only route is
                  to revoke this agent under Agents and pair it again from
                  Overview, which writes a fresh desktop-approval policy.{" "}
                  {REVOKE_AGENT_WARNING} Leaving the agent as it is costs
                  nothing: it stays authorized for whatever it can already read,
                  and it simply cannot be paid.
                </p>
              </>
            ) : (
              <p>Desktop approval is the only production-ready choice. Mobile approval modes remain unavailable.</p>
            )}
          </section>
          <section className="agent-panel">
            <h2>Capabilities</h2>
            <div className="agent-check-list">{PERMISSIONS.map((permission) => (
              <label key={permission.id}><input type="checkbox" checked={draft.permissions.includes(permission.id)} disabled={busy || !!review || unsupportedApprovalMode} onChange={(event) => setDraft({ ...draft, permissions: event.target.checked ? [...draft.permissions, permission.id] : draft.permissions.filter((item) => item !== permission.id) })} /><span><strong>{permission.label}</strong><small>{permission.detail}</small></span></label>
            ))}</div>
          </section>
          <section className="agent-panel">
            <h2>Recipients</h2>
            <div className="agent-form-grid"><PolicyArea label="Allowed addresses, one per line" value={draft.allowedRecipients} onChange={(value) => setDraft({ ...draft, allowedRecipients: value })} disabled={busy || !!review || unsupportedApprovalMode} /><PolicyArea label="Blocked addresses, one per line" value={draft.blockedRecipients} onChange={(value) => setDraft({ ...draft, blockedRecipients: value })} disabled={busy || !!review || unsupportedApprovalMode} /></div>
            <p>An empty allowlist denies every payment recipient. An address cannot appear in both lists.</p>
            {/* Off for every existing agent. Turning it on lets the agent ASK
                about an address you have not vetted; it never lets the agent
                pay one. */}
            <div className="agent-check-list">
              <label>
                <input
                  type="checkbox"
                  checked={draft.allowUnlistedWithApproval}
                  disabled={busy || !!review || unsupportedApprovalMode}
                  onChange={(event) => setDraft({ ...draft, allowUnlistedWithApproval: event.target.checked })}
                />
                <span>
                  <strong>Let this agent propose payments to addresses that are not allowed above</strong>
                  <small>
                    Each one still needs your exact manual approval, and is refused if the address is blocked.
                    Approving a payment does not add the address to the allowlist, so the next payment to the same
                    address asks again.
                  </small>
                </span>
              </label>
            </div>
            {draft.allowUnlistedWithApproval && (
              <p className="agent-warning" role="status">
                This agent may propose payments to any address that is not blocked. Nothing is paid without
                your approval of the exact amount and address.
              </p>
            )}
          </section>
          {validation.error && <div className="alert" role="alert">{validation.error}</div>}
          {!review ? <button type="button" className="agent-primary-action" disabled={busy || !validation.policy || !selectedAgent} onClick={() => {
            if (selectedAgent && validation.policy) setReview(createPolicyReview(selectedAgent, validation.policy));
          }}>Review policy change</button> : (
            <section className="agent-panel agent-review">
              <span className="agent-eyebrow">Final confirmation</span><h2>Apply policy epoch {review.policy.policy_epoch + 1}</h2>
              <p>The fields above are frozen. Saving persists this exact reviewed snapshot and disconnects existing authenticated sessions for {review.agentName}.</p>
              {/* The real scope. `update_agent_policy`
                  (crates/agent-wallet-core/src/service/admin.rs) calls
                  cancel_pre_signing_operations with scope None, so it is every
                  agent on the wallet, and it cancels payment requests rather
                  than only sessions. The sentence above named one agent and
                  named sessions only. */}
              <p className="agent-warning" role="alert">
                Saving also cancels every payment request that is waiting for
                your decision, on every agent on this wallet and not only on
                {" "}{review.agentName}. Those requests are gone and each agent
                has to ask again. Back changes nothing.
              </p>
              <dl className="agent-detail-grid">
                <Detail label="Maximum per request" value={formatUnits(review.policy.max_per_payment_units)} />
                <Detail label="Maximum per day" value={formatUnits(review.policy.max_daily_units)} />
                <Detail label="Maximum pending" value={String(review.policy.max_pending_operations)} />
                <Detail label="Approval" value={approvalModeLabel(review.policy.approval_mode)} />
                <Detail label="Permissions" value={review.policy.permissions.join(", ") || "None"} wide />
                <Detail label="Allowed recipients" value={review.policy.allowed_recipients.join(", ") || "None (default deny)"} wide />
                <Detail label="Blocked recipients" value={review.policy.blocked_recipients.join(", ") || "None"} wide />
                <Detail label="Payments to addresses not on the allowlist" value={review.policy.allow_unlisted_recipient_with_approval ? "May be proposed, each needs your exact approval" : "Refused"} wide />
              </dl>
              <div className="agent-confirm-row"><button type="button" onClick={() => setReview(null)} disabled={busy}>Back</button><button type="button" className="agent-primary-action" disabled={busy} onClick={() => void run(async () => {
                const saved = await agentWalletApi.updatePolicy(overview.wallet_id, review.agentId, review.policy);
                setPolicy(saved); setDraft(policyToDraft(saved)); setReview(null);
                onInfo("Rules updated for " + review.agentName + ". Active sessions were invalidated.");
                await loadAgents();
              })}>Save policy and disconnect sessions</button></div>
            </section>
          )}
        </div>
      )}
    </section>
  );
}

function ActivityPage({ overview, busy, run, onInfo, onRefreshOverview, onOpenPage }: AdminPageProps) {
  const [activity, setActivity] = useState<PaymentOperation[] | null>(null);
  const [pending, setPending] = useState<PaymentOperation[] | null>(null);
  const [error, setError] = useState("");
  const load = useCallback(async () => {
    setError("");
    try { const [nextActivity, nextPending] = await Promise.all([agentWalletApi.listActivity(overview.wallet_id), agentWalletApi.listPendingApprovals(overview.wallet_id)]); setActivity(nextActivity); setPending(nextPending); }
    catch (reason) { setActivity(null); setPending(null); setError(readableError(reason)); }
  }, [overview.wallet_id]);
  useEffect(() => { void load(); }, [load]);
  return (
    <section>
      <PageHead eyebrow="Authenticated journal" title="Activity" onRefresh={() => void load()} busy={busy} />
      <p className="agent-lead">Amounts are exact integer HAC units. Agent Wallet activity never includes My Wallet transactions.</p>
      <AgentFastPayOperationsPanel
        walletId={overview.wallet_id}
        busy={busy}
        run={run}
        onInfo={onInfo}
        onRefreshOverview={onRefreshOverview}
      />
      <AgentHvmOperationsPanel
        walletId={overview.wallet_id}
        networkMode={overview.network_mode}
        channelBinding={overview.hvm_channel_binding}
        registryBinding={overview.hvm_registry_binding}
        busy={busy}
        run={run}
        onInfo={onInfo}
        onRefreshOverview={onRefreshOverview}
      />
      {error && <LoadFailure message={error} onRetry={() => void load()} />}
      {activity === null && !error && <LoadingState label="Loading activity" />}
      {/* The sentence named Security and gave no way to get there. */}
      {pending && pending.length > 0 && (
        <div className="agent-warning agent-control-row" role="alert">
          <span>
            {pending.length} payment {pending.length === 1 ? "request needs" : "requests need"} your decision.
          </span>
          <button type="button" className="agent-primary-action" onClick={() => onOpenPage("security")}>
            {DESKTOP_CONTROLS.open_security}
          </button>
        </div>
      )}
      {activity?.length === 0 && <EmptyState title="No Agent Wallet activity" body="No payment intent has been recorded for this wallet." />}
      <div className="agent-card-list">{activity?.map((operation) => <OperationCard key={operation.operation_id} operation={operation} />)}</div>
    </section>
  );
}

function SecurityPage({ overview, busy, run, onInfo, onRefreshOverview, onEmergencyStop, onEnable, localEnableBlockers }: AdminPageProps) {
  const [pending, setPending] = useState<PaymentOperation[] | null>(null);
  const [approval, setApproval] = useState<ApprovalCommitment | null>(null);
  // The allowlist standing of the address under review. It is fetched next to
  // the approval rather than carried on the approval, because the approval is
  // the exact signed payment and must not grow fields that are not signed.
  const [standing, setStanding] = useState<RecipientStanding>("unverified");
  const [confirmReject, setConfirmReject] = useState<string | null>(null);
  const [error, setError] = useState("");
  // The payment that is waiting on the phone, read from the core rather than
  // inferred from the approval list: only the core knows whether the phone
  // still has an open confirmation window, and that is what decides whether the
  // give-up control may be offered at all.
  const [stranded, setStranded] = useState<StrandedWitness | null>(null);
  const [confirmGiveUp, setConfirmGiveUp] = useState<string | null>(null);
  // What the owner's own fullnode says about walking out of the registry
  // channel alone, and this wallet's own record of what it has already spent
  // out of that channel. Neither read touches the Hub, which is the whole
  // point: this section has to render identically when the provider is gone.
  const [exitStatus, setExitStatus] = useState<AgentHvmRegistryExitStatus | null>(null);
  const [exitReadError, setExitReadError] = useState("");
  const [exitOperations, setExitOperations] = useState<AgentHvmPaymentOperation[]>([]);
  const [confirmExit, setConfirmExit] = useState(false);
  // Opening a channel. The other end of the exit above, and the only screen in
  // this app where money is deliberately made irreversible. Everything it shows
  // is read before anything is asked of the provider, and the provider's
  // countersigned full refund is validated in Rust before any funding is built,
  // so nothing on this panel can talk an owner into an unbacked deposit.
  const [openHubUrl, setOpenHubUrl] = useState("");
  const [openDepositHac, setOpenDepositHac] = useState("");
  const [openBindingText, setOpenBindingText] = useState("");
  const [openStatus, setOpenStatus] = useState<AgentHvmRegistryOpenStatus | null>(null);
  const [openReadError, setOpenReadError] = useState("");
  const [confirmOpen, setConfirmOpen] = useState(false);
  // This desktop's own note of a channel it opened and has not finished, and
  // the two presses that finish it.
  //
  // An open leaves the owner holding a countersigned full refund over a channel
  // that contains nothing, and the deposit that follows is the press this whole
  // panel exists to warn about. Without this note the panel would show the
  // empty open form again on the next visit, which reads as though the first
  // press never happened and invites a second channel that this wallet would
  // refuse anyway. The note decides nothing: both presses below re-derive
  // everything from the wallet's own sealed record.
  const [channelNote, setChannelNote] = useState<RegistryChannelNote | null>(null);
  const [confirmFund, setConfirmFund] = useState(false);
  // Why the last press of an open, a funding or a finish was refused, in the
  // backend's own words, rendered inside this panel rather than only in the
  // page banner. A provider that will not countersign is the refusal an owner
  // is most likely to meet, and it means no channel opened and nothing was
  // spent: that has to be readable where they are looking.
  const [channelRefusal, setChannelRefusal] = useState("");
  // Adoption clears the note, because the wallet's own binding has taken over
  // as the record of this channel and the panel below it is the exit.
  useEffect(() => {
    if (overview.hvm_registry_binding) {
      clearChannelNote(window.localStorage);
      setChannelNote(null);
      return;
    }
    setChannelNote(readChannelNote(window.localStorage, overview.wallet_id));
  }, [overview.wallet_id, overview.hvm_registry_binding]);
  const rememberChannel = useCallback((note: RegistryChannelNote) => {
    writeChannelNote(window.localStorage, note);
    setChannelNote(note);
  }, []);
  const openDepositZhu = depositHacToZhu(openDepositHac);
  const openInputsReady =
    !overview.hvm_registry_binding &&
    /^https?:\/\/\S+$/.test(openHubUrl.trim()) &&
    openDepositZhu !== null &&
    openDepositZhu > 0 &&
    isJsonObject(openBindingText);
  const load = useCallback(async () => {
    setError("");
    try { setPending(await agentWalletApi.listPendingApprovals(overview.wallet_id)); } catch (reason) { setPending(null); setError(readableError(reason)); }
    // A failure to read this must never invent a stranded payment, and must
    // never hide the approvals that did load.
    try { setStranded(await agentWalletApi.strandedWitness(overview.wallet_id)); } catch { setStranded(null); }
    // A failure here is reported rather than swallowed. An owner whose channel
    // is stuck is entitled to know that the check itself did not run, instead
    // of reading a section that quietly disappeared.
    try {
      setExitStatus(await agentWalletApi.hvmRegistryExitStatus(overview.wallet_id));
      setExitReadError("");
    } catch (reason) {
      setExitStatus(null);
      setExitReadError(readableError(reason));
    }
    try { setExitOperations(await agentWalletApi.listHvmActivity(overview.wallet_id)); } catch { setExitOperations([]); }
  }, [overview.wallet_id]);
  useEffect(() => { void load(); }, [load]);
  // The open panel's own read. It is separate from `load` because it depends on
  // two things the owner types, and because it is the only read on this page
  // that contacts a provider at all: the exit section must stay readable when
  // every provider in the world is unreachable.
  useEffect(() => {
    if (!openInputsReady || openDepositZhu === null) {
      setOpenStatus(null);
      setOpenReadError("");
      return;
    }
    let live = true;
    void agentWalletApi
      .hvmRegistryOpenStatus(overview.wallet_id, openHubUrl.trim(), openDepositZhu)
      .then((status) => { if (live) { setOpenStatus(status); setOpenReadError(""); } })
      .catch((reason) => { if (live) { setOpenStatus(null); setOpenReadError(readableError(reason)); } });
    return () => { live = false; };
  }, [overview.wallet_id, openHubUrl, openDepositZhu, openInputsReady]);
  // Same predicate and same view helper as the Overview page. Before this,
  // Security could engage a stop and then showed no control that could clear
  // it, so the page that offers the emergency stop offered no way back.
  const stopControl = emergencyStopControl({
    paymentsSuspended: overview.payments_suspended,
    busy,
    localEnableBlockers,
  });
  const rejectOperation = (operation: PaymentOperation) =>
    void run(async () => {
      await agentWalletApi.reject(overview.wallet_id, operation.operation_id, operation.approval_mode ?? "desktop_manual");
      setConfirmReject(null);
      setApproval(null);
      setStanding("unverified");
      onInfo("Payment request rejected. No transaction was signed.");
      await Promise.all([load(), onRefreshOverview()]);
    });
  const reviewedOperation = approval
    ? pending?.find((operation) => operation.operation_id === approval.operation_id) ?? null
    : null;
  const strandedView = strandedWitnessView(stranded, formatUnits);
  const exitView = exitStatus
    ? registryExitView(overview.hvm_registry_binding, exitStatus, exitOperations, formatZhu)
    : null;
  const openView = openStatus
    ? registryOpenView(Boolean(overview.hvm_registry_binding), openStatus, formatZhu)
    : null;
  // The wallet's own record of an unfinished channel, preferred over this
  // desktop's note whenever the wallet has one.
  //
  // The note came first and was the only source, and that stranded money: it
  // is a single browser key shared by every Agent Wallet on the machine, it
  // does not follow a wallet restored elsewhere, and clearing browser data
  // deletes it. With the note gone and the provider gone, the only control
  // left was the open form, which asks the provider first and then reports
  // that nothing was funded and nothing was spent, over a deposit already in
  // a block.
  //
  // The note is kept as the fallback for the moment before the first status
  // read returns, so the panel does not blink out on a slow read. It is no
  // longer the only thing that knows, and it can no longer be the reason an
  // owner cannot reach their money.
  const walletChannel = channelNoteFromWallet(
    overview.wallet_id,
    openHubUrl,
    openStatus?.channel_in_progress,
    openStatus?.required_l1_fee_zhu ?? 0,
  );
  const resumableChannel = mergeResumableChannel(walletChannel, channelNote);
  // Reads no Hub and no chain, which is the point: finishing a channel is
  // exactly what an owner needs when the provider has stopped answering, and a
  // section that failed to render because a Hub was unreachable would fail
  // precisely then.
  const fundingView = resumableChannel
    ? registryFundingView(resumableChannel, formatZhu)
    : null;
  const rotationPhase = overview.witness_rotation_phase;
  const rotationNeedsAttention = Boolean(rotationPhase && rotationPhase !== "stable");
  return (
    <section>
      <PageHead eyebrow="Desktop primary signer" title="Security and approvals" onRefresh={() => void load()} busy={busy} />
      <div className="agent-security-grid">
        <section className="agent-panel"><h2>Emergency control</h2><StatusBadge status={overview.payments_suspended ? "disabled" : "active"} label={overview.payments_suspended ? "Payments disabled" : "Payments enabled"} />
          {/* Before-the-fact and never behind a disclosure: this control cannot
              undo a transaction that is already on the network. */}
          <p>{EMERGENCY_STOP_WARNING}</p>
          {stopControl.action === "enable" ? (<>
          <button type="button" className="agent-primary-action agent-block-action" disabled={stopControl.disabled} title={stopControl.reason} onClick={onEnable}>Enable locally</button>
          {localEnableBlockers.length > 0 && <p className="agent-warning" role="status">{stopControl.reason}</p>}
        </>) : <button type="button" className="agent-danger agent-block-action" disabled={stopControl.disabled} title={stopControl.reason} onClick={onEmergencyStop}>Disable All Agent Payments</button>}
          <details className="agent-advanced-details">
            <summary>What does this do?</summary>
            <p>It does not affect My Wallet. Enable locally is a desktop-only action on this unlocked Agent Wallet. It authorizes no payment: each exact transaction still requires a separate manual approval.</p>
          </details>
        </section>
        <section className="agent-panel"><h2>Signer boundary</h2><ul><li>The blockchain private key stays inside this encrypted desktop vault.</li><li>Agents cannot request raw signatures, exports or generic sends.</li><li>Every transaction commitment is checked again immediately before signing.</li></ul></section>
      </div>
      {/* A payment stranded waiting on the phone blocks every new agent payment
          and every phone replacement, so it outranks the approval list. The
          desktop is where the owner approved it and where they are stuck, so
          the way out is here and not on the phone. Never inside a <details>:
          the cost sentence has to be readable before the press. */}
      {strandedView && (
        <section className="agent-panel" aria-label="Payment waiting for your phone">
          <span className="agent-eyebrow">Waiting on your phone</span>
          <h2>{strandedView.heading}</h2>
          <p className="agent-exact-address">{strandedView.summary}</p>
          {/* Where the money is comes before anything else on this panel. Three
              of the four statuses that reach here are already on the network,
              and an owner reading a recovery screen is entitled to know that
              before they read a word about controls. */}
          <p role="status">{strandedView.whereTheMoneyIs}</p>
          {strandedView.transactionId && (
            <p className="agent-exact-address">{strandedView.transactionId}</p>
          )}
          <p>{strandedView.explanation}</p>
          <p role="status">{strandedView.phoneInstruction}</p>
          {/* Clearing a dead confirmation window moves no money and does not
              touch the payment. It is the step that frees this wallet to offer
              the phone replacement, so it says so rather than sitting there
              unexplained. */}
          {strandedView.canReleaseAnchor && (
            <div className="agent-confirm-row">
              <p>{strandedView.releaseExplanation}</p>
              <button type="button" disabled={busy} onClick={() => void run(async () => {
                await agentWalletApi.releaseDeadWitnessAnchor(overview.wallet_id, stranded?.operation_id ?? "");
                onInfo("The expired confirmation window was cleared. The payment is unchanged and still waiting for your phone.");
                await Promise.all([load(), onRefreshOverview()]);
              })}>{DESKTOP_CONTROLS.clear_expired_confirmation_window}</button>
            </div>
          )}
          <p role="status">{strandedView.replacePhoneGuidance}</p>
          {/* The give-up control is offered only when the core would accept it.
              While the phone still has an open window the reason is shown
              instead of a button that would be refused. */}
          {strandedView.canAbandon ? (
            <>
              <div className="agent-warning">{ABANDON_STRANDED_PAYMENT_WARNING}</div>
              <p>{strandedView.afterAbandon}</p>
              <div className="agent-confirm-row">
                {confirmGiveUp === strandedView.summary ? (
                  <>
                    <button type="button" disabled={busy} onClick={() => setConfirmGiveUp(null)}>Cancel</button>
                    <button type="button" className="agent-danger" disabled={busy} onClick={() => void run(async () => {
                      await agentWalletApi.abandonStrandedWitness(overview.wallet_id, stranded?.operation_id ?? "");
                      setConfirmGiveUp(null);
                      onInfo("That payment was given up. Nothing was sent to the network and the reserved funds are back in your spendable balance.");
                      await Promise.all([load(), onRefreshOverview()]);
                    })}>Confirm give up</button>
                  </>
                ) : (
                  <button type="button" className="agent-danger" disabled={busy} onClick={() => setConfirmGiveUp(strandedView.summary)}>{DESKTOP_CONTROLS.give_up_stranded_payment}</button>
                )}
              </div>
            </>
          ) : (
            <p role="status">{strandedView.abandonWithheldReason}</p>
          )}
        </section>
      )}
      {/* Opening a channel, and locking money up to do it.

          It sits directly above the exit section on purpose: these are the two
          ends of the same decision, and an owner deciding whether to put money
          in is entitled to read how it comes out on the same screen.

          Nothing here is behind a <details>. The deposit, the fee and the
          refund guarantee are the three facts that decide this, and a
          disclosure an owner never opens is the same as not saying it. */}
      {!overview.hvm_registry_binding && overview.pilot_enabled && !resumableChannel && (
        <section className="agent-panel" aria-label="Opening a channel with a provider">
          <span className="agent-eyebrow">Your money, before you commit it</span>
          <h2>Opening a channel with a provider</h2>
          <label className="agent-field">
            <span>Provider URL</span>
            <input
              value={openHubUrl}
              onChange={(event) => { setOpenHubUrl(event.target.value); setConfirmOpen(false); }}
              placeholder="http://127.0.0.1:8790"
              autoComplete="off"
              spellCheck={false}
            />
          </label>
          <label className="agent-field">
            <span>Deposit to lock up, in HAC</span>
            <input
              value={openDepositHac}
              onChange={(event) => { setOpenDepositHac(event.target.value); setConfirmOpen(false); }}
              placeholder="5"
              autoComplete="off"
              spellCheck={false}
            />
          </label>
          {/* The channel itself, exactly as the provider published it. This
              wallet re-states it as its own and the provider gets no field
              through which to change it afterwards, so the one thing that can
              be wrong here is the amount, and the deposit above is typed
              separately for exactly that reason: the Rust command refuses
              unless the two agree. */}
          <label className="agent-field">
            <span>Channel details from your provider</span>
            <textarea
              value={openBindingText}
              onChange={(event) => { setOpenBindingText(event.target.value); setConfirmOpen(false); }}
              placeholder='{"schema":"...","contract_address":"...","channel_id":"...","left_deposit_zhu":5000000}'
              autoComplete="off"
              spellCheck={false}
              rows={4}
            />
          </label>
          {openView ? (
            <>
              <p className="agent-exact-address">{openView.lockUpLine}</p>
              {/* The fact that makes the deposit safe. Never collapsible and
                  never softened into a statement about the provider being
                  trustworthy: it is a signature this wallet checks itself, and
                  funding is unbuildable without it. */}
              <p className="agent-warning" role="status">{openView.refundLine}</p>
              {/* What the press actually does, and what it does not. It moves
                  no money and it binds this wallet to one channel for good, and
                  an owner is owed both halves before the first press. */}
              <p>{openView.commitmentLine}</p>
              <p>{openView.refusalLine}</p>
              <p>{openView.feeLine}</p>
              <p>{openView.exitLine}</p>
              {/* No build gives the phone a Hacash spending key, so this says
                  "never" rather than "not yet". */}
              <p>{openView.phoneLine}</p>
              {/* Stated, never a silent gate. */}
              <dl className="agent-detail-grid">
                {openView.preconditions.map((entry) => (
                  <Detail
                    key={entry.label}
                    label={`${entry.label}: ${entry.met ? "ready" : "not ready"}`}
                    value={entry.detail}
                    wide
                  />
                ))}
              </dl>
              <div className="agent-warning">{OPEN_PROVIDER_CHANNEL_WARNING}</div>
              {openView.canOpen ? (
                <div className="agent-confirm-row">
                  {confirmOpen ? (
                    <>
                      <button type="button" disabled={busy} onClick={() => setConfirmOpen(false)}>Cancel</button>
                      <button type="button" className="agent-danger" disabled={busy} onClick={() => void run(async () => {
                        const depositZhu = openDepositZhu ?? 0;
                        const feeZhu = openStatus?.required_l1_fee_zhu ?? 0;
                        let result;
                        try {
                          result = await agentWalletApi.openHvmRegistryChannel(
                            overview.wallet_id,
                            openHubUrl.trim(),
                            JSON.parse(openBindingText),
                            depositZhu,
                          );
                        } catch (reason) {
                          // The refusal an owner is most likely to meet, said
                          // where they are looking. A provider that will not
                          // countersign means no channel opened and nothing
                          // spent, and the backend says exactly that in words
                          // this screen must not paraphrase or soften.
                          setConfirmOpen(false);
                          setChannelRefusal(readableError(reason));
                          return;
                        }
                        setConfirmOpen(false);
                        setChannelRefusal("");
                        setOpenHubUrl("");
                        setOpenDepositHac("");
                        setOpenBindingText("");
                        // The channel this desktop now has to finish, written
                        // from the backend's own answer and not from the form.
                        rememberChannel({
                          schema: "hpay-desktop-registry-channel-note/1",
                          wallet_id: overview.wallet_id,
                          hub_url: result.hub_url,
                          binding_commitment: result.binding_commitment,
                          contract_address: result.contract_address,
                          deposit_zhu: result.deposit_zhu,
                          refunded_zhu: result.refunded_zhu,
                          required_l1_fee_zhu: feeZhu,
                          funding_transaction_hash: null,
                          funding_confirmed: false,
                          network_fee_zhu: null,
                        });
                        // The backend's own numbers, read from the countersigned
                        // bill rather than from what this form was told earlier,
                        // and honest about the deposit not having been sent.
                        onInfo(openPressResultLine(result, formatZhu));
                        await Promise.all([load(), onRefreshOverview()]);
                      })}>Confirm, open this channel</button>
                    </>
                  ) : (
                    <button type="button" className="agent-danger" disabled={busy} onClick={() => setConfirmOpen(true)}>
                      {DESKTOP_CONTROLS.open_provider_channel}
                    </button>
                  )}
                </div>
              ) : (
                <p className="agent-warning" role="status">
                  {DESKTOP_CONTROLS.open_provider_channel} is not available yet. {openView.openWithheldReason}
                </p>
              )}
            </>
          ) : (
            <p role="status">
              {openReadError
                ? `This provider could not be checked just now. Nothing has been asked of it and no money has moved. ${openReadError}`
                : "Enter a provider URL and the deposit you want to lock up. Nothing is asked of the provider and nothing is sent until you have read exactly what this costs."}
            </p>
          )}
          {/* The refusal, in the backend's own words. Never behind a
              disclosure and never rewritten: a provider that would not
              countersign the refund means no channel was opened, nothing was
              funded and nothing was spent, and the sentence that says so is
              the one an owner needs before they go looking for money that
              never left. */}
          {channelRefusal && (
            <p className="agent-warning" role="status">{channelRefusal}</p>
          )}
        </section>
      )}
      {/* The channel that is opened and not yet finished.

          This is the middle of the flow and the only place in this app where a
          press exists in order to make money irreversible. It replaces the open
          form rather than sitting beside it, because an owner who already holds
          a countersigned refund for one channel does not have a second channel
          to open: this wallet would refuse it, and offering the empty form
          again would read as though the first press had not happened.

          Nothing here reads a Hub. Finishing is exactly what an owner needs on
          the day the provider stops answering, so this section renders the same
          whether the provider is healthy, unreachable or gone.

          Nothing here is behind a <details>. The deposit, the fee and the
          refund already held are the three facts that decide this press. */}
      {!overview.hvm_registry_binding && overview.pilot_enabled && fundingView && (
        <section className="agent-panel" aria-label="Finishing a channel you have opened">
          <span className="agent-eyebrow">Your money, before it is locked up</span>
          <h2>{fundingView.heading}</h2>
          {/* What this note is, said before anything it claims. */}
          <p role="status">{fundingView.noteLine}</p>
          {/* The fact that makes the deposit safe, and it is already true. */}
          <p className="agent-warning" role="status">{fundingView.refundHeldLine}</p>
          <p className="agent-exact-address">{fundingView.lockUpLine}</p>
          <p>{fundingView.feeLine}</p>
          {/* Where this channel has already got to. An owner returning to a
              laptop they closed between the two presses is the ordinary case,
              and the wallet never signs a second transfer into one channel. */}
          {fundingView.resumeLine && (
            <p className="agent-warning" role="status">{fundingView.resumeLine}</p>
          )}
          <p>{fundingView.refusalLine}</p>
          <p>{fundingView.finishLine}</p>
          {/* No build gives the phone a Hacash spending key, so this says
              "never" rather than "not yet". */}
          <p>{fundingView.phoneLine}</p>
          <dl className="agent-detail-grid">
            <Detail label="Provider" value={resumableChannel?.hub_url ?? ""} wide />
            <Detail label="Channel contract" value={resumableChannel?.contract_address ?? ""} wide />
          </dl>
          {fundingView.actionSpendsMoney ? (
            <>
              {/* Before the first press, never after it and never collapsed. */}
              <div className="agent-warning">{FUND_PROVIDER_CHANNEL_WARNING}</div>
              <div className="agent-confirm-row">
                {confirmFund ? (
                  <>
                    <button type="button" disabled={busy} onClick={() => setConfirmFund(false)}>Cancel</button>
                    <button type="button" className="agent-danger" disabled={busy} onClick={() => void run(async () => {
                      let result;
                      try {
                        result = await agentWalletApi.fundHvmRegistryChannel(overview.wallet_id);
                      } catch (reason) {
                        // A wallet holding no validated countersigned refund
                        // refuses to fund, and says so. That refusal is the
                        // gate working, so it is shown rather than retried.
                        setConfirmFund(false);
                        setChannelRefusal(readableError(reason));
                        return;
                      }
                      setConfirmFund(false);
                      setChannelRefusal("");
                      if (channelNote) {
                        rememberChannel({
                          ...channelNote,
                          funding_transaction_hash: result.transaction_hash,
                          funding_confirmed: result.confirmed,
                          network_fee_zhu: result.network_fee_zhu,
                        });
                      }
                      // Sent and unseen is not the same fact as funded, and
                      // one fixed sentence over both would hide the step that
                      // is still owed.
                      onInfo(fundPressResultLine(result, formatZhu));
                      await Promise.all([load(), onRefreshOverview()]);
                    })}>{fundingView.stage === "funding_sent" ? "Confirm, carry on sending the deposit" : "Confirm, send the deposit"}</button>
                  </>
                ) : (
                  <button type="button" className="agent-danger" disabled={busy} onClick={() => setConfirmFund(true)}>
                    {fundingView.stage === "funding_sent"
                      ? DESKTOP_CONTROLS.continue_funding_provider_channel
                      : DESKTOP_CONTROLS.fund_provider_channel}
                  </button>
                )}
              </div>
            </>
          ) : (
            // Finishing sends no transaction and spends nothing, so it is one
            // press. It is also the press the exit refuses without, which is
            // why it is offered here and not hidden behind the provider.
            <div className="agent-confirm-row">
              <button type="button" disabled={busy} onClick={() => void run(async () => {
                let result;
                try {
                  result = await agentWalletApi.adoptHvmRegistryChannel(overview.wallet_id);
                } catch (reason) {
                  setChannelRefusal(readableError(reason));
                  return;
                }
                setChannelRefusal("");
                onInfo(adoptPressResultLine(result));
                await Promise.all([load(), onRefreshOverview()]);
              })}>{DESKTOP_CONTROLS.finish_opening_channel}</button>
            </div>
          )}
          {/* The refusal, in the backend's own words, where the press was. */}
          {channelRefusal && (
            <p className="agent-warning" role="status">{channelRefusal}</p>
          )}
          {/* A note this desktop cannot back is a trap: it hides the open form
              behind a channel the wallet does not hold. Clearing it moves no
              money, sends nothing and changes nothing inside the wallet, and
              the label promises only that. */}
          <details className="agent-advanced-details">
            <summary>This is not my channel</summary>
            <p>
              Clearing this note only forgets what this desktop wrote down. It sends nothing, spends nothing
              and cannot cancel a deposit that has already gone: if this wallet really holds a channel, the
              note comes back the next time you finish it, and if it does not, the form for opening one
              returns. Your refund receipt lives in the wallet and is untouched either way.
            </p>
            <button type="button" disabled={busy} onClick={() => {
              clearChannelNote(window.localStorage);
              setChannelNote(null);
              setConfirmFund(false);
              setChannelRefusal("");
            }}>{DESKTOP_CONTROLS.forget_channel_note}</button>
          </details>
        </section>
      )}
      {/* Getting out of a channel whose provider has stopped answering.
          It lives on Security rather than Activity because it has to be
          findable when everything else on the wallet is failing, and it is
          built entirely from this wallet's own state and the owner's own
          fullnode: no read on this section goes anywhere near the Hub, so a
          vanished provider cannot change a word of it.

          Nothing here is behind a <details>. The amount, the lease and the
          cost of the press are the three facts an owner needs before they
          decide, and a disclosure they never open is the same as not saying
          it. */}
      {overview.hvm_registry_binding && (
        <section className="agent-panel" aria-label="Getting your money out without the provider">
          <span className="agent-eyebrow">Your money, without your provider</span>
          <h2>{exitView ? exitView.heading : "Getting your money out without the provider"}</h2>
          {exitView ? (
            <>
              <p>{exitView.depositLine}</p>
              <p className="agent-exact-address">{exitView.yourMoneyLine}</p>
              {/* The one clock in this system that destroys money rather than
                  delaying it. Never collapsible, never rounded away, and never
                  a number this screen made up: when the chain could not be
                  asked, it says so instead. */}
              <p className="agent-warning" role="status">{exitView.leaseLine}</p>
              <p>{exitView.windowLine}</p>
              {/* The window running the other way. It sits directly under the
                  window sentence because the two are the same clock and an
                  owner who reads only the first one comes away believing the
                  objection window is a thing that protects them. Marked as a
                  warning and given role="status" for the same reason the lease
                  line is: this is the other way the money goes, and neither of
                  them may be something a reader has to open. */}
              <p className="agent-warning" role="status">{exitView.noWatcherLine}</p>
              <p>{exitView.feeLine}</p>
              {/* An exit outlives the app. Most of one is an objection window
                  measured in blocks, so an owner coming back to a laptop they
                  closed is the ordinary case, not an edge one. This is that
                  owner's answer, and it is read from the wallet's own durable
                  record rather than from anything held in this component. */}
              {exitView.alreadyStarted && (
                <p className="agent-warning" role="status">{exitView.progressSoFarLine}</p>
              )}
              <h3>What happens after you press it</h3>
              <ol className="agent-security-list">
                {exitView.steps.map((step) => <li key={step}>{step}</li>)}
              </ol>
              {/* Stated, never a silent gate. An owner who is refused is owed
                  the reason, and the reason is what tells them what to fix. */}
              <dl className="agent-detail-grid">
                {exitView.preconditions.map((entry) => (
                  <Detail
                    key={entry.label}
                    label={`${entry.label}: ${entry.met ? "ready" : "not ready"}`}
                    value={entry.detail}
                    wide
                  />
                ))}
              </dl>
              <div className="agent-warning">{EXIT_WITHOUT_PROVIDER_WARNING}</div>
              {exitView.canStart ? (
                <div className="agent-confirm-row">
                  {confirmExit ? (
                    <>
                      <button type="button" disabled={busy} onClick={() => setConfirmExit(false)}>Cancel</button>
                      <button type="button" className="agent-danger" disabled={busy} onClick={() => void run(async () => {
                        const progress = await agentWalletApi.startHvmRegistryExit(overview.wallet_id);
                        setConfirmExit(false);
                        // Say what the press did, in the backend's own words.
                        //
                        // This used to be one fixed sentence printed whatever
                        // came back: "The exit has started ... leave it open
                        // until the last step is done." Both halves were
                        // wrong. The press can answer that the objection window
                        // is open and name the block it ends at, or that this
                        // channel holds nothing and closing it would spend fees
                        // to recover zero, and the fixed sentence overwrote all
                        // of it. And the record survives the app closing, which
                        // is exactly what kill_mid_exit_on_chain.rs proves, so
                        // asking a person to sit in front of a laptop through
                        // an objection window measured in hours was asking for
                        // nothing.
                        onInfo(exitPressResultLine(progress, formatZhu));
                        await Promise.all([load(), onRefreshOverview()]);
                      })}>{exitView.startLabelKind === "continue" ? "Confirm, continue closing this channel" : "Confirm, close this channel"}</button>
                    </>
                  ) : (
                    <button type="button" className="agent-danger" disabled={busy} onClick={() => setConfirmExit(true)}>
                      {exitView.startLabelKind === "continue"
                        ? DESKTOP_CONTROLS.continue_exit_without_provider
                        : DESKTOP_CONTROLS.start_exit_without_provider}
                    </button>
                  )}
                </div>
              ) : (
                <p className="agent-warning" role="status">
                  {exitView.startLabelKind === "continue"
                    ? DESKTOP_CONTROLS.continue_exit_without_provider
                    : DESKTOP_CONTROLS.start_exit_without_provider} is not available yet. {exitView.startWithheldReason}
                </p>
              )}
            </>
          ) : (
            <div className="alert" role="alert">
              <span>
                This wallet has a channel with a provider, and whether you can walk out of it alone could not be
                checked just now. Nothing has changed and no money has moved. {exitReadError}
              </span>
              <button type="button" disabled={busy} onClick={() => void load()}>Check again</button>
            </div>
          )}
        </section>
      )}
      {/* Deciding a payment is the job of this page. It used to render below a
          diagnostics panel and a full rotation wizard, both permanently open. */}
      <h2 className="agent-section-title">Pending approvals</h2>
      {error && <LoadFailure message={error} onRetry={() => void load()} />}{pending === null && !error && <LoadingState label="Loading approvals" />}{pending?.length === 0 && <EmptyState title="No pending approvals" body="There is nothing waiting for a signing decision." />}
      <div className="agent-card-list">{pending?.map((operation) => (
        <article className="agent-panel agent-operation" key={operation.operation_id}><OperationSummary operation={operation} /><div className="agent-confirm-row">
          {confirmReject === operation.operation_id ? <><p className="agent-warning">{REJECT_PAYMENT_WARNING}</p><button type="button" disabled={busy} onClick={() => setConfirmReject(null)}>Cancel</button><button type="button" className="agent-danger" disabled={busy} onClick={() => rejectOperation(operation)}>Confirm reject</button></> : <>
            <button type="button" className="agent-danger" disabled={busy} onClick={() => setConfirmReject(operation.operation_id)}>{DESKTOP_CONTROLS.reject_payment}</button>
            <button type="button" className="agent-primary-action" disabled={busy} onClick={() => void run(async () => {
              const next = await agentWalletApi.pendingApproval(overview.wallet_id, operation.operation_id);
              // Fail loud, never quietly claim the address is known: if the
              // policy cannot be read the review says so instead.
              const policy = await agentWalletApi.getPolicy(overview.wallet_id, next.agent_id).catch(() => null);
              setApproval(next);
              setStanding(recipientStanding(next.recipient, policy));
              setConfirmReject(null);
            })}>{DESKTOP_CONTROLS.review_exact_transaction}</button>
          </>}
        </div></article>
      ))}</div>
      {approval && (
        <section className="agent-panel agent-approval-review" aria-label="Exact transaction approval"><span className="agent-eyebrow">Exact transaction review</span><h2>{formatUnits(approval.amount_units)} to {approval.recipient}</h2>
          {/* First thing in the review, not buried in the detail grid: whether
              this address is one the owner has already vetted. */}
          <div className={standing === "allowlisted" ? "agent-safe-note" : "alert"} role={standing === "allowlisted" ? undefined : "alert"}>
            <strong>{RECIPIENT_STANDING_LABEL[standing]}</strong>
            <p>{RECIPIENT_STANDING_DETAIL[standing]}</p>
            <p className="agent-exact-address">{approval.recipient}</p>
          </div>
          <dl className="agent-detail-grid"><Detail label="Recipient" value={approval.recipient} wide /><Detail label="Network fee" value={formatUnits(approval.fee_units)} /><Detail label="HPAY wallet fee" value={approval.wallet_fee_units === "0" ? "None" : "Blocked: invalid fee"} /><Detail label="Total debit" value={formatUnits(approval.total_debit_units)} /><Detail label="Expires" value={formatDate(approval.expires_at)} /><Detail label="Agent" value={approval.agent_id} wide /><Detail label="Transaction commitment" value={approval.transaction_commitment} wide /></dl><div className="agent-warning">{APPROVE_TRANSACTION_WARNING}</div>{!approvalIsExactAndFeeFree(approval) && <div className="alert" role="alert">This approval is malformed or contains a wallet fee. Signing is blocked.</div>}
          {/* The other half of the same disable, which used to say nothing at all.
              `disabled={busy || approvalIsExpired(approval) || !approvalIsExactAndFeeFree(approval)}`
              had a named reason for the malformed branch, above, and none for
              expiry. An owner who read the whole review and pressed Approve got a
              grey rectangle; the "Expires" value was one cell in a seven-cell
              grid and did not say it had passed. The gate is unchanged - an
              approval whose window has closed is still refused, here and in the
              core. It now has a cause, and a next step. */}
          {approvalIsExpired(approval) && <div className="alert" role="alert">This approval expired at {formatDate(approval.expires_at)}, so it can no longer be signed. Nothing was signed and nothing was sent. Ask the agent to request a new approval, and it will appear in this list.</div>}
          {/* An owner who has just read the exact amount and decided no had to
              close this review and hunt for the row's Reject. Same call, same
              two-press confirmation. */}
          {reviewedOperation && confirmReject === reviewedOperation.operation_id && (
            <div className="agent-warning" role="alert">{REJECT_PAYMENT_WARNING}</div>
          )}
          {/* Before the controls, not after them: the owner has just read the
              exact amount and needs to know what a yes actually does here. In a
              pilot build it signs and stops for the phone; it does not pay. */}
          <p className="agent-warning" role="status">{APPROVE_OUTCOME_NOTICE[approvalOutcome(overview)]}</p>
          <div className="agent-confirm-row"><button type="button" disabled={busy} onClick={() => { setApproval(null); setStanding("unverified"); setConfirmReject(null); }}>Cancel</button>
          {reviewedOperation && (
            confirmReject === reviewedOperation.operation_id
              ? <button type="button" className="agent-danger" disabled={busy} onClick={() => rejectOperation(reviewedOperation)}>Confirm reject</button>
              : <button type="button" className="agent-danger" disabled={busy} onClick={() => setConfirmReject(reviewedOperation.operation_id)}>{DESKTOP_CONTROLS.reject_payment}</button>
          )}
          {/* Offered in every build again. It was hidden while Rust refused
              every desktop approval under the pilot feature; that refusal is
              gone and the whole approve-to-witness path is executed in
              desktop_witness_flow.rs. What the owner is told afterwards comes
              from the status Rust returned, never from the build, because a
              pilot approval succeeds into signed_awaiting_witness where nothing
              has been submitted yet. */}
          <button type="button" className="agent-primary-action" disabled={busy || approvalIsExpired(approval) || !approvalIsExactAndFeeFree(approval)} onClick={() => void run(async () => { const result = await agentWalletApi.approveDesktop(overview.wallet_id, approval); setApproval(null); setStanding("unverified"); onInfo(approvalResultNotice(result.status)); await Promise.all([load(), onRefreshOverview()]); })}>{DESKTOP_CONTROLS.approve_exact_transaction}</button>
          </div></section>
      )}
      {/* Rare, deliberate, one-off flows. They open by themselves when their
          own state says they are in progress. */}
      <details className="agent-advanced-details agent-section-title">
        <summary>Backup and restore</summary>
        <AgentBackupPanel
          walletId={overview.wallet_id}
          busy={busy}
          run={run}
          onInfo={onInfo}
        />
      </details>
      <details className="agent-advanced-details">
        <summary>Diagnostics export</summary>
        <PilotDiagnosticsPanel
          walletId={overview.wallet_id}
          busy={busy}
          run={run}
          onInfo={onInfo}
        />
      </details>
      <details className="agent-advanced-details" open={rotationNeedsAttention}>
        <summary>
          {DESKTOP_CONTROLS.replace_the_paired_phone}{rotationNeedsAttention ? " (in progress)" : ""}
        </summary>
        <WitnessRotationPanel
          overview={overview}
          busy={busy}
          run={run}
          onInfo={onInfo}
          onRefreshOverview={onRefreshOverview}
        />
      </details>
    </section>
  );
}

function ProvidersPage() { return <section className="agent-panel agent-info-page"><span className="agent-eyebrow">Not enabled</span><h1>Providers</h1><p>Provider discovery and marketplace payments are intentionally unavailable in this release.</p><div className="agent-safe-note">No provider can connect or receive payment through this screen.</div></section>; }
function PageHead({ eyebrow, title, onRefresh, busy }: { eyebrow: string; title: string; onRefresh: () => void; busy: boolean }) { return <div className="agent-page-head"><div><span className="agent-eyebrow">{eyebrow}</span><h1>{title}</h1></div><button type="button" onClick={onRefresh} disabled={busy}>{DESKTOP_CONTROLS.refresh}</button></div>; }
function PolicyInput({ label, value, onChange, type = "text", disabled = false }: { label: string; value: string; onChange: (value: string) => void; type?: "text" | "number"; disabled?: boolean }) { return <label className="agent-field">{label}<input type={type} inputMode="decimal" min={type === "number" ? 0 : undefined} value={value} disabled={disabled} onChange={(event) => onChange(event.target.value)} /></label>; }
function PolicyArea({ label, value, onChange, disabled = false }: { label: string; value: string; onChange: (value: string) => void; disabled?: boolean }) { return <label className="agent-field">{label}<textarea rows={5} value={value} disabled={disabled} onChange={(event) => onChange(event.target.value)} spellCheck={false} /></label>; }
function StatusBadge({ status, label }: { status: AgentRecord["status"]; label?: string }) { return <span className={"agent-status " + (status === "active" ? "ok" : "stopped")}>{label ?? status}</span>; }
function Detail({ label, value, wide = false }: { label: string; value: string; wide?: boolean }) { return <div className={wide ? "wide" : ""}><dt>{label}</dt><dd>{value}</dd></div>; }
function OperationCard({ operation }: { operation: PaymentOperation }) { return <article className="agent-panel agent-operation"><OperationSummary operation={operation} /><dl className="agent-detail-grid"><Detail label="Created" value={formatDate(operation.created_at)} /><Detail label="Expires" value={formatDate(operation.expires_at)} /><Detail label="Agent" value={shortId(operation.agent_id)} /><Detail label="Operation" value={shortId(operation.operation_id)} />{operation.tx_hash && <Detail label="Transaction hash" value={operation.tx_hash} wide />}</dl></article>; }
function OperationSummary({ operation }: { operation: PaymentOperation }) { return <div className="agent-record-head"><div><h2>{formatUnits(operation.amount_units)} to {shortAddress(operation.recipient)}</h2><p>{operation.reason}</p></div><span className="agent-status ok">{operation.status.replace(/_/g, " ")}</span></div>; }
function LoadingState({ label }: { label: string }) { return <div className="agent-panel agent-empty" aria-live="polite">{label}...</div>; }
/**
 * An empty state that names an action now has to offer it. Three of these named
 * a screen or a control and rendered nothing the owner could press.
 */
function EmptyState({ title, body, action, onAction }: { title: string; body: string; action?: string; onAction?: () => void }) {
  return (
    <div className="agent-panel agent-empty">
      <h2>{title}</h2>
      <p>{body}</p>
      {action && onAction && (
        <button type="button" className="agent-primary-action" onClick={onAction}>{action}</button>
      )}
    </div>
  );
}
function LoadFailure({ message, onRetry }: { message: string; onRetry: () => void }) { return <div className="alert" role="alert"><span>{message}</span><button type="button" onClick={onRetry}>Retry</button></div>; }

export function policyToDraft(policy: AgentPolicy): PolicyDraft { return { maxPerPayment: unitsToDecimal(policy.max_per_payment_units), maxDaily: unitsToDecimal(policy.max_daily_units), maxPending: String(policy.max_pending_operations), allowedRecipients: policy.allowed_recipients.join("\n"), blockedRecipients: policy.blocked_recipients.join("\n"), allowUnlistedWithApproval: policy.allow_unlisted_recipient_with_approval, approvalMode: policy.approval_mode, permissions: [...policy.permissions] }; }
export function validateDraft(draft: PolicyDraft, policyEpoch: number): { policy: AgentPolicy | null; error: string } {
  if (draft.approvalMode !== "desktop_manual") return { policy: null, error: "This existing mobile approval policy is read-only and remains blocked until end-to-end mobile approvals are production-ready." };
  const perPayment = decimalToUnits(draft.maxPerPayment); const daily = decimalToUnits(draft.maxDaily);
  if (perPayment === null || daily === null) return { policy: null, error: "Limits must be non-negative HAC amounts with no more than six decimal places." };
  if (BigInt(perPayment) > BigInt(daily)) return { policy: null, error: "Maximum per request cannot exceed the daily limit." };
  if (!/^\d+$/.test(draft.maxPending) || Number(draft.maxPending) > 65_535) return { policy: null, error: "Maximum pending requests must be an integer from 0 to 65535." };
  const allowed = uniqueLines(draft.allowedRecipients); const blocked = uniqueLines(draft.blockedRecipients);
  if (allowed.length > 256 || blocked.length > 256) return { policy: null, error: "Recipient lists support at most 256 addresses each." };
  const blockedSet = new Set(blocked); if (allowed.some((address) => blockedSet.has(address))) return { policy: null, error: "The same address cannot be both allowed and blocked." };
  return { policy: { permissions: [...new Set(draft.permissions)], max_per_payment_units: perPayment, max_daily_units: daily, max_pending_operations: Number(draft.maxPending), allowed_recipients: allowed, blocked_recipients: blocked, allow_unlisted_recipient_with_approval: draft.allowUnlistedWithApproval, approval_mode: draft.approvalMode, policy_epoch: policyEpoch }, error: "" };
}
function approvalModeLabel(mode: ApprovalMode): string { if (mode === "desktop_manual") return "Desktop only"; if (mode === "mobile_manual") return "Paired mobile only (unavailable)"; return "Either trusted device (unavailable)"; }
function decimalToUnits(value: string): string | null { const match = value.trim().match(/^(0|[1-9]\d*)(?:\.(\d{1,6}))?$/); if (!match) return null; try { const units = BigInt(match[1]) * 1_000_000n + BigInt((match[2] ?? "").padEnd(6, "0") || "0"); return units <= 18_446_744_073_709_551_615n ? units.toString() : null; } catch { return null; } }
function unitsToDecimal(raw: string): string { try { const units = BigInt(raw); const fraction = (units % 1_000_000n).toString().padStart(6, "0").replace(/0+$/, ""); return String(units / 1_000_000n) + (fraction ? "." + fraction : ""); } catch { return ""; } }
function uniqueLines(value: string): string[] { return [...new Set(value.split(/\r?\n/).map((line) => line.trim()).filter(Boolean))]; }
/**
 * Whether the address in an approval is one the owner has already vetted.
 *
 * "not_on_allowlist" is the honest name for what is checked. It does not claim
 * the address has never been paid: approving a payment deliberately does not
 * add the address to the allowlist, so a second payment to the same address is
 * reported as not on the allowlist again, and asks again.
 */
export type RecipientStanding = "allowlisted" | "not_on_allowlist" | "unverified";

export function recipientStanding(recipient: string, policy: AgentPolicy | null): RecipientStanding {
  if (!policy) return "unverified";
  return policy.allowed_recipients.includes(recipient) ? "allowlisted" : "not_on_allowlist";
}

const RECIPIENT_STANDING_LABEL: Record<RecipientStanding, string> = {
  allowlisted: "Allowed recipient",
  not_on_allowlist: "New recipient. This address is not on this agent's allowlist.",
  unverified: "Recipient not checked. This agent's rules could not be read.",
};

const RECIPIENT_STANDING_DETAIL: Record<RecipientStanding, string> = {
  allowlisted: "You added this address to this agent's allowed recipients. Check it anyway.",
  not_on_allowlist:
    "Approval covers this one payment only. The address is not added to the allowlist, so a later payment to it asks again. Read every character before approving.",
  unverified:
    "The allowlist could not be loaded, so this address could not be compared against it. Read every character before approving.",
};

/**
 * The version this desktop will approve, and the binding that has to come with
 * it.
 *
 * This used to admit "2" only. A Testnet Pilot build issues "3"
 * (`create_payment_intent` in crates/agent-wallet-core/src/service/payment.rs),
 * so with the Approve control restored, a v3 commitment - every real pilot
 * approval - would have been reported to the owner as malformed and the button
 * would have stayed disabled forever.
 *
 * The pairing is not loosened, it is mirrored: Rust's own
 * `ApprovalCommitment::validate` admits exactly (2, no binding) and
 * (3, binding), and so does this. A v3 commitment that arrived without its
 * network binding, or a v2 one that arrived with one, is still refused.
 */
function approvalVersionMatchesBinding(approval: ApprovalCommitment): boolean {
  const binding = approval.network_binding;
  if (approval.approval_version === "2") return !binding;
  if (approval.approval_version !== "3" || !binding) return false;
  return (
    typeof binding.network_id === "string" &&
    binding.network_id.length > 0 &&
    typeof binding.genesis_identifier === "string" &&
    binding.genesis_identifier.length > 0 &&
    typeof binding.node_profile_id === "string" &&
    binding.node_profile_id.length > 0 &&
    Number.isSafeInteger(binding.chain_id) &&
    Number.isSafeInteger(binding.transaction_format_version)
  );
}

export function approvalIsExactAndFeeFree(approval: ApprovalCommitment): boolean {
  if (
    !approvalVersionMatchesBinding(approval) ||
    !/^[0-9a-f]{32}$/i.test(approval.challenge_nonce) ||
    !/^[0-9a-f]{64}$/i.test(approval.transaction_commitment) ||
    !approval.agent_wallet_id ||
    !approval.agent_id ||
    !approval.desktop_device_id ||
    !approval.operation_id ||
    !approval.approval_id ||
    !approval.recipient
  ) return false;
  try {
    const amount = parseStrictU64(approval.amount_units);
    const networkFee = parseStrictU64(approval.fee_units);
    const walletFee = parseStrictU64(approval.wallet_fee_units);
    const total = parseStrictU64(approval.total_debit_units);
    const policyEpoch = parseStrictU64(approval.policy_epoch);
    const issuedAt = parseSafeUnixSeconds(approval.issued_at);
    const expiresAt = parseSafeUnixSeconds(approval.expires_at);
    return amount !== null && amount > 0n && networkFee === 1_000n && walletFee === 0n && total !== null &&
      total === amount + networkFee && policyEpoch !== null && policyEpoch > 0n &&
      issuedAt !== null && expiresAt !== null && expiresAt > issuedAt;
  } catch {
    return false;
  }
}
function approvalIsExpired(approval: ApprovalCommitment): boolean {
  const expiresAt = parseSafeUnixSeconds(approval.expires_at);
  return expiresAt === null || Math.floor(Date.now() / 1_000) >= expiresAt;
}
function parseStrictU64(raw: string): bigint | null {
  if (!/^(0|[1-9]\d{0,19})$/.test(raw)) return null;
  try {
    const value = BigInt(raw);
    return value <= 18_446_744_073_709_551_615n ? value : null;
  } catch {
    return null;
  }
}
function parseSafeUnixSeconds(raw: string | number): number | null {
  if (typeof raw === "number") return Number.isSafeInteger(raw) && raw >= 0 ? raw : null;
  const value = parseStrictU64(raw);
  return value !== null && value <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(value) : null;
}
function formatUnits(raw: string): string { const value = unitsToDecimal(raw); return value ? value + " HAC" : "Invalid amount"; }
function formatDate(raw: string | number): string { const unix = parseSafeUnixSeconds(raw); if (unix === null || unix > Number.MAX_SAFE_INTEGER / 1_000) return "Invalid time"; const date = new Date(unix * 1_000); return Number.isNaN(date.getTime()) ? "Invalid time" : date.toLocaleString(); }
/**
 * One HAC in chain zhu.
 *
 * This is the L1 chain's own unit and not the Agent ledger's. The two differ by
 * a hundred, and this file previously used the Agent ledger's `1_000_000`
 * against amounts that arrive in chain zhu, so every deposit, fee and refund on
 * the registry screens read a hundred times larger than it was and the deposit
 * an owner typed was a hundred times smaller than they meant.
 *
 * Three independent anchors in this repository fix the value, and any one of
 * them failing should stop this constant from being changed back:
 *   - `crates/l2-fast-pay-hub/src/node.rs` asserts
 *     `parse_fin_balance_zhu("1:248") == 100_000_000`, and `1:248` is one HAC;
 *   - `crates/wallet-core/src/wallet/authorization_service.rs` formats HAC with
 *     `const ZHU_PER_HAC: u64 = 100_000_000`;
 *   - `crates/l2-fast-pay-hub/src/readiness.rs` sets
 *     `ZHU_PER_MILLIMEI = 100_000`, and a millimei is a thousandth of a HAC.
 *
 * `AgentHvmOperationsPanel` is deliberately *not* the reference: its
 * `formatHacUnits` divides by 1_000_000 because it renders `HacUnits`, the
 * Agent ledger's 1e-6 unit (`crates/agent-wallet-core/src/amount.rs`,
 * `PER_HAC = 1_000_000`). Copying that formatter onto chain zhu is the mistake
 * this constant exists to prevent.
 */
const ZHU_PER_HAC = 100_000_000n;
const ZHU_FRACTION_DIGITS = 8;
/** An exact chain-zhu amount as HAC. */
export function formatZhu(raw: string): string {
  try {
    const zhu = BigInt(raw);
    const whole = zhu / ZHU_PER_HAC;
    const fraction = (zhu % ZHU_PER_HAC)
      .toString()
      .padStart(ZHU_FRACTION_DIGITS, "0")
      .replace(/0+$/, "");
    return fraction ? `${whole}.${fraction} HAC` : `${whole} HAC`;
  } catch {
    return "Invalid amount";
  }
}
/**
 * A typed HAC deposit as exact zhu, or null when it is not a deposit.
 *
 * The inverse of `formatZhu`, and deliberately strict rather than forgiving:
 * this number decides how much of an owner's money stops being theirs to spend,
 * so anything but a plain positive decimal with at most eight places is refused
 * outright instead of being rounded into something the screen never showed
 * them. `Number.MAX_SAFE_INTEGER` bounds it because the value crosses the IPC
 * boundary as a JSON number.
 *
 * Eight places, not six, because chain zhu is 1e-8 HAC. At six this returned a
 * number a hundred times smaller than the owner typed, and Rust then refused
 * the open outright against `binding.left_deposit_zhu`
 * (`OPEN_CHANNEL_DEPOSIT_MISMATCH`), so the only way to open a fifty HAC
 * channel was to type five thousand into a field labelled HAC.
 */
export function depositHacToZhu(raw: string): number | null {
  const text = raw.trim();
  if (!/^\d+(?:\.\d{1,8})?$/.test(text)) return null;
  const [whole, fraction = ""] = text.split(".");
  const zhu =
    BigInt(whole) * ZHU_PER_HAC + BigInt(fraction.padEnd(ZHU_FRACTION_DIGITS, "0"));
  if (zhu <= 0n || zhu > BigInt(Number.MAX_SAFE_INTEGER)) return null;
  return Number(zhu);
}
/**
 * Whether a pasted string is a JSON object at all.
 *
 * The only judgement made on this side. Everything about what the object means
 * is decided in Rust, where the channel is validated against the reviewed
 * profile and the deposit inside it is compared with the one the owner typed;
 * this exists so the confirm press is not offered for text that cannot even be
 * parsed, and it deliberately claims nothing more than that.
 */
export function isJsonObject(raw: string): boolean {
  try {
    const parsed: unknown = JSON.parse(raw);
    return typeof parsed === "object" && parsed !== null && !Array.isArray(parsed);
  } catch {
    return false;
  }
}
function shortId(value: string): string { return value.length > 20 ? value.slice(0, 10) + "..." + value.slice(-6) : value; }
function shortAddress(value: string): string { return value.length > 22 ? value.slice(0, 10) + "..." + value.slice(-8) : value; }
function readableError(reason: unknown): string { return reason instanceof Error ? reason.message : typeof reason === "string" ? reason : "Agent Wallet operation failed."; }

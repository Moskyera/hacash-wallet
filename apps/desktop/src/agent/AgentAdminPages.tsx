import { useCallback, useEffect, useMemo, useState } from "react";
import {
  agentWalletApi,
  type AgentPermission,
  type AgentPolicy,
  type AgentRecord,
  type AgentWalletOverview,
  type ApprovalCommitment,
  type ApprovalMode,
  type PaymentOperation,
} from "./api";
import { PilotDiagnosticsPanel } from "./PilotDiagnosticsPanel";
import { WitnessRotationPanel } from "./WitnessRotationPanel";
import {
  emergencyStopControl,
  type AgentWalletWriteReadiness,
} from "./access";
import { DESKTOP_CONTROLS } from "./desktopControls";
import {
  APPROVE_TRANSACTION_WARNING,
  EMERGENCY_STOP_WARNING,
  REJECT_PAYMENT_WARNING,
  REVOKE_AGENT_WARNING,
} from "./irreversibleActions";

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
          body="No local agent currently has access to this Agent Wallet."
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

type PolicyDraft = {
  maxPerPayment: string;
  maxDaily: string;
  maxPending: string;
  allowedRecipients: string;
  blockedRecipients: string;
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
          body="Pair an agent before defining spending permissions."
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
              <div className="agent-warning" role="alert">This existing policy uses a mobile approval mode that is not production-ready. It is preserved unchanged and this policy is read-only. Agent payments remain blocked until a supported approval path is available.</div>
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
          </section>
          {validation.error && <div className="alert" role="alert">{validation.error}</div>}
          {!review ? <button type="button" className="agent-primary-action" disabled={busy || !validation.policy || !selectedAgent} onClick={() => {
            if (selectedAgent && validation.policy) setReview(createPolicyReview(selectedAgent, validation.policy));
          }}>Review policy change</button> : (
            <section className="agent-panel agent-review">
              <span className="agent-eyebrow">Final confirmation</span><h2>Apply policy epoch {review.policy.policy_epoch + 1}</h2>
              <p>The fields above are frozen. Saving persists this exact reviewed snapshot and disconnects existing authenticated sessions for {review.agentName}.</p>
              <dl className="agent-detail-grid">
                <Detail label="Maximum per request" value={formatUnits(review.policy.max_per_payment_units)} />
                <Detail label="Maximum per day" value={formatUnits(review.policy.max_daily_units)} />
                <Detail label="Maximum pending" value={String(review.policy.max_pending_operations)} />
                <Detail label="Approval" value={approvalModeLabel(review.policy.approval_mode)} />
                <Detail label="Permissions" value={review.policy.permissions.join(", ") || "None"} wide />
                <Detail label="Allowed recipients" value={review.policy.allowed_recipients.join(", ") || "None (default deny)"} wide />
                <Detail label="Blocked recipients" value={review.policy.blocked_recipients.join(", ") || "None"} wide />
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

function ActivityPage({ overview, busy, onOpenPage }: AdminPageProps) {
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
  const [confirmReject, setConfirmReject] = useState<string | null>(null);
  const [error, setError] = useState("");
  const load = useCallback(async () => { setError(""); try { setPending(await agentWalletApi.listPendingApprovals(overview.wallet_id)); } catch (reason) { setPending(null); setError(readableError(reason)); } }, [overview.wallet_id]);
  useEffect(() => { void load(); }, [load]);
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
      onInfo("Payment request rejected. No transaction was signed.");
      await Promise.all([load(), onRefreshOverview()]);
    });
  const reviewedOperation = approval
    ? pending?.find((operation) => operation.operation_id === approval.operation_id) ?? null
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
      {/* Deciding a payment is the job of this page. It used to render below a
          diagnostics panel and a full rotation wizard, both permanently open. */}
      <h2 className="agent-section-title">Pending approvals</h2>
      {error && <LoadFailure message={error} onRetry={() => void load()} />}{pending === null && !error && <LoadingState label="Loading approvals" />}{pending?.length === 0 && <EmptyState title="No pending approvals" body="There is nothing waiting for a signing decision." />}
      <div className="agent-card-list">{pending?.map((operation) => (
        <article className="agent-panel agent-operation" key={operation.operation_id}><OperationSummary operation={operation} /><div className="agent-confirm-row">
          {confirmReject === operation.operation_id ? <><p className="agent-warning">{REJECT_PAYMENT_WARNING}</p><button type="button" disabled={busy} onClick={() => setConfirmReject(null)}>Cancel</button><button type="button" className="agent-danger" disabled={busy} onClick={() => rejectOperation(operation)}>Confirm reject</button></> : <>
            <button type="button" className="agent-danger" disabled={busy} onClick={() => setConfirmReject(operation.operation_id)}>{DESKTOP_CONTROLS.reject_payment}</button>
            <button type="button" className="agent-primary-action" disabled={busy} onClick={() => void run(async () => { setApproval(await agentWalletApi.pendingApproval(overview.wallet_id, operation.operation_id)); setConfirmReject(null); })}>{DESKTOP_CONTROLS.review_exact_transaction}</button>
          </>}
        </div></article>
      ))}</div>
      {approval && (
        <section className="agent-panel agent-approval-review" aria-label="Exact transaction approval"><span className="agent-eyebrow">Exact transaction review</span><h2>{formatUnits(approval.amount_units)} to {approval.recipient}</h2><dl className="agent-detail-grid"><Detail label="Network fee" value={formatUnits(approval.fee_units)} /><Detail label="HPAY wallet fee" value={approval.wallet_fee_units === "0" ? "None" : "Blocked: invalid fee"} /><Detail label="Total debit" value={formatUnits(approval.total_debit_units)} /><Detail label="Expires" value={formatDate(approval.expires_at)} /><Detail label="Agent" value={approval.agent_id} wide /><Detail label="Transaction commitment" value={approval.transaction_commitment} wide /></dl><div className="agent-warning">{APPROVE_TRANSACTION_WARNING}</div>{!approvalIsExactAndFeeFree(approval) && <div className="alert" role="alert">This approval is malformed or contains a wallet fee. Signing is blocked.</div>}
          {/* An owner who has just read the exact amount and decided no had to
              close this review and hunt for the row's Reject. Same call, same
              two-press confirmation. */}
          {reviewedOperation && confirmReject === reviewedOperation.operation_id && (
            <div className="agent-warning" role="alert">{REJECT_PAYMENT_WARNING}</div>
          )}
          <div className="agent-confirm-row"><button type="button" disabled={busy} onClick={() => { setApproval(null); setConfirmReject(null); }}>Cancel</button>
          {reviewedOperation && (
            confirmReject === reviewedOperation.operation_id
              ? <button type="button" className="agent-danger" disabled={busy} onClick={() => rejectOperation(reviewedOperation)}>Confirm reject</button>
              : <button type="button" className="agent-danger" disabled={busy} onClick={() => setConfirmReject(reviewedOperation.operation_id)}>{DESKTOP_CONTROLS.reject_payment}</button>
          )}
          <button type="button" className="agent-primary-action" disabled={busy || approvalIsExpired(approval) || !approvalIsExactAndFeeFree(approval)} onClick={() => void run(async () => { const result = await agentWalletApi.approveDesktop(overview.wallet_id, approval); setApproval(null); onInfo(result.status === "broadcast_uncertain" ? "Broadcast status is uncertain. Do not retry automatically." : "The exact approved transaction was submitted."); await Promise.all([load(), onRefreshOverview()]); })}>{DESKTOP_CONTROLS.approve_exact_transaction}</button></div></section>
      )}
      {/* Rare, deliberate, one-off flows. They open by themselves when their
          own state says they are in progress. */}
      <details className="agent-advanced-details agent-section-title">
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
          Replace the paired phone{rotationNeedsAttention ? " (in progress)" : ""}
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

function policyToDraft(policy: AgentPolicy): PolicyDraft { return { maxPerPayment: unitsToDecimal(policy.max_per_payment_units), maxDaily: unitsToDecimal(policy.max_daily_units), maxPending: String(policy.max_pending_operations), allowedRecipients: policy.allowed_recipients.join("\n"), blockedRecipients: policy.blocked_recipients.join("\n"), approvalMode: policy.approval_mode, permissions: [...policy.permissions] }; }
function validateDraft(draft: PolicyDraft, policyEpoch: number): { policy: AgentPolicy | null; error: string } {
  if (draft.approvalMode !== "desktop_manual") return { policy: null, error: "This existing mobile approval policy is read-only and remains blocked until end-to-end mobile approvals are production-ready." };
  const perPayment = decimalToUnits(draft.maxPerPayment); const daily = decimalToUnits(draft.maxDaily);
  if (perPayment === null || daily === null) return { policy: null, error: "Limits must be non-negative HAC amounts with no more than six decimal places." };
  if (BigInt(perPayment) > BigInt(daily)) return { policy: null, error: "Maximum per request cannot exceed the daily limit." };
  if (!/^\d+$/.test(draft.maxPending) || Number(draft.maxPending) > 65_535) return { policy: null, error: "Maximum pending requests must be an integer from 0 to 65535." };
  const allowed = uniqueLines(draft.allowedRecipients); const blocked = uniqueLines(draft.blockedRecipients);
  if (allowed.length > 256 || blocked.length > 256) return { policy: null, error: "Recipient lists support at most 256 addresses each." };
  const blockedSet = new Set(blocked); if (allowed.some((address) => blockedSet.has(address))) return { policy: null, error: "The same address cannot be both allowed and blocked." };
  return { policy: { permissions: [...new Set(draft.permissions)], max_per_payment_units: perPayment, max_daily_units: daily, max_pending_operations: Number(draft.maxPending), allowed_recipients: allowed, blocked_recipients: blocked, approval_mode: draft.approvalMode, policy_epoch: policyEpoch }, error: "" };
}
function approvalModeLabel(mode: ApprovalMode): string { if (mode === "desktop_manual") return "Desktop only"; if (mode === "mobile_manual") return "Paired mobile only (unavailable)"; return "Either trusted device (unavailable)"; }
function decimalToUnits(value: string): string | null { const match = value.trim().match(/^(0|[1-9]\d*)(?:\.(\d{1,6}))?$/); if (!match) return null; try { const units = BigInt(match[1]) * 1_000_000n + BigInt((match[2] ?? "").padEnd(6, "0") || "0"); return units <= 18_446_744_073_709_551_615n ? units.toString() : null; } catch { return null; } }
function unitsToDecimal(raw: string): string { try { const units = BigInt(raw); const fraction = (units % 1_000_000n).toString().padStart(6, "0").replace(/0+$/, ""); return String(units / 1_000_000n) + (fraction ? "." + fraction : ""); } catch { return ""; } }
function uniqueLines(value: string): string[] { return [...new Set(value.split(/\r?\n/).map((line) => line.trim()).filter(Boolean))]; }
export function approvalIsExactAndFeeFree(approval: ApprovalCommitment): boolean {
  if (
    approval.approval_version !== "2" ||
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
function shortId(value: string): string { return value.length > 20 ? value.slice(0, 10) + "..." + value.slice(-6) : value; }
function shortAddress(value: string): string { return value.length > 22 ? value.slice(0, 10) + "..." + value.slice(-8) : value; }
function readableError(reason: unknown): string { return reason instanceof Error ? reason.message : typeof reason === "string" ? reason : "Agent Wallet operation failed."; }
import { useState } from "react";
import {
  COMPANION_REFRESH_ACTION,
  COMPANION_REVIEW_APPROVAL_ACTION,
} from "./companionStatus";

/**
 * How the read-only tabs point at the one control that would fill them.
 *
 * Deliberately not a quoted label. There is exactly one connect control on the
 * screen, and it reads "Connect to the desktop" from cold and "Try connecting
 * again" after a refusal, because that is what every failure sentence tells the
 * owner to tap. Quoting either name would be wrong in the other state.
 */
const CONNECT_ROUTE =
  "Use the connect button on this screen once HPAY Desktop is open and unlocked on the same Wi-Fi.";
import {
  authorizedAgentForApproval,
  formatCompanionNodeStatus,
  formatCompanionTime,
  formatHacUnits,
  shortValue,
  verifiedAgentApprovalFacts,
} from "./companionView";
import type {
  AgentCompanionAgent,
  AgentCompanionPendingApproval,
  AgentCompanionPolicy,
  AgentCompanionSnapshot,
} from "./types";

export function CompanionOverview({
  snapshot,
  onOpenActivity,
}: {
  snapshot: AgentCompanionSnapshot | null;
  onOpenActivity?: () => void;
}) {
  if (!snapshot) {
    return (
      <Unavailable
        title="Wallet status unavailable"
        body={`No figure is shown until a fresh authenticated snapshot arrives from the paired desktop, and no value is assumed to be zero. ${CONNECT_ROUTE}`}
      />
    );
  }

  const primaryAgent = snapshot.agents.find((agent) => agent.authorization === "authorized")
    ?? snapshot.agents[0]
    ?? null;
  const dailyPolicy = primaryAgent
    ? snapshot.policies.find((policy) => policy.agentId === primaryAgent.agentId) ?? null
    : null;

  return (
    <>
      <section className="agent-overview-hero">
        <div className="agent-overview-agent">
          <div className="agent-robot-orb compact" aria-hidden>
            <svg viewBox="0 0 24 24"><rect x="5" y="7" width="14" height="12" rx="3" /><path d="M12 3v4M8 12h.01M16 12h.01M9 16h6" /></svg>
          </div>
          <div>
            <p className="agent-eyebrow">Agent status</p>
            <h2>{primaryAgent?.displayName ?? "Agent Wallet"}</h2>
            <span className={`agent-live-state ${snapshot.wallet.paused ? "paused" : "ready"}`}>
              {snapshot.wallet.paused ? "Paused on desktop" : authorizationLabel(primaryAgent?.authorization ?? "disabled")}
            </span>
          </div>
        </div>

        <div className="agent-wallet-balance">
          <span>Available balance</span>
          <strong>{formatHacUnits(snapshot.wallet.availableUnits)}</strong>
          <small>{shortValue(snapshot.wallet.address)}</small>
        </div>

        {/* The old bar drew wallet-wide committed spending against one agent's
            cap. Enforcement instead uses exposure_for_agent_in_window, which is
            per agent and also counts reservations, so the bar could read well
            under the limit at the moment a payment was refused. Protocol v3 does
            not carry the inputs needed to compute the real figure, so no number
            is drawn rather than a wrong one. */}
        <AllowanceUnavailable limit={dailyPolicy?.maximumPerDayUnits ?? null} />

        <dl className="agent-overview-facts">
          <Detail label="Node" value={formatCompanionNodeStatus(snapshot.wallet.nodeStatus)} />
          <Detail label="Snapshot" value={formatCompanionTime(snapshot.session.snapshotIssuedAtUnix)} />
        </dl>
      </section>

      <section className="agent-metric-grid" aria-label="Agent Wallet balances">
        {/* These come from spent_in_window, which counts only committed
            operations across the whole wallet, over rolling 86_400 and
            31 * 86_400 second windows. Naming them for what they count keeps
            them from being read as the enforced per agent budget. */}
        <Metric label="Reserved" value={formatHacUnits(snapshot.wallet.reservedUnits)} />
        <Metric
          label="Completed, last 24 hours"
          value={formatHacUnits(snapshot.wallet.spentTodayUnits)}
        />
        <Metric
          label="Completed, last 31 days"
          value={formatHacUnits(snapshot.wallet.spentMonthUnits)}
        />
        <Metric label="Pending approvals" value={String(snapshot.pendingApprovals.length)} />
      </section>

      {/* The pill on the hero said "Paused on desktop" and stopped there: no
          statement of what it blocks, and no route to the one control that
          clears it. Nothing on a phone can clear it, and that is the point. */}
      {snapshot.wallet.paused ? (
        <p className="agent-blocked-note" role="status">
          Agent payments are stopped on HPAY Desktop, so no agent payment can
          start. No button on this phone can clear it. On HPAY Desktop open AI
          Agent Wallet, find Payment control and use Enable locally.
        </p>
      ) : null}

      {snapshot.pendingApprovals.length > 0 && onOpenActivity ? (
        <button
          type="button"
          className="agent-pending-shortcut"
          onClick={onOpenActivity}
        >
          Review {snapshot.pendingApprovals.length} pending testnet {snapshot.pendingApprovals.length === 1 ? "request" : "requests"}
        </button>
      ) : null}

      {/* Three closing paragraphs, sixty-eight words, on the screen an owner
          opens most. The line that changes a reading of the figures above it
          stays; the reasoning behind it, the read-only footnote and the reach
          of the desktop emergency stop are one tap away, each still complete. */}
      <p className="agent-muted">
        These totals are wallet-wide, not the enforced budget.
      </p>
      <details className="agent-disclosure">
        <summary>Why is that not the budget?</summary>
        <p className="agent-muted">
          Completed totals cover every agent in this wallet and count only
          payments that finished. They are not the value the spending limits are
          enforced against.
        </p>
        <p className="agent-readonly-footnote">
          {snapshot.pilotEnabled
            ? "Exact testnet requests can be reviewed in Activity. Rules and arbitrary signing remain on the trusted desktop."
            : "Spending rules, signing and payment approval remain on the trusted desktop."}
        </p>
      </details>
      <details className="agent-disclosure agent-emergency-note">
        <summary>Emergency stop is currently available from HPAY Desktop</summary>
        <p>
          There, Disable All Agent Payments blocks new agent payment progress and
          invalidates active permits. It cannot reverse a transaction that has
          already been submitted to the network.
        </p>
      </details>
    </>
  );
}
export function CompanionAgents({
  snapshot,
}: {
  snapshot: AgentCompanionSnapshot | null;
}) {
  if (!snapshot) {
    return (
      <Unavailable
        title="Agents unavailable"
        body={`This list comes from the paired desktop and no fresh snapshot has arrived. ${CONNECT_ROUTE}`}
      />
    );
  }
  if (snapshot.agents.length === 0) {
    return <Unavailable title="No agents reported" body="The desktop snapshot contains no agent records." />;
  }
  return (
    <section className="agent-list" aria-label="Agent authorization records">
      {snapshot.agents.map((agent) => (
        <article className="agent-panel" key={agent.agentId}>
          <div className="agent-record-head">
            <div>
              <h2>{agent.displayName}</h2>
              <p className="agent-muted">{shortValue(agent.agentId)}</p>
            </div>
            <span className="agent-state-pill">
              {authorizationLabel(agent.authorization)}
            </span>
          </div>
        </article>
      ))}
    </section>
  );
}

export function CompanionRules({
  snapshot,
}: {
  snapshot: AgentCompanionSnapshot | null;
}) {
  if (!snapshot) {
    return (
      <Unavailable
        title="Policies unavailable"
        body={`This tab comes from the paired desktop and no fresh snapshot has arrived. ${CONNECT_ROUTE}`}
      />
    );
  }
  if (snapshot.policies.length === 0) {
    // filter_snapshot_for_permissions in wallet-tauri-common sends an empty
    // policy list to every paired device, so this is the permanent state on a
    // phone rather than a missing capability the owner could switch on.
    return (
      <Unavailable
        title="Spending rules stay on the desktop"
        body="Spending limits are never sent to a phone, so this tab stays empty by design. Open the Agent Wallet on your trusted desktop and choose Rules to read or change them."
      />
    );
  }
  return (
    <section className="agent-list" aria-label="Read-only policy summaries">
      {snapshot.policies.map((policy) => (
        <PolicyCard
          key={policy.agentId}
          policy={policy}
          pilotEnabled={snapshot.pilotEnabled}
          agentName={
            snapshot.agents.find((agent) => agent.agentId === policy.agentId)
              ?.displayName ?? shortValue(policy.agentId)
          }
        />
      ))}
      {/* The same fifty-five words used to close every card, so a wallet with
          three agents printed them three times. They apply to all the cards, so
          they are said once, under the list, and folded away. */}
      <details className="agent-disclosure">
        <summary>How these limits are counted</summary>
        <p className="agent-muted">
          The per request limit includes the payment amount and the Hacash network
          fee. The 24 hour limit is a rolling window, not a calendar day, and
          pending or reserved payment requests may count toward enforcement.
        </p>
        <p className="agent-muted">
          Enforceable remaining allowance is calculated on HPAY Desktop and is not
          included in Companion Protocol v3. Policy data is read only on this device.
        </p>
      </details>
    </section>
  );
}

function PolicyCard({
  policy,
  agentName,
  pilotEnabled,
}: {
  policy: AgentCompanionPolicy;
  agentName: string;
  pilotEnabled: boolean;
}) {
  return (
    <article className="agent-panel">
      <h2>{agentName}</h2>
      <dl className="agent-detail-list">
        {/* validate_policy_for_request compares the cap against total_debit, not
            against the payment amount, and the daily window is a rolling 86_400
            seconds that also counts operations still holding a reservation. The
            old labels described neither, so a request could be refused at a
            figure the owner had been shown as allowed. */}
        <Detail
          label="Maximum total debit per request"
          value={formatHacUnits(policy.maximumPerRequestUnits)}
        />
        <Detail
          label="Rolling 24-hour spending limit"
          value={formatHacUnits(policy.maximumPerDayUnits)}
        />
        <Detail label="Pending operation limit" value={String(policy.maximumPendingOperations)} />
        <Detail label="Approval route" value={approvalModeLabel(policy.approvalMode, pilotEnabled)} />
        <Detail
          label="Permissions"
          value={policy.permissions.length ? policy.permissions.join(", ") : "None"}
        />
        <Detail
          label="Allowed recipients"
          value={
            policy.allowedRecipients.length
              ? policy.allowedRecipients.map(shortValue).join(", ")
              : "None listed"
          }
        />
        <Detail
          label="Blocked recipients"
          value={
            policy.blockedRecipients.length
              ? policy.blockedRecipients.map(shortValue).join(", ")
              : "None listed"
          }
        />
      </dl>
    </article>
  );
}

export function CompanionActivity({
  snapshot,
  busy = false,
  onRefresh,
  onDecision,
}: {
  snapshot: AgentCompanionSnapshot | null;
  busy?: boolean;
  /** Reloads the desktop's list. Absent when there is no live connection. */
  onRefresh?: () => void;
  onDecision?: (
    approval: AgentCompanionPendingApproval,
    decision: "approve" | "reject",
  ) => void;
}) {
  const [selectedApprovalId, setSelectedApprovalId] = useState<string | null>(null);
  if (!snapshot) {
    return (
      <Unavailable
        title="Activity unavailable"
        body={`Requests waiting for your decision come from the paired desktop and no fresh snapshot has arrived. ${CONNECT_ROUTE}`}
      />
    );
  }
  const selectedApproval = selectedApprovalId
    ? snapshot.pendingApprovals.find(
        (approval) => approval.approvalId === selectedApprovalId,
      ) ?? null
    : null;
  // Recent activity is blank by design on every phone, and it used to render
  // above the only actionable thing in the whole app. Whatever is waiting for a
  // decision goes first; the empty-by-design list follows it.
  return (
    <>
      <section className="agent-list" aria-label="Pending testnet approvals">
        <div className="agent-record-head">
          <h2>Pending approvals</h2>
          {/* The stale-request message tells the owner to tap Refresh the
              status now. That button used to live only inside the connection
              card, so on this screen the instruction named a control that was
              not here. */}
          {onRefresh ? (
            <button type="button" disabled={busy} onClick={onRefresh}>
              {COMPANION_REFRESH_ACTION}
            </button>
          ) : null}
        </div>
        {snapshot.pendingApprovals.length === 0 ? (
          <p className="agent-muted">
            No payment needs your approval. Approve and Reject appear here only
            for a fresh, verified testnet request from the paired desktop.
          </p>
        ) : (
          snapshot.pendingApprovals.map((approval) => {
            const facts = verifiedAgentApprovalFacts(approval, snapshot);
            const requestingAgent = authorizedAgentForApproval(approval, snapshot);
            const canReview = Boolean(
              snapshot.pilotEnabled &&
                facts &&
                requestingAgent &&
                onDecision,
            );
            return (
              <article className="agent-panel" key={approval.approvalId}>
                <div className="agent-record-head">
                  <div>
                    <p className="agent-eyebrow">Testnet HAC request</p>
                    <h3>{facts ? formatHacUnits(facts.amountUnits) : "Blocked request"}</h3>
                  </div>
                  <span className="agent-state-pill">
                    {requestingAgent?.displayName ?? "Unknown agent"}
                  </span>
                </div>
                <p className="agent-muted">
                  Recipient {shortValue(approval.recipient)}
                </p>
                <dl className="agent-detail-list">
                  <Detail
                    label="Network fee"
                    value={facts ? formatHacUnits(facts.networkFeeUnits) : "Blocked"}
                  />
                  <Detail
                    label="HPAY wallet fee"
                    value={facts?.walletFeeUnits === "0" ? "None" : "Blocked"}
                  />
                  <Detail
                    label="Total debit"
                    value={facts ? formatHacUnits(facts.totalDebitUnits) : "Blocked"}
                  />
                  <Detail label="Expires" value={formatCompanionTime(approval.expiresAtUnix)} />
                </dl>
                {canReview ? (
                  <button
                    type="button"
                    className="agent-primary-action"
                    disabled={busy}
                    onClick={() => setSelectedApprovalId(approval.approvalId)}
                  >
                    {COMPANION_REVIEW_APPROVAL_ACTION}
                  </button>
                ) : (
                  <p className="agent-blocked-note" role="alert">
                    Approval is disabled because the request, agent identity or
                    testnet binding could not be verified.
                  </p>
                )}
              </article>
            );
          })
        )}
      </section>

      {selectedApproval && onDecision ? (
        <ApprovalReview
          approval={selectedApproval}
          snapshot={snapshot}
          busy={busy}
          onClose={() => setSelectedApprovalId(null)}
          onDecision={onDecision}
        />
      ) : null}

      <section className="agent-list" aria-label="Agent Wallet activity">
        <h2>Recent activity</h2>
        {snapshot.activity.length === 0 ? (
          // The desktop blanks the activity list for every paired device, so an
          // empty list here never means "nothing happened". Saying so avoids
          // reading a payment history that does not exist as a clean record.
          // It is a standing fact rather than news, so it folds away.
          <details className="agent-disclosure">
            <summary>Empty by design</summary>
            <p className="agent-muted">
              Payment history is never sent to a phone, so this list stays empty
              by design. It does not mean no payment was made. Open the Agent
              Wallet on your trusted desktop to read the full history. Requests
              waiting for your approval appear above.
            </p>
          </details>
        ) : (
          snapshot.activity.map((item) => (
            <article className="agent-panel" key={item.activityId}>
              <div className="agent-record-head">
                <div>
                  <h3>{item.description}</h3>
                  <p className="agent-muted">
                    {item.asset} to {shortValue(item.recipient)}
                  </p>
                </div>
                <strong>{formatHacUnits(item.amountUnits)}</strong>
              </div>
              <p className="agent-muted">
                {item.status}. {formatCompanionTime(item.occurredAtUnix)}
              </p>
            </article>
          ))
        )}
      </section>
    </>
  );
}

function ApprovalReview({
  approval,
  snapshot,
  busy,
  onClose,
  onDecision,
}: {
  approval: AgentCompanionPendingApproval;
  snapshot: AgentCompanionSnapshot;
  busy: boolean;
  onClose: () => void;
  onDecision: (
    approval: AgentCompanionPendingApproval,
    decision: "approve" | "reject",
  ) => void;
}) {
  const facts = verifiedAgentApprovalFacts(approval, snapshot);
  const requestingAgent = authorizedAgentForApproval(approval, snapshot);
  if (!facts || !requestingAgent) {
    return (
      <section className="agent-boundary-card" role="alert">
        <strong>Request blocked</strong>
        <p>The request is no longer valid or its agent is not authorized.</p>
        <button type="button" onClick={onClose}>Close</button>
      </section>
    );
  }
  return (
    <section className="agent-panel agent-approval-review" aria-label="Exact testnet payment review">
      <div className="agent-record-head">
        <div>
          <p className="agent-eyebrow">Fingerprint confirmation required</p>
          <h2>Review the exact payment</h2>
        </div>
        <span className="agent-testnet-badge">TESTNET</span>
      </div>
      <p className="agent-warning-copy">
        Approve signs only this exact testnet decision. Reject signs only the
        rejection. Neither action gives the phone an Agent Wallet private key.
      </p>
      <div className="agent-exact-grid">
        <ExactValue label="Asset" value="HAC" />
        <ExactValue label="Amount" value={formatHacUnits(facts.amountUnits)} />
        <ExactValue label="Network fee" value={formatHacUnits(facts.networkFeeUnits)} />
        <ExactValue label="HPAY wallet fee" value="None" />
        <ExactValue label="Total debit" value={formatHacUnits(facts.totalDebitUnits)} />
        <ExactValue label="Expires" value={formatCompanionTime(approval.expiresAtUnix)} />
        <ExactValue label="Recipient" value={approval.recipient} wide />
        <ExactValue label="Requesting agent" value={requestingAgent.displayName} wide />
        <ExactValue label="Agent ID" value={requestingAgent.agentId} wide />
      </div>
      <details className="agent-technical-details">
        <summary>Technical verification</summary>
        <ExactValue
          label="Network"
          value={approval.networkBinding
            ? `${approval.networkBinding.networkId}, chain ${approval.networkBinding.chainId}, Type ${approval.networkBinding.transactionFormatVersion}`
            : "Unavailable"}
          wide
        />
        <ExactValue label="Transaction commitment" value={approval.transactionCommitment} wide />
      </details>
      {/* Three buttons of equal weight sat side by side here, and one of them
          signs. Approve stays last and spans the row, below the exact figures,
          as the single primary; Reject keeps its danger styling; leaving
          without deciding is quiet and says what it is, rather than reading as
          a third decision called "Cancel". Order and weight only. */}
      <div className="agent-approval-actions">
        <button
          type="button"
          className="agent-quiet-action"
          disabled={busy}
          onClick={onClose}
        >
          Close without deciding
        </button>
        <button
          type="button"
          className="agent-danger-action"
          disabled={busy}
          onClick={() => onDecision(approval, "reject")}
        >
          Reject request
        </button>
        <button
          type="button"
          className="agent-primary-action"
          disabled={busy}
          onClick={() => onDecision(approval, "approve")}
        >
          {busy ? "Waiting for fingerprint..." : "Approve exact testnet payment"}
        </button>
      </div>
    </section>
  );
}

function ExactValue({
  label,
  value,
  wide = false,
}: {
  label: string;
  value: string;
  wide?: boolean;
}) {
  return (
    <div className={`agent-exact-value${wide ? " wide" : ""}`}>
      <span>{label}</span>
      <code>{value}</code>
    </div>
  );
}
function AllowanceUnavailable({ limit }: { limit: string | null }) {
  return (
    <div className="agent-budget-progress">
      <div>
        <span>Rolling 24-hour spending limit</span>
        <strong>{limit ? formatHacUnits(limit) : "Not shared"}</strong>
      </div>
      <p className="agent-muted">
        Enforceable remaining allowance is calculated on HPAY Desktop and is not
        included in Companion Protocol v3.
      </p>
    </div>
  );
}
function Metric({ label, value }: { label: string; value: string }) {
  return (
    <div className="agent-metric">
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

export function Detail({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <dt>{label}</dt>
      <dd>{value}</dd>
    </div>
  );
}

export function Unavailable({ title, body }: { title: string; body: string }) {
  return (
    <section className="agent-panel">
      <h2>{title}</h2>
      <p className="agent-muted">{body}</p>
    </section>
  );
}

function authorizationLabel(value: AgentCompanionAgent["authorization"]): string {
  if (value === "authorized") return "Authorized";
  if (value === "disabled") return "Disabled";
  return "Revoked";
}

function approvalModeLabel(
  value: AgentCompanionPolicy["approvalMode"],
  pilotEnabled: boolean,
): string {
  if (value === "desktop_manual") return "Desktop manual";
  if (value === "mobile_manual") {
    return pilotEnabled ? "Mobile testnet approval" : "Mobile approval unavailable";
  }
  return pilotEnabled
    ? "Desktop or mobile testnet approval"
    : "Desktop approval only";
}
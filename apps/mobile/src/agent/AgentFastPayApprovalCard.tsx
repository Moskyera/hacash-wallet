import { Detail } from "./CompanionReadOnlyPages";
import type { AgentFastPayApprovalCommitment } from "./types";

type Props = {
  approval: AgentFastPayApprovalCommitment | null;
  busy: boolean;
  connected: boolean;
  onCheck: () => void;
  onDecision: (decision: "approve" | "reject") => void;
};

/**
 * Human-readable review of one authenticated Agent Fast Pay commitment.
 *
 * The component carries no authority and sends no commitment back to native.
 * Rust polls the paired desktop again and signs only its authenticated typed
 * response, so stale or edited WebView state cannot change what is approved.
 */
export function AgentFastPayApprovalCard({
  approval,
  busy,
  connected,
  onCheck,
  onDecision,
}: Props) {
  const isMainnet = approval?.network_binding.network_mode === "mainnet";
  return (
    <section className="agent-boundary-card">
      <strong>Agent Fast Pay</strong>
      <p className="agent-muted">
        Check for one exact L2 payment request from your paired HPAY Desktop.
        This phone never receives the Agent Wallet key.
      </p>
      {approval ? (
        <>
          {isMainnet ? (
            <p className="agent-danger-copy">
              MAINNET: approving allows this exact real HAC payment from the
              separate Agent Wallet channel.
            </p>
          ) : null}
          <dl className="agent-detail-list">
            <Detail
              label="Network"
              value={isMainnet ? "Hacash MAINNET" : "Hacash testnet"}
            />
            <Detail label="Amount" value={`${approval.amount_hac} HAC`} />
            <Detail label="To" value={approval.payee} />
            <Detail label="Hub" value={approval.hub_url} />
            <Detail label="HPAY wallet fee" value="None" />
            <Detail label="Hub fee" value="None" />
            <Detail
              label="Valid until"
              value={formatExpiry(approval.expires_at)}
            />
          </dl>
          <div className="agent-action-row">
            <button
              type="button"
              className="agent-primary-action"
              disabled={busy}
              onClick={() => onDecision("approve")}
            >
              {isMainnet ? "Approve MAINNET Fast Pay" : "Approve Fast Pay"}
            </button>
            <button
              type="button"
              className="agent-danger-action"
              disabled={busy}
              onClick={() => onDecision("reject")}
            >
              Reject
            </button>
          </div>
        </>
      ) : (
        <button
          type="button"
          className="agent-secondary-action"
          disabled={busy || !connected}
          onClick={onCheck}
        >
          Check Fast Pay approvals
        </button>
      )}
    </section>
  );
}

function formatExpiry(value: string): string {
  const seconds = Number(value);
  if (!Number.isSafeInteger(seconds) || seconds <= 0) return "Invalid";
  return new Date(seconds * 1_000).toLocaleString();
}

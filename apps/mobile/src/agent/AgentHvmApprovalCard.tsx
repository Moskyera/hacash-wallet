import { Detail } from "./CompanionReadOnlyPages";
import type { AgentHvmApprovalCommitment } from "./types";

type Props = {
  approval: AgentHvmApprovalCommitment | null;
  busy: boolean;
  connected: boolean;
  onCheck: () => void;
  onDecision: (decision: "approve" | "reject") => void;
};

/**
 * Human-readable review of one exact HVM-backed Agent payment.
 *
 * The WebView carries no signing authority. Rust re-polls the authenticated
 * desktop and Android signs only the canonical decision held in durable native
 * state, so editing this presentation cannot alter the approved bill.
 */
export function AgentHvmApprovalCard({
  approval,
  busy,
  connected,
  onCheck,
  onDecision,
}: Props) {
  const isMainnet = approval?.network_binding.network_mode === "mainnet";
  return (
    <section className="agent-boundary-card">
      <strong>HVM Agent Fast Pay</strong>
      <p className="agent-muted">
        Review one exact payment protected by the HPAY HVM contract. The Agent
        key and your Personal Wallet key never enter this phone.
      </p>
      {approval ? (
        <>
          {isMainnet ? (
            <p className="agent-danger-copy">
              MAINNET: this is an exact real HAC payment from the separate
              Agent Wallet HVM channel.
            </p>
          ) : null}
          <dl className="agent-detail-list">
            <Detail
              label="Network"
              value={isMainnet ? "Hacash MAINNET" : "Hacash testnet"}
            />
            <Detail label="Amount" value={approval.amount_hac + " HAC"} />
            <Detail label="To" value={approval.payee} />
            <Detail label="Hub" value={approval.hub_url} />
            <Detail label="Contract" value={short(approval.contract_address)} />
            <Detail label="Contract leases" value="18 bound and verified" />
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
              {isMainnet ? "Approve MAINNET HVM payment" : "Approve HVM payment"}
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
          Check HVM Fast Pay approvals
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

function short(value: string): string {
  if (value.length <= 18) return value;
  return value.slice(0, 10) + "..." + value.slice(-6);
}

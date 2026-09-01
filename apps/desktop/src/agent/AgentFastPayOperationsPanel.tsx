import { useCallback, useEffect, useState } from "react";
import {
  agentWalletApi,
  type AgentFastPayOperation,
  type AgentFastPayStatus,
} from "./api";

type Props = {
  walletId: string;
  busy: boolean;
  run: (work: () => Promise<void>) => Promise<void>;
  onInfo: (message: string) => void;
  onRefreshOverview: () => Promise<void>;
};

const EXECUTABLE = new Set<AgentFastPayStatus>(["approved", "execution_prepared"]);
const RECONCILABLE = new Set<AgentFastPayStatus>([
  "signed",
  "submitted",
  "awaiting_recipient",
  "exact_retry_ready",
  "recovery_required",
]);

export function fastPayStatusLabel(status: AgentFastPayStatus): string {
  return status.replace(/_/g, " ");
}

function formatHacUnits(raw: string): string {
  try {
    const units = BigInt(raw);
    const whole = units / 1_000_000n;
    const fraction = (units % 1_000_000n).toString().padStart(6, "0").replace(/0+$/, "");
    return fraction ? `${whole}.${fraction} HAC` : `${whole} HAC`;
  } catch {
    return `${raw} exact units`;
  }
}

function replaceOperation(
  operations: AgentFastPayOperation[],
  updated: AgentFastPayOperation,
): AgentFastPayOperation[] {
  return operations.map((operation) =>
    operation.operation_id === updated.operation_id ? updated : operation,
  );
}

export function AgentFastPayOperationsPanel({
  walletId,
  busy,
  run,
  onInfo,
  onRefreshOverview,
}: Props) {
  const [operations, setOperations] = useState<AgentFastPayOperation[] | null>(null);
  const [loadError, setLoadError] = useState("");
  const [retryConfirm, setRetryConfirm] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoadError("");
    try {
      setOperations(await agentWalletApi.listFastPayActivity(walletId));
    } catch (reason) {
      setOperations(null);
      setLoadError(readableError(reason));
    }
  }, [walletId]);

  useEffect(() => {
    void load();
  }, [load]);

  const apply = useCallback(
    (action: () => Promise<AgentFastPayOperation>, success: string) =>
      run(async () => {
        try {
          const updated = await action();
          setOperations((current) => current ? replaceOperation(current, updated) : [updated]);
          setRetryConfirm(null);
          onInfo(success);
        } finally {
          // A timeout may still have advanced either durable journal. Always
          // replace the optimistic screen state with authenticated core state.
          await load();
          await onRefreshOverview();
        }
      }),
    [load, onInfo, onRefreshOverview, run],
  );

  return (
    <section className="agent-panel" aria-labelledby="agent-fast-pay-title">
      <div className="agent-control-row">
        <div>
          <h2 id="agent-fast-pay-title">Agent Fast Pay</h2>
          <p className="agent-muted">
            Separate Agent L2 channel. Wallet fee and network fee must both be zero. There is no L1 fallback.
          </p>
        </div>
        <button type="button" disabled={busy} onClick={() => void load()}>Refresh Fast Pay</button>
      </div>

      {loadError && (
        <div className="alert" role="alert">
          <span>{loadError}</span>
          <button type="button" disabled={busy} onClick={() => void load()}>Retry read</button>
        </div>
      )}
      {operations === null && !loadError && (
        <div className="agent-empty" aria-live="polite">Loading Agent Fast Pay...</div>
      )}
      {operations?.length === 0 && (
        <div className="agent-empty">No Agent Fast Pay request has been recorded.</div>
      )}

      <div className="agent-card-list">
        {operations?.map((operation) => {
          const zeroFee = operation.network_fee_units === "0"
            && operation.wallet_fee_units === "0"
            && operation.total_debit_units === operation.amount_units;
          const canExecute = zeroFee && EXECUTABLE.has(operation.status);
          const canReconcile = RECONCILABLE.has(operation.status);
          const confirmingRetry = retryConfirm === operation.operation_id;
          return (
            <article className="agent-panel agent-operation" key={operation.operation_id}>
              <dl className="agent-detail-grid">
                <FastPayDetail label="Amount" value={formatHacUnits(operation.amount_units)} />
                <FastPayDetail label="Status" value={fastPayStatusLabel(operation.status)} />
                <FastPayDetail label="Recipient" value={operation.recipient} wide />
                <FastPayDetail label="Operation" value={operation.operation_id} wide />
                <FastPayDetail label="Hub operation" value={operation.hub_operation_id} wide />
              </dl>
              {!zeroFee && (
                <p className="alert" role="alert">
                  Invalid fee contract. Execution is blocked because Agent Fast Pay must debit exactly the payment amount.
                </p>
              )}
              {canExecute && (
                <div className="agent-confirm-row">
                  <p className="agent-warning">
                    This signs and submits only the exact approved L2 bill. It cannot use My Wallet and cannot fall back to L1.
                  </p>
                  <button
                    type="button"
                    className="agent-primary-action"
                    disabled={busy}
                    onClick={() => void apply(
                      () => agentWalletApi.executeApprovedFastPay(walletId, operation.operation_id),
                      "The approved Agent Fast Pay operation reached its next durable state.",
                    )}
                  >
                    Execute approved Fast Pay
                  </button>
                </div>
              )}
              {canReconcile && (
                <div className="agent-confirm-row">
                  <button
                    type="button"
                    disabled={busy}
                    onClick={() => void apply(
                      () => agentWalletApi.reconcileFastPay(walletId, operation.operation_id),
                      "The exact Agent Fast Pay operation was reconciled with its bound Hub.",
                    )}
                  >
                    Check exact Hub status
                  </button>
                  {operation.status === "exact_retry_ready" && !confirmingRetry && (
                    <button type="button" disabled={busy} onClick={() => setRetryConfirm(operation.operation_id)}>
                      Prepare exact retry
                    </button>
                  )}
                </div>
              )}
              {confirmingRetry && (
                <div className="agent-confirm-row" role="alert">
                  <p className="agent-warning">
                    This may submit a payment. The core will first prove that the same Hub still holds the same pending bill, then resend only the already stored signature. No new signature or identifier is created.
                  </p>
                  <button type="button" disabled={busy} onClick={() => setRetryConfirm(null)}>Cancel retry</button>
                  <button
                    type="button"
                    className="agent-primary-action"
                    disabled={busy}
                    onClick={() => void apply(
                      () => agentWalletApi.retryFastPayExact(walletId, operation.operation_id),
                      "The exact stored Agent Fast Pay signature was retried safely.",
                    )}
                  >
                    Confirm exact retry
                  </button>
                </div>
              )}
            </article>
          );
        })}
      </div>
    </section>
  );
}

function FastPayDetail({ label, value, wide = false }: { label: string; value: string; wide?: boolean }) {
  return (
    <div className={wide ? "wide" : undefined}>
      <dt>{label}</dt>
      <dd>{value}</dd>
    </div>
  );
}

function readableError(reason: unknown): string {
  return reason instanceof Error
    ? reason.message
    : typeof reason === "string"
      ? reason
      : "Agent Fast Pay read failed.";
}

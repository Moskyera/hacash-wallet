import { useCallback, useEffect, useState } from "react";
import {
  agentWalletApi,
  type AgentHvmChannelBinding,
  type AgentHvmPaymentOperation,
  type AgentHvmPaymentStatus,
  type AgentHvmRegistryBinding,
} from "./api";

type Props = {
  walletId: string;
  networkMode: "mainnet" | "testnet";
  channelBinding: AgentHvmChannelBinding | null;
  registryBinding: AgentHvmRegistryBinding | null;
  busy: boolean;
  run: (work: () => Promise<void>) => Promise<void>;
  onInfo: (message: string) => void;
  onRefreshOverview: () => Promise<void>;
};

const RECOVERABLE = new Set<AgentHvmPaymentStatus>([
  "signing_prepared",
  "signed",
  "submitted",
  "recovery_required",
]);

type HvmRail = "registry_v2" | "legacy_v1";

function isHvmRail(value: string): value is HvmRail {
  return value === "registry_v2" || value === "legacy_v1";
}

function replaceOperation(
  operations: AgentHvmPaymentOperation[],
  updated: AgentHvmPaymentOperation,
): AgentHvmPaymentOperation[] {
  return operations.map((operation) =>
    operation.operation_id === updated.operation_id ? updated : operation,
  );
}

export function AgentHvmOperationsPanel({
  walletId,
  networkMode,
  channelBinding,
  registryBinding,
  busy,
  run,
  onInfo,
  onRefreshOverview,
}: Props) {
  const [operations, setOperations] = useState<AgentHvmPaymentOperation[] | null>(null);
  const [hubUrl, setHubUrl] = useState("");
  const [bindingCommitment, setBindingCommitment] = useState("");
  const [rail, setRail] = useState<HvmRail>("registry_v2");
  const [loadError, setLoadError] = useState("");
  const [retryConfirm, setRetryConfirm] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoadError("");
    try {
      setOperations(await agentWalletApi.listHvmActivity(walletId));
    } catch (reason) {
      setOperations(null);
      setLoadError(readableError(reason));
    }
  }, [walletId]);

  useEffect(() => {
    void load();
  }, [load]);

  const apply = useCallback(
    (action: () => Promise<AgentHvmPaymentOperation>, success: string) =>
      run(async () => {
        try {
          const updated = await action();
          setOperations((current) => current ? replaceOperation(current, updated) : [updated]);
          setRetryConfirm(null);
          onInfo(success);
        } finally {
          await load();
          await onRefreshOverview();
        }
      }),
    [load, onInfo, onRefreshOverview, run],
  );

  const normalizedCommitment = bindingCommitment.trim().toLowerCase();
  const canBind = networkMode === "testnet"
    && /^https?:\/\//.test(hubUrl.trim())
    && /^[0-9a-f]{64}$/.test(normalizedCommitment);

  return (
    <section className="agent-panel" aria-labelledby="agent-hvm-fast-pay-title">
      <div className="agent-control-row">
        <div>
          <h2 id="agent-hvm-fast-pay-title">HVM Fast Pay</h2>
          <p className="agent-muted">
            Separate Agent contract rail with 18 live leases. Wallet fee and Hub fee are exactly zero. There is no L1 fallback.
          </p>
        </div>
        <button type="button" disabled={busy} onClick={() => void load()}>Refresh HVM</button>
      </div>

      {networkMode === "mainnet" && (
        <p className="agent-warning" role="status">
          Mainnet HVM owner actions are intentionally locked until the production HTTPS node, Hub deployment and canary gates pass.
        </p>
      )}

      {registryBinding ? (
        <dl className="agent-detail-grid">
          <Detail label="Rail" value="Registry V2" />
          <Detail label="Status" value="Verified and bound" />
          <Detail label="Required leases" value="18 of 18" />
          <Detail label="Reuse version" value={String(registryBinding.recovery_bundle.binding.reuse_version)} />
          <Detail label="Registry contract" value={registryBinding.recovery_bundle.binding.contract_address} wide />
          <Detail label="Hub" value={registryBinding.hub_address} wide />
          <Detail label="Channel" value={registryBinding.recovery_bundle.binding.channel_id} wide />
          <Detail label="Binding commitment" value={registryBinding.binding_commitment} wide />
        </dl>
      ) : channelBinding ? (
        <>
          <p className="agent-warning" role="status">
            Legacy V1 Local Pilot rail. Registry V2 is the production architecture for new deployments.
          </p>
          <dl className="agent-detail-grid">
            <Detail label="Rail" value="Legacy V1" />
            <Detail label="Status" value="Verified and bound" />
            <Detail label="Required leases" value="18 of 18" />
            <Detail label="Contract" value={channelBinding.recovery_bundle.binding.contract_address} wide />
            <Detail label="Hub" value={channelBinding.hub_address} wide />
            <Detail label="Channel" value={channelBinding.recovery_bundle.binding.channel_id} wide />
            <Detail label="Binding commitment" value={channelBinding.binding_commitment} wide />
          </dl>
        </>
      ) : networkMode === "testnet" ? (
        <div className="agent-card-list">
          <p className="agent-warning">
            Bind only a Local Pilot rail whose commitment you received from the reviewed HPAY Hub. The core verifies the Hub, node, contract and every lease before saving it.
          </p>
          <label className="agent-field">
            <span>HVM rail</span>
            <select
              value={rail}
              onChange={(event) => {
                if (isHvmRail(event.target.value)) setRail(event.target.value);
              }}
            >
              <option value="registry_v2">Registry V2 (recommended)</option>
              <option value="legacy_v1">Legacy V1 (Local Pilot compatibility)</option>
            </select>
          </label>
          <label className="agent-field">
            <span>Local Pilot Hub URL</span>
            <input
              value={hubUrl}
              onChange={(event) => setHubUrl(event.target.value)}
              placeholder="http://127.0.0.1:8790"
              autoComplete="off"
              spellCheck={false}
            />
          </label>
          <label className="agent-field">
            <span>Exact 64-character binding commitment</span>
            <input
              value={bindingCommitment}
              onChange={(event) => setBindingCommitment(event.target.value)}
              placeholder="64 lowercase hexadecimal characters"
              autoComplete="off"
              spellCheck={false}
            />
          </label>
          <button
            type="button"
            className="agent-primary-action"
            disabled={busy || !canBind}
            onClick={() => void run(async () => {
              const bind = rail === "registry_v2"
                ? agentWalletApi.bindHvmRegistry
                : agentWalletApi.bindHvmChannel;
              await bind(walletId, hubUrl.trim(), normalizedCommitment);
              setHubUrl("");
              setBindingCommitment("");
              onInfo(`The exact Local Pilot ${rail === "registry_v2" ? "Registry V2" : "legacy V1"} rail was verified and bound to this Agent Wallet.`);
              await onRefreshOverview();
              await load();
            })}
          >
            Verify and bind {rail === "registry_v2" ? "Registry V2" : "legacy V1"}
          </button>
        </div>
      ) : null}

      {loadError && (
        <div className="alert" role="alert">
          <span>{loadError}</span>
          <button type="button" disabled={busy} onClick={() => void load()}>Retry read</button>
        </div>
      )}
      {operations === null && !loadError && (
        <div className="agent-empty" aria-live="polite">Loading HVM activity...</div>
      )}
      {operations?.length === 0 && (
        <div className="agent-empty">No Agent HVM payment has been recorded.</div>
      )}

      <div className="agent-card-list">
        {operations?.map((operation) => {
          const zeroFee = operation.wallet_fee_zhu === 0
            && operation.hub_fee_zhu === 0
            && operation.total_debit_zhu === operation.amount_zhu;
          const canExecute = networkMode === "testnet" && zeroFee && operation.status === "approved";
          const canRecover = RECOVERABLE.has(operation.status);
          const canPrepareRetry = networkMode === "testnet" && operation.status === "exact_retry_ready";
          const confirmingRetry = retryConfirm === operation.operation_id;
          return (
            <article className="agent-panel agent-operation" key={operation.operation_id}>
              <dl className="agent-detail-grid">
                <Detail label="Amount" value={formatHacUnits(operation.amount_units)} />
                <Detail label="Status" value={operation.status.replace(/_/g, " ")} />
                <Detail label="Recipient" value={operation.recipient} wide />
                <Detail label="Operation" value={operation.operation_id} wide />
                <Detail label="Hub operation" value={operation.hub_operation_id} wide />
              </dl>
              {!zeroFee && (
                <p className="alert" role="alert">
                  Invalid fee contract. HVM execution is blocked because Agent payments must debit exactly the payment amount.
                </p>
              )}
              {canExecute && (
                <div className="agent-confirm-row">
                  <p className="agent-warning">
                    This signs only the exact approved HVM bill after fresh node, Hub, contract, balance and 18-lease verification.
                  </p>
                  <button
                    type="button"
                    className="agent-primary-action"
                    disabled={busy}
                    onClick={() => void apply(
                      () => agentWalletApi.executeApprovedHvm(walletId, operation.operation_id),
                      "The approved HVM payment reached its next durable state.",
                    )}
                  >
                    Execute approved HVM payment
                  </button>
                </div>
              )}
              {canRecover && (
                <button
                  type="button"
                  disabled={busy}
                  onClick={() => void apply(
                    () => agentWalletApi.reconcileHvm(walletId, operation.operation_id),
                    "The exact HVM operation was recovered from authenticated local and Hub state.",
                  )}
                >
                  Recover exact HVM state
                </button>
              )}
              {canPrepareRetry && !confirmingRetry && (
                <button type="button" disabled={busy} onClick={() => setRetryConfirm(operation.operation_id)}>
                  Prepare exact retry
                </button>
              )}
              {confirmingRetry && (
                <div className="agent-confirm-row" role="alert">
                  <p className="agent-warning">
                    This resends only the already stored signature and identifiers after fresh verification. It never creates a second signature.
                  </p>
                  <button type="button" disabled={busy} onClick={() => setRetryConfirm(null)}>Cancel retry</button>
                  <button
                    type="button"
                    className="agent-primary-action"
                    disabled={busy}
                    onClick={() => void apply(
                      () => agentWalletApi.retryHvmExact(walletId, operation.operation_id),
                      "The exact stored HVM signature was retried safely.",
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

function Detail({ label, value, wide = false }: { label: string; value: string; wide?: boolean }) {
  return <div className={wide ? "wide" : undefined}><dt>{label}</dt><dd>{value}</dd></div>;
}

function formatHacUnits(raw: string): string {
  try {
    const units = BigInt(raw);
    const whole = units / 1_000_000n;
    const fraction = (units % 1_000_000n).toString().padStart(6, "0").replace(/0+$/, "");
    return fraction ? String(whole) + "." + fraction + " HAC" : String(whole) + " HAC";
  } catch {
    return raw + " exact units";
  }
}

function readableError(reason: unknown): string {
  return reason instanceof Error
    ? reason.message
    : typeof reason === "string"
      ? reason
      : "Agent HVM read failed.";
}

import { useCallback, useEffect, useState } from "react";
import {
  agentWalletApi,
  type AgentHvmChannelBinding,
  type AgentHvmPaymentOperation,
  type AgentHvmPaymentStatus,
  type AgentHvmRegistryBinding,
  type AnchorWitnessAnswer,
  type AnchorWitnessChange,
  type AnchorWitnessRecord,
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

/**
 * Is this a re-affirmation of the head the wallet already holds, rather than a
 * new bill?
 *
 * A continuity declaration always is: same serial, same bill commitment. The
 * copy written for a pending payment is actively misleading there — it shows
 * "last accepted" and "being offered" as the same serial and tells the reader
 * nothing was spent, describing a transaction that does not exist and never
 * will, because the Hub can no longer co-sign anything.
 */
function isReAffirmation(change: AnchorWitnessChange): boolean {
  return change.serial === change.last_accepted_serial;
}

/**
 * Name a witness by the pair the wallet actually keyed on.
 *
 * The address alone is not enough, and the case where it is not enough is the
 * one that matters most: a witness store rebuilt from nothing keeps its signing
 * key, so the dropped and the offered rows render as the identical string and
 * the reader is asked to spot a difference that is not on screen. The store
 * instance is the half that changed, and it is already on the wire.
 */
function describeWitnesses(records: AnchorWitnessRecord[]): string {
  if (records.length === 0) return "none";
  return records
    .map((record) => `${record.signer_address} (store ${record.witness_instance_id.slice(0, 16)}...)`)
    .join(", ");
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
  const [anchorDecisions, setAnchorDecisions] = useState<Record<string, AnchorWitnessChange>>({});

  const load = useCallback(async () => {
    setLoadError("");
    try {
      const loaded = await agentWalletApi.listHvmActivity(walletId);
      setOperations(loaded);
      // A parked rollback-anchor decision is durable and per channel, so it is
      // read back rather than remembered. This is the only place the question
      // reaches a person, and until it is answered the channel does not
      // advance in either direction.
      //
      // Every operation is read, not only the recoverable ones. A decision is
      // parked against a *channel*, and the channel that most needs the
      // question asked is one whose payments all committed cleanly and whose
      // Hub then lost its witness - so the last operation on it is `committed`
      // and gating on recoverability would hide the question exactly where it
      // matters.
      const parked: Record<string, AnchorWitnessChange> = {};
      const askedChannels = new Set<string>();
      for (const operation of loaded) {
        try {
          const change = await agentWalletApi.hvmAnchorDecision(walletId, operation.operation_id);
          if (change) {
            parked[operation.operation_id] = change;
            askedChannels.add(operation.binding_commitment);
          }
        } catch {
          // A decision that cannot be read is not a decision that can be
          // skipped: the recover path refuses on its own while one is parked.
        }
      }
      // Then the one question nothing else can ever ask.
      //
      // A Hub whose single witness was replaced will never co-sign another
      // bill, and every other route into the witness ratchet runs on a new
      // bill. So no payment, retry or recovery will ever park a decision on
      // that channel again: without this call the owner's entire evidence is a
      // channel that quietly stopped working. Once per channel per read, and
      // only for channels that do not already owe an answer.
      for (const operation of loaded) {
        if (askedChannels.has(operation.binding_commitment)) continue;
        askedChannels.add(operation.binding_commitment);
        try {
          const change = await agentWalletApi.refreshHvmAnchorContinuity(
            walletId,
            operation.operation_id,
          );
          if (change) parked[operation.operation_id] = change;
        } catch {
          // Expected on every healthy Hub: one in agreement with its pinned
          // witness has nothing to declare and says so. A declaration that
          // cannot be fetched changes nothing here - the channel is in exactly
          // the state it was already in.
        }
      }
      setAnchorDecisions(parked);
    } catch (reason) {
      setOperations(null);
      setAnchorDecisions({});
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

  const resolveAnchor = useCallback(
    (operationId: string, answer: AnchorWitnessAnswer) =>
      run(async () => {
        try {
          await agentWalletApi.resolveHvmAnchorDecision(walletId, operationId, answer);
          onInfo(
            answer === "close_channel"
              ? "This channel is now closing on its last accepted bill. It will not accept another bill from this Hub."
              : "This Hub's new witness set was recorded. The witnesses it dropped are kept in the record, not erased.",
          );
        } finally {
          await load();
          await onRefreshOverview();
        }
      }),
    [load, onInfo, onRefreshOverview, run, walletId],
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
          const anchorChange = anchorDecisions[operation.operation_id];
          // Recovery is hidden while a witness decision is parked. Recovery is
          // the path that commits the Hub's bill, and this refusal exists
          // precisely to stop that bill being committed unexamined.
          const canRecover = RECOVERABLE.has(operation.status) && !anchorChange;
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
              {anchorChange && (
                <div className="agent-confirm-row" role="alert">
                  <p className="agent-warning">
                    {anchorChange.headline}. This is what an operator changing witnesses looks like, and it is also what a Hub re-using a bill number it already spent looks like. From here they are the same, so only you can answer it. Nothing was accepted and nothing was spent.
                  </p>
                  {isReAffirmation(anchorChange) ? (
                    // No new bill is on the table, and saying "bill being
                    // offered" here would be describing a payment that does not
                    // exist. This is a Hub that cannot sign at all any more,
                    // re-showing the head this wallet already holds under a
                    // different witness - so the honest framing is about the
                    // channel's future, not about a pending payment.
                    <p className="agent-muted">
                      No new payment is involved. This Hub is re-showing the bill you already hold at serial {anchorChange.serial}, vouched for by a different witness. A Hub in this state has stopped being able to co-sign, so accepting the new witness does not restore payments on this channel — closing on the bill you already hold is what actually settles it.
                    </p>
                  ) : (
                    <dl className="agent-detail-grid">
                      <Detail label="Last bill you accepted" value={`Serial ${anchorChange.last_accepted_serial}`} />
                      <Detail label="Bill being offered" value={`Serial ${anchorChange.serial}`} />
                    </dl>
                  )}
                  <dl className="agent-detail-grid">
                    <Detail
                      label="Witnesses no longer covering this channel"
                      value={describeWitnesses(anchorChange.dropped)}
                      wide
                    />
                    <Detail
                      label="Witnesses this Hub offers now"
                      value={describeWitnesses(anchorChange.offered)}
                      wide
                    />
                  </dl>
                  <button
                    type="button"
                    className={isReAffirmation(anchorChange) ? "agent-primary-action" : undefined}
                    disabled={busy}
                    onClick={() => void resolveAnchor(operation.operation_id, "close_channel")}
                  >
                    Close this channel on its last accepted bill
                  </button>
                  <button
                    type="button"
                    className={isReAffirmation(anchorChange) ? undefined : "agent-primary-action"}
                    disabled={busy}
                    onClick={() => void resolveAnchor(operation.operation_id, "accept_new_witness_set")}
                  >
                    Accept this Hub's new witnesses
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

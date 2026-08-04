import { useEffect, useState } from "react";
import { CompanionQrDisplay, CompanionQrScanner } from "@hacash/wallet-ui";
import {
  agentWalletApi,
  type AgentWalletOverview,
  type EncryptedCompanionFrame,
  type MobilePairingConfirmation,
  type MobilePairingOffer,
  type SignedRotationCandidateAcceptance,
  type SignedRotationPairingTicket,
  type WitnessRotationRecord,
} from "./api";
import { parseAck, parseRequest } from "./companionPairing";

type Props = {
  overview: AgentWalletOverview;
  busy: boolean;
  run: (work: () => Promise<void>) => Promise<void>;
  onInfo: (message: string) => void;
  onRefreshOverview: () => Promise<void>;
};

type CandidateConfirmation = {
  confirmation: MobilePairingConfirmation;
  ticket: SignedRotationPairingTicket;
};

type CandidateAck = {
  encryptedAck: EncryptedCompanionFrame;
  signedAcceptance: SignedRotationCandidateAcceptance;
};

export function WitnessRotationPanel({
  overview,
  busy,
  run,
  onInfo,
  onRefreshOverview,
}: Props) {
  const [record, setRecord] = useState<WitnessRotationRecord | null>(null);
  const [mode, setMode] = useState<"normal" | "lost_phone_recovery">("normal");
  const [confirmationText, setConfirmationText] = useState("");
  const [endpoint, setEndpoint] = useState("");
  const [offer, setOffer] = useState<MobilePairingOffer | null>(null);
  const [candidateConfirmation, setCandidateConfirmation] =
    useState<CandidateConfirmation | null>(null);
  const [candidateAck, setCandidateAck] = useState<CandidateAck | null>(null);
  const [typedCode, setTypedCode] = useState("");
  const [localError, setLocalError] = useState("");

  useEffect(() => {
    void agentWalletApi.witnessRotationStatus(overview.wallet_id)
      .then(setRecord)
      .catch(() => setRecord(null));
  }, [overview.wallet_id, overview.witness_rotation_phase]);

  const expected = mode === "normal" ? "ROTATE WITNESS" : "LOST PHONE RECOVERY";
  const phase = overview.witness_rotation_phase;
  const rotationActive = phase !== null && phase !== "stable" && phase !== "completed";

  async function prepare() {
    if (confirmationText !== expected) return;
    const rotationId = `rotation_${crypto.randomUUID()}`;
    const candidateSlot = `rotation_candidate_${crypto.randomUUID().replace(/-/g, "")}`;
    const next = await agentWalletApi.prepareWitnessRotation(
      overview.wallet_id,
      rotationId,
      candidateSlot,
      mode,
      mode === "normal" ? "replace_phone" : "lost_phone",
    );
    setRecord(next);
    setConfirmationText("");
    await onRefreshOverview();
    onInfo(mode === "normal"
      ? "Rotation is locked. Authorize it on the old phone; then this screen will enable the one-time candidate QR."
      : "Recovery rotation is locked after clean-state and live-node verification. Create the one-time candidate QR next.");
  }

  async function startCandidatePairing() {
    if (!record || !endpoint.trim()) return;
    const next = await agentWalletApi.startRotationCandidatePairing(
      overview.wallet_id,
      record.rotation_id,
      endpoint.trim(),
    );
    setOffer(next);
    setCandidateConfirmation(null);
    setCandidateAck(null);
    setTypedCode("");
    onInfo("Scan this rotation-only offer on the unpaired replacement phone.");
  }

  async function cancelRotation() {
    if (!record) return;
    await agentWalletApi.cancelWitnessRotation(
      overview.wallet_id,
      record.rotation_id,
    );
    setRecord(null);
    setOffer(null);
    setCandidateConfirmation(null);
    setCandidateAck(null);
    setTypedCode("");
    setLocalError("");
    await onRefreshOverview();
    onInfo("Witness rotation cancelled before authority transition. The old phone remains active.");
  }

  async function completeCandidatePairing() {
    if (!candidateConfirmation || !candidateAck) return;
    await agentWalletApi.completeRotationCandidatePairing(
      overview.wallet_id,
      candidateAck.encryptedAck,
      typedCode,
      candidateAck.signedAcceptance,
    );
    const status = await agentWalletApi.companionStatus();
    if (!status?.enabled) {
      const bindAddress = endpoint.trim().replace(/^hpay-lan:\/\//, "");
      await agentWalletApi.startCompanion(overview.wallet_id, bindAddress);
    }
    setOffer(null);
    setCandidateConfirmation(null);
    setCandidateAck(null);
    setTypedCode("");
    await onRefreshOverview();
    onInfo("The phone is a restricted RotationCandidate. It has no payment or general companion authority. Continue rotation on that phone.");
  }

  return (
    <section className="agent-panel" aria-label="Witness device rotation">
      <span className="agent-eyebrow">Testnet pilot only</span>
      <h2>Replace approval phone</h2>
      <p>
        The replacement phone does not need prior pairing. It remains a restricted
        candidate until the final completion receipt is durably accepted.
      </p>
      <dl className="agent-detail-grid">
        <Detail label="Current phase" value={phase?.replace(/_/g, " ") ?? "stable"} />
        <Detail label="Unresolved operations" value={String(overview.unresolved_signed_operations)} />
        <Detail label="Rotation ID" value={record ? shortId(record.rotation_id) : "none"} />
      </dl>
      {localError ? <div className="alert" role="alert">{localError}</div> : null}

      {!rotationActive ? (
        <>
          <label className="agent-field">
            Rotation path
            <select value={mode} onChange={(event) => {
              setMode(event.target.value as "normal" | "lost_phone_recovery");
              setConfirmationText("");
            }} disabled={busy}>
              <option value="normal">Old phone is available</option>
              <option value="lost_phone_recovery">Old phone is lost</option>
            </select>
          </label>
          {mode === "lost_phone_recovery" ? (
            <div className="agent-warning" role="alert">
              Recovery requires an authenticated clean journal, no unresolved financial
              state and the live pinned HPAY custom testnet node.
            </div>
          ) : null}
          <label className="agent-field">
            Type {expected}
            <input value={confirmationText} onChange={(event) => setConfirmationText(event.target.value)} disabled={busy} autoComplete="off" spellCheck={false} />
          </label>
          <button type="button" className="agent-primary-action" disabled={busy || confirmationText !== expected || overview.unresolved_signed_operations !== 0} onClick={() => void run(prepare)}>
            Start controlled rotation
          </button>
        </>
      ) : null}

      {phase === "awaiting_old_witness_authorization" ? (
        <div className="agent-safe-note">Open the old phone, connect, and authorize this exact rotation.</div>
      ) : null}

      {phase === "awaiting_candidate_pairing" && !offer ? (
        <>
          <label className="agent-field">
            Exact desktop private-LAN endpoint
            <input value={endpoint} onChange={(event) => setEndpoint(event.target.value)} placeholder="hpay-lan://192.168.1.20:42492" spellCheck={false} disabled={busy} />
          </label>
          <button type="button" className="agent-primary-action" disabled={busy || !record || !endpoint.trim()} onClick={() => void run(startCandidatePairing)}>
            Create rotation candidate QR
          </button>
        </>
      ) : null}

      {offer && !candidateConfirmation ? (
        <div className="agent-companion-step">
          <h3>1. Scan the rotation-only offer</h3>
          <CompanionQrDisplay
            value={JSON.stringify({ kind: "hpay_rotation_candidate_offer_v1", offer })}
            label="One-time HPAY rotation candidate offer"
          />
          <h3>2. Scan the signed candidate request</h3>
          <CompanionQrScanner
            label="Scan rotation candidate request"
            disabled={busy}
            onValue={(raw) => void run(async () => {
              const request = parseRequest(raw, overview.wallet_id, offer.pairing_id);
              setCandidateConfirmation(
                await agentWalletApi.acceptRotationCandidatePairingRequest(
                  overview.wallet_id,
                  request,
                ),
              );
            })}
          />
        </div>
      ) : null}

      {candidateConfirmation && !candidateAck ? (
        <div className="agent-companion-step">
          <h3>3. Compare this code on both devices</h3>
          <strong className="agent-verification-code">{candidateConfirmation.confirmation.verification_code}</strong>
          <CompanionQrDisplay
            value={JSON.stringify({
              kind: "hpay_rotation_candidate_confirmation_v1",
              confirmation: candidateConfirmation.confirmation,
              ticket: candidateConfirmation.ticket,
            })}
            label="Signed HPAY rotation ticket and confirmation"
          />
          <h3>4. Scan the restricted candidate acknowledgement</h3>
          <CompanionQrScanner
            label="Scan restricted candidate acknowledgement"
            disabled={busy}
            onValue={(raw) => {
              try {
                const envelope = parseCandidateAck(raw, candidateConfirmation);
                setCandidateAck(envelope);
              } catch (error) {
                setLocalError(readableError(error));
              }
            }}
          />
        </div>
      ) : null}

      {candidateConfirmation && candidateAck ? (
        <div className="agent-companion-step">
          <label className="agent-field">
            Enter the six-digit code
            <input value={typedCode} inputMode="numeric" maxLength={6} onChange={(event) => setTypedCode(event.target.value.replace(/\D/g, "").slice(0, 6))} />
          </label>
          <button type="button" className="agent-primary-action" disabled={busy || typedCode !== candidateConfirmation.confirmation.verification_code} onClick={() => void run(completeCandidatePairing)}>
            Register restricted candidate
          </button>
        </div>
      ) : null}

      {phase === "candidate_paired_restricted" || phase === "awaiting_completion_anchor" ? (
        <div className="agent-safe-note">
          The replacement phone is restricted to this rotation. On that phone choose
          Continue witness rotation. It cannot approve payments or view wallet activity.
        </div>
      ) : null}
      {rotationActive && [
        "awaiting_old_witness_authorization",
        "awaiting_candidate_pairing",
        "rotation_ticket_issued",
        "candidate_paired_restricted",
      ].includes(phase ?? "") ? (
        <button type="button" className="agent-secondary-action" disabled={busy || !record} onClick={() => void run(cancelRotation)}>
          Cancel before authority transition
        </button>
      ) : null}
      {phase === "completed" ? <div className="agent-safe-note">Witness rotation completed. The old phone is revoked.</div> : null}
    </section>
  );
}

function parseCandidateAck(raw: string, current: CandidateConfirmation): CandidateAck {
  const value = JSON.parse(raw) as Record<string, unknown>;
  if (value.kind !== "hpay_rotation_candidate_ack_v1" || !value.encryptedAck || !value.signedAcceptance) {
    throw new Error("This is not a rotation candidate acknowledgement.");
  }
  const acceptance = value.signedAcceptance as SignedRotationCandidateAcceptance;
  if (
    acceptance.acceptance.ticket_id !== current.ticket.ticket.ticket_id
    || acceptance.acceptance.rotation_id !== current.ticket.ticket.rotation_id
    || acceptance.acceptance.agent_wallet_id !== current.ticket.ticket.agent_wallet_id
    || acceptance.acceptance.candidate_device_id !== current.confirmation.mobile_device_id
    || acceptance.acceptance.network_id !== "testnet"
  ) {
    throw new Error("Rotation candidate acknowledgement scope mismatch.");
  }
  return {
    encryptedAck: parseAck(
      JSON.stringify(value.encryptedAck),
      current.confirmation.session_id,
      current.confirmation.mobile_device_id,
      current.confirmation.desktop_device_id,
    ),
    signedAcceptance: acceptance,
  };
}

function Detail({ label, value }: { label: string; value: string }) {
  return <div><dt>{label}</dt><dd>{value}</dd></div>;
}

function shortId(value: string): string {
  return value.length > 18 ? `${value.slice(0, 9)}...${value.slice(-5)}` : value;
}

function readableError(reason: unknown): string {
  return reason instanceof Error ? reason.message : String(reason);
}

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
  type WitnessRotationControls,
  type WitnessRotationRecord,
} from "./api";
import { parseAck, parseRequest } from "./companionPairing";
import { companionPhoneAppName } from "./companionWaitingView";

/** The exact name of the phone app, shared with the pairing copy. */
const COMPANION_PHONE_APP_NAME = companionPhoneAppName;

/**
 * The exact label of the phone button that advances a witness rotation.
 *
 * It must stay identical to the button rendered in
 * apps/mobile/src/agent/CompanionSecurity.tsx. This panel used to say "Continue
 * witness rotation", which is not a label that exists anywhere on the phone,
 * and the panel that carries the real button is headed "Approval phone
 * rotation". companionUi.test.ts pins the two together.
 */
const COMPANION_PHONE_ROTATION_ACTION = "Check and continue rotation";

/** The exact words the owner types to re-target a stranded rotation. */
export const ROTATION_RETARGET_CONFIRMATION = "USE A DIFFERENT PHONE";

/** The label of the only control that leaves `awaiting_completion_anchor`. */
export const ROTATION_RETARGET_ACTION = "Use a different replacement phone";

/**
 * What the re-target costs, said before the press and never behind a
 * `<details>`.
 *
 * `retarget_witness_rotation`
 * (crates/agent-wallet-core/src/service/companion/rotation.rs) discards the
 * abandoned candidate's baseline receipt and its registration, and never rolls
 * the witness epoch back, so the epoch that handset was admitted at is burned.
 * Nothing else is discarded: no funds, no anchor chain, no journal, and the old
 * phone stays revoked either way.
 */
export const ROTATION_RETARGET_WARNING =
  "This cannot be undone. The replacement phone you already paired is discarded: it is never registered on this wallet, and the witness epoch it was admitted at is used up, so that exact handset can never serve this wallet again even if it comes back. Nothing else is lost. No money moves, no payment is signed, your balance, history and limits are untouched, and the old phone stays revoked exactly as it is now. You then pair a different replacement phone from the beginning.";

/**
 * The same escape, at a phase where the replacement phone never got as far as
 * signing a baseline.
 *
 * `retarget_preconditions`
 * (crates/agent-wallet-core/src/service/companion/rotation.rs) also offers the
 * re-target at `rotation_ticket_issued` and `candidate_paired_restricted` once
 * the old phone is already revoked, because the cancel is refused there for good
 * and the pairing ticket cannot be re-issued. At those phases no baseline was
 * ever accepted and no witness epoch was consumed, so the expensive warning
 * above would be false. Overstating the cost is not harmless: it would talk an
 * owner out of the only control they have.
 */
export const ROTATION_RETARGET_PAIRING_WARNING =
  "This cannot be undone. The half-finished pairing with that replacement phone is discarded and you start the candidate pairing again from the beginning. Nothing else is lost: no witness epoch was used up, so you may pair the same phone again if it comes back. No money moves, no payment is signed, your balance, history and limits are untouched, and the old phone stays revoked exactly as it is now.";

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
  const [controls, setControls] = useState<WitnessRotationControls>({
    cancellable: false,
    retargetable: false,
  });
  const [retargetText, setRetargetText] = useState("");
  const [controlsUnknown, setControlsUnknown] = useState(false);
  const [controlsReloadKey, setControlsReloadKey] = useState(0);

  useEffect(() => {
    void agentWalletApi.witnessRotationStatus(overview.wallet_id)
      .then(setRecord)
      .catch(() => setRecord(null));
  }, [overview.wallet_id, overview.witness_rotation_phase]);

  // The core owns both predicates. Asking it means a control is never offered
  // in a state where it would be refused, and never withheld in one where it is
  // the only way out. Guessing from the phase is not enough: a re-targeted
  // rotation sits in awaiting_candidate_pairing with the old phone already
  // revoked, where the cancel is refused.
  //
  // A failed answer is fail-closed - no control is offered - but it must not be
  // silent. Every control on this panel is now gated on this one call, so a
  // hiccup would otherwise leave the owner looking at a rotation with no button
  // and no reason given, which is the exact failure this panel exists to end.
  useEffect(() => {
    setRetargetText("");
    void agentWalletApi.witnessRotationControls(overview.wallet_id)
      .then((next) => {
        setControls(next);
        setControlsUnknown(false);
      })
      .catch(() => {
        setControls({ cancellable: false, retargetable: false });
        setControlsUnknown(true);
      });
  }, [overview.wallet_id, overview.witness_rotation_phase, controlsReloadKey]);

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

  async function retargetRotation() {
    if (!record || retargetText !== ROTATION_RETARGET_CONFIRMATION) return;
    const next = await agentWalletApi.retargetWitnessRotation(
      overview.wallet_id,
      record.rotation_id,
      `rotation_${crypto.randomUUID()}`,
      `rotation_candidate_${crypto.randomUUID().replace(/-/g, "")}`,
    );
    setRecord(next);
    setOffer(null);
    setCandidateConfirmation(null);
    setCandidateAck(null);
    setTypedCode("");
    setRetargetText("");
    setLocalError("");
    await onRefreshOverview();
    onInfo("The unusable replacement phone was discarded. Pair a different replacement phone from the candidate QR step.");
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
        <div className="agent-safe-note">
          Open {COMPANION_PHONE_APP_NAME} on the old phone, connect it to this
          desktop, then open the Security tab and choose{" "}
          {COMPANION_PHONE_ROTATION_ACTION} in Approval phone rotation. It asks
          for your fingerprint and authorizes this exact rotation.
        </div>
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
          The replacement phone is restricted to this rotation. It cannot approve
          payments or view wallet activity. On that phone open{" "}
          {COMPANION_PHONE_APP_NAME}, go to the Security tab and choose{" "}
          {COMPANION_PHONE_ROTATION_ACTION} in Approval phone rotation.
        </div>
      ) : null}
      {/* Past CandidatePairedRestricted the backend refuses a cancel
          (crates/agent-wallet-core/src/service/companion/rotation.rs), and the
          start form is hidden because a rotation is active, so this phase had a
          phase label and nothing else. It cannot be closed by copy: this states
          plainly what the desktop can and cannot do from here. */}
      {phase === "awaiting_completion_anchor" ? (
        <div className="agent-warning" role="alert">
          This rotation can no longer be cancelled from this desktop. It is
          normally finished on the replacement phone with{" "}
          {COMPANION_PHONE_ROTATION_ACTION}. Until it finishes, every agent
          payment request on this wallet is refused and the agent is told the
          wallet needs manual recovery. Do not revoke anything: revoking is
          permanent and removes the phone that can still finish this.
        </div>
      ) : null}
      {/* Fail-closed, but never silently. Both controls below are gated on one
          call to the core; if that call did not answer, the panel must say so
          rather than simply show nothing, which is indistinguishable from
          "there is no way out of this state". */}
      {rotationActive && controlsUnknown ? (
        <div className="agent-warning" role="alert">
          This desktop could not check which rotation controls are available
          right now, so none are shown. Nothing has changed and nothing is lost.
          Make sure the wallet is unlocked and try again.{" "}
          <button
            type="button"
            className="agent-secondary-action"
            disabled={busy}
            onClick={() => setControlsReloadKey((value) => value + 1)}
          >
            Check again
          </button>
        </div>
      ) : null}
      {/* Until this control existed, an owner whose replacement phone was lost,
          broken or wiped at exactly this point had nothing at all: the cancel
          is refused twice over
          (crates/agent-wallet-core/src/service/companion/rotation.rs), the
          start form is hidden while a rotation is active, and every agent
          payment stays refused. The wallet was stopped for good. The escape
          costs the unusable candidate; that cost is stated in full, in the open,
          before the first press. */}
      {controls.retargetable ? (
        <div className="agent-companion-step">
          <h3>If the replacement phone is gone</h3>
          <p>
            If that handset is lost, broken, wiped or simply will not connect,
            this is the only way to move on. It points this same rotation at a
            different replacement phone.
          </p>
          {/* Fail-loud, but not falsely loud. Past the authority transition a
              real baseline and a real witness epoch are discarded; at the
              pairing phases nothing was ever admitted, and claiming otherwise
              would scare an owner off the only control they have. */}
          <div className="agent-warning" role="alert">
            {phase === "awaiting_completion_anchor"
              ? ROTATION_RETARGET_WARNING
              : ROTATION_RETARGET_PAIRING_WARNING}
          </div>
          <label className="agent-field">
            Type {ROTATION_RETARGET_CONFIRMATION}
            <input
              value={retargetText}
              onChange={(event) => setRetargetText(event.target.value)}
              disabled={busy}
              autoComplete="off"
              spellCheck={false}
            />
          </label>
          <button
            type="button"
            className="agent-danger-action"
            disabled={busy || !record || retargetText !== ROTATION_RETARGET_CONFIRMATION}
            onClick={() => void run(retargetRotation)}
          >
            {ROTATION_RETARGET_ACTION}
          </button>
        </div>
      ) : null}
      {/* Gated on the core's own answer rather than on the phase. A re-targeted
          rotation is back in awaiting_candidate_pairing, but its old phone is
          already revoked, so cancel_witness_rotation refuses it - offering the
          button there would be a control that does nothing. */}
      {rotationActive && controls.cancellable ? (
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

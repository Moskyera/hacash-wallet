import { Fragment, useState } from "react";
import { openUrl } from "@tauri-apps/plugin-opener";
import WalletLogo from "../components/WalletLogo";
import {
  AGENT_WALLET_HOW_IT_WORKS_URL,
  parseCompanionConfirmation,
  parseCompanionOffer,
} from "@hacash/wallet-ui";
import { agentCompanionApi } from "./api";
import {
  COMPANION_RETRY_AFTER_APPROVAL_ACTION,
  COMPANION_SEND_CONFIRMATION_ACTION,
  companionFailureText,
  companionPairingStateView,
  companionRevocationSuspected,
} from "./companionStatus";
import {
  COMPANION_OPEN_SECURITY_SETUP_ACTION,
  COMPANION_REFRESH_ACTION,
  companionBlockOrder,
  companionPrimaryAction,
  type AgentCompanionPage,
  type CompanionBlockId,
} from "./companionLayout";
import {
  authorizedAgentForApproval,
  pendingWitnessOperation,
  validateFreshPairingOffer,
  validatePairingCompletion,
  validatePairingConfirmationFresh,
  validatePairingStart,
  toNativeApprovalCommitment,
  verifiedAgentApprovalFacts,
} from "./companionView";
import {
  CompanionConnectionPanel,
  CompanionPairingPanel,
  type PairingFlow,
} from "./CompanionPairingPanel";
import {
  CompanionActivity,
  CompanionAgents,
  Detail,
  CompanionOverview,
  CompanionRules,
} from "./CompanionReadOnlyPages";
import { CompanionSecurity } from "./CompanionSecurity";
import { COMPANION_DISCARD_CONSENT_PHRASE } from "./companionHeldConsent";
import { AgentFastPayApprovalCard } from "./AgentFastPayApprovalCard";
import { AgentHvmApprovalCard } from "./AgentHvmApprovalCard";
import { useCompanionSession } from "./useCompanionSession";
import type {
  AgentCompanionActivity,
  AgentCompanionPendingApproval,
  AgentFastPayApprovalCommitment,
  AgentHvmApprovalCommitment,
  CompanionPairingCompletionView,
  RotationCandidatePairingCompletionView,
  SignedRotationCandidateAcceptance,
  SignedRotationPairingTicket,
} from "./types";

type AgentPage = AgentCompanionPage;

const PAGES: Array<{ id: AgentPage; label: string }> = [
  { id: "overview", label: "Overview" },
  { id: "agents", label: "Agents" },
  { id: "rules", label: "Rules" },
  { id: "activity", label: "Activity" },
  { id: "security", label: "Security" },
];

export default function AgentCompanionApp() {
  const companion = useCompanionSession();
  const [page, setPage] = useState<AgentPage>("overview");
  const [pairing, setPairing] = useState<PairingFlow | null>(null);
  /**
   * What the phone is waiting on, or "" when it is not waiting on anything.
   *
   * The banner keyed on the flag alone said "Complete or cancel the fingerprint
   * prompt to continue pairing" for approving a payment, for continuing a
   * witness rotation and for cancelling a pairing. Same words, six unrelated
   * situations. The flag is unchanged; only its reason is now carried with it.
   */
  const [nativeWait, setNativeWait] = useState<NativeWaitReason>("");
  const pairingBusy = nativeWait !== "";
  const setPairingBusy = (reason: NativeWaitReason | false) =>
    setNativeWait(reason === false ? "" : reason);
  const [pendingAckSent, setPendingAckSent] = useState(false);
  const [createConfirm, setCreateConfirm] = useState(false);
  const [resetConfirm, setResetConfirm] = useState(false);
  const [resetText, setResetText] = useState("");
  const [retireConfirm, setRetireConfirm] = useState(false);
  const [retireText, setRetireText] = useState("");
  const [discardConfirm, setDiscardConfirm] = useState(false);
  const [discardText, setDiscardText] = useState("");
  const [actionNotice, setActionNotice] = useState("");
  const [fastPayApproval, setFastPayApproval] =
    useState<AgentFastPayApprovalCommitment | null>(null);
  const [hvmApproval, setHvmApproval] =
    useState<AgentHvmApprovalCommitment | null>(null);
  const busy = Boolean(companion.busy) || pairingBusy;

  const acceptOffer = async (raw: string) => {
    // Never a bare return. The scanner fires onValue exactly once and then
    // closes the camera, so a silent guard here is the historical defect
    // verbatim: the camera shuts and nothing else happens.
    const refusal = scanRefusal({
      busy,
      configured: Boolean(companion.stored?.configured),
      identityReady: Boolean(companion.identity?.ready),
    });
    if (refusal) {
      companion.setError(refusal);
      return;
    }
    setPairingBusy("pairing");
    companion.setError("");
    try {
      const rotationEnvelope = parseRotationOfferEnvelope(raw);
      const offer = validateFreshPairingOffer(
        rotationEnvelope?.offer ?? parseCompanionOffer(raw),
      );
      const start = validatePairingStart(
        await (rotationEnvelope
          ? agentCompanionApi.rotationPairingStart(offer)
          : agentCompanionApi.pairingStart(offer)),
        offer,
      );
      setPairing({
        offer,
        request: start.request,
        confirmation: start.confirmation ?? null,
        completion: null,
        rotationTicket: null,
        signedAcceptance: null,
        ackDelivered: false,
        automaticTransport: start.automaticTransport,
      });
    } catch (reason) {
      companion.setError(readableError(reason));
    } finally {
      setPairingBusy(false);
    }
  };

  const retryPairingRequest = async () => {
    if (!pairing || !pairing.automaticTransport) return;
    if (busy) {
      companion.setError(BUSY_REFUSAL);
      return;
    }
    setPairingBusy("pairing");
    companion.setError("");
    try {
      const confirmation = validatePairingConfirmationFresh(
        await agentCompanionApi.pairingRetryRequest(),
        pairing.offer,
        pairing.request.mobile_device_id,
      );
      setPairing({ ...pairing, confirmation });
    } catch (reason) {
      companion.setError(readableError(reason));
    } finally {
      setPairingBusy(false);
    }
  };
  const acceptConfirmation = (raw: string) => {
    if (!pairing) return;
    // The manual-transport confirmation scanner can already be open when busy
    // flips, and a scan in that window used to be discarded without a word.
    if (busy) {
      companion.setError(BUSY_REFUSAL);
      return;
    }
    try {
      companion.setError("");
      const rotationEnvelope = parseRotationConfirmationEnvelope(raw);
      const confirmation = parseCompanionConfirmation(
        rotationEnvelope ? JSON.stringify(rotationEnvelope.confirmation) : raw,
        {
        walletId: pairing.offer.agent_wallet_id,
        pairingId: pairing.offer.pairing_id,
        desktopDeviceId: pairing.offer.desktop_device_id,
        mobileDeviceId: pairing.request.mobile_device_id,
        },
      );
      setPairing({
        ...pairing,
        confirmation: validatePairingConfirmationFresh(
          confirmation,
          pairing.offer,
          pairing.request.mobile_device_id,
        ),
        completion: null,
        rotationTicket: rotationEnvelope?.ticket ?? null,
        signedAcceptance: null,
        ackDelivered: false,
      });
    } catch (reason) {
      companion.setError(readableError(reason));
    }
  };

  const confirmPairing = async () => {
    if (!pairing?.confirmation) return;
    if (busy) {
      companion.setError(BUSY_REFUSAL);
      return;
    }
    const humanCode = pairing.confirmation.verification_code;
    setPairingBusy("pairing");
    companion.setError("");
    let completion: CompanionPairingCompletionView;
    let signedAcceptance: SignedRotationCandidateAcceptance | null = null;
    try {
      const rawCompletion = pairing.rotationTicket
        ? await agentCompanionApi.rotationPairingConfirm(
            pairing.confirmation,
            pairing.rotationTicket,
            humanCode,
          )
        : await agentCompanionApi.pairingConfirm(pairing.confirmation, humanCode);
      completion = validatePairingCompletion(rawCompletion, pairing.confirmation);
      signedAcceptance = pairing.rotationTicket
        ? (rawCompletion as RotationCandidatePairingCompletionView).signedAcceptance
        : null;
    } catch (reason) {
      try {
        await agentCompanionApi.pairingCancel();
      } catch {
        // The one-shot native attempt may already have been consumed.
      }
      setPairing(null);
      companion.setError(
        `Pairing did not complete, so nothing was paired and no money moved. Start again on HPAY Desktop: open AI Agent Wallet, run Pair a phone and scan the new QR code with this phone. ${readableError(reason)}`,
      );
      setPairingBusy(false);
      return;
    }

    setPairing({
      ...pairing,
      completion,
      signedAcceptance,
      ackDelivered: Boolean(pairing.rotationTicket),
    });
    // The pairing has already succeeded here. This read used to sit outside
    // every catch, so a rejection escaped into `void confirmPairing()`,
    // setPairingBusy(false) never ran, and the app wedged on a permanent and
    // false "waiting for the fingerprint prompt" banner with no error anywhere.
    try {
      await companion.refreshStoredState();
    } catch (reason) {
      companion.setError(
        `This phone finished pairing, and nothing was paid, signed or lost. It could not read its own saved pairing back afterwards, so this screen may be out of date. Close and reopen the agent space to read it again. ${readableError(reason)}`,
      );
    }
    if (!pairing.rotationTicket) {
      try {
        const delivered = await agentCompanionApi.pairingDeliverAck();
        if (!delivered.delivered) throw new Error("Desktop did not accept the confirmation.");
        setPairing((current) => current ? { ...current, ackDelivered: true } : current);
      } catch (reason) {
        companion.setError(
          `This phone is set up, but HPAY Desktop has not received your confirmation yet, so nothing is paired there. Keep both devices on the same Wi-Fi, keep the pairing screen open on the desktop, and tap ${COMPANION_SEND_CONFIRMATION_ACTION}. ${readableError(reason)}`,
        );
      }
    }
    setPairingBusy(false);
    setPage("overview");
  };

  const retryAck = async () => {
    if (!pairing?.completion || pairing.rotationTicket) return;
    if (busy) {
      companion.setError(BUSY_REFUSAL);
      return;
    }
    setPairingBusy("send_confirmation");
    companion.setError("");
    try {
      const delivered = await agentCompanionApi.pairingDeliverAck();
      if (!delivered.delivered) throw new Error("Desktop did not accept the confirmation.");
      setPairing({ ...pairing, ackDelivered: true });
      setActionNotice(
        `Your confirmation reached HPAY Desktop. Now finish on the desktop: open AI Agent Wallet, find Pair your phone and choose Yes, the codes match. Then come back and tap ${COMPANION_RETRY_AFTER_APPROVAL_ACTION}.`,
      );
    } catch (reason) {
      companion.setError(
        `HPAY Desktop did not take the confirmation, so nothing is paired there yet and nothing was spent. Keep the pairing screen open on the desktop, keep both devices on the same Wi-Fi, and tap ${COMPANION_SEND_CONFIRMATION_ACTION} again. ${readableError(reason)}`,
      );
    } finally {
      setPairingBusy(false);
    }
  };

  const resendPendingAck = async () => {
    if (busy) {
      companion.setError(BUSY_REFUSAL);
      return;
    }
    setPairingBusy("send_confirmation");
    setPendingAckSent(false);
    companion.setError("");
    try {
      const result = await agentCompanionApi.pairingDeliverAck();
      if (!result.delivered) throw new Error("The desktop did not receive the confirmation.");
      setPendingAckSent(true);
      setActionNotice(
        `Your confirmation reached HPAY Desktop. Now finish on the desktop: open AI Agent Wallet, find Pair your phone and choose Yes, the codes match. Then come back and tap ${COMPANION_RETRY_AFTER_APPROVAL_ACTION}.`,
      );
    } catch (reason) {
      companion.setError(
        `HPAY Desktop did not take the confirmation, so nothing is paired there yet and nothing was spent. On the desktop open AI Agent Wallet and leave Pair your phone on screen, keep both devices on the same Wi-Fi, and tap ${COMPANION_SEND_CONFIRMATION_ACTION} again. ${readableError(reason)}`,
      );
    } finally {
      setPairingBusy(false);
    }
  };
  const cancelPairing = async () => {
    const completed = Boolean(pairing?.completion);
    setPairingBusy("cancel");
    companion.setError("");
    try {
      if (!pairing?.completion) {
        const result = await agentCompanionApi.pairingCancel();
        if (!result.pairingCancelled) {
          throw new Error("Native pairing cancellation was not confirmed.");
        }
      }
      setPairing(null);
      if (completed) setPage("overview");
    } catch (reason) {
      companion.setError(readableError(reason));
    } finally {
      setPairingBusy(false);
    }
  };

  const finishIdentityCreation = () => {
    void companion
      .createIdentity()
      .then(() => setCreateConfirm(false))
      .catch(() => undefined);
  };

  const decidePayment = async (
    approval: AgentCompanionPendingApproval,
    decision: "approve" | "reject",
  ) => {
    const snapshot = companion.trustedSnapshot;
    if (
      busy ||
      !snapshot?.pilotEnabled ||
      !verifiedAgentApprovalFacts(approval, snapshot) ||
      !authorizedAgentForApproval(approval, snapshot)
    ) {
      // The old sentence said "Tap Refresh now". No button anywhere on the
      // phone carried that label, and the control that does the job used to sit
      // inside the connection card on another part of the screen. It is named
      // exactly now, and Activity carries that button itself.
      companion.setError(
        snapshot && !snapshot.pilotEnabled
          ? "This build of the phone app is read-only, so it has no Approve or Reject. Nothing was paid or signed. Decide this request in AI Agent Wallet on HPAY Desktop, under Security and approvals."
          : `This payment request can no longer be approved from this phone, so nothing was paid or signed. It has expired, or its details changed since it was shown. Tap ${COMPANION_REFRESH_ACTION} to load the current list from HPAY Desktop.`,
      );
      return;
    }
    setPairingBusy("decision");
    companion.setError("");
    setActionNotice("");
    try {
      const result = await agentCompanionApi.decidePayment(
        toNativeApprovalCommitment(approval),
        decision,
      );
      if (
        result.operationId !== approval.operationId ||
        result.approved !== (decision === "approve") ||
        (decision === "approve" && !result.witnessed)
      ) {
        throw new Error("The native pilot decision response was not exact.");
      }
      setActionNotice(
        decision === "approve"
          ? "The exact testnet payment was approved and witnessed."
          : "The testnet payment request was rejected. No payment was signed.",
      );
      await companion.syncNow();
    } catch (reason) {
      setActionNotice("");
      companion.setError(readableError(reason));
    } finally {
      setPairingBusy(false);
    }
  };

  /**
   * Signs the rollback witness for a payment approved on HPAY Desktop.
   *
   * Nothing about the payment is chosen here. The operation, amount and
   * recipient come from the one disclosed pending-witness entry, and the native
   * side writes the owner's confirmation of exactly those durably before it
   * fetches the anchor or asks for a biometric.
   */
  const witnessPending = async (operation: AgentCompanionActivity) => {
    const snapshot = companion.trustedSnapshot;
    if (busy || !snapshot?.pilotEnabled) {
      companion.setError(
        snapshot && !snapshot.pilotEnabled
          ? "This build of the phone app is read-only, so it cannot sign a witness. Nothing was signed."
          : BUSY_REFUSAL,
      );
      return;
    }
    const current = pendingWitnessOperation(snapshot);
    if (
      !current ||
      current.activityId !== operation.activityId ||
      current.amountUnits !== operation.amountUnits ||
      current.recipient !== operation.recipient ||
      current.status !== operation.status
    ) {
      // What is on the screen is no longer what the desktop is waiting for.
      // Refuse rather than sign a witness for something the owner did not read.
      companion.setError(
        `This payment is no longer the one waiting for your witness, so nothing was signed. Tap ${COMPANION_REFRESH_ACTION} to load the current state from HPAY Desktop.`,
      );
      return;
    }
    setPairingBusy("decision");
    companion.setError("");
    setActionNotice("");
    try {
      const result = await agentCompanionApi.witnessPending(current);
      if (!result.accepted) {
        throw new Error("The desktop did not accept the rollback witness.");
      }
      setActionNotice(
        "The rollback witness was signed. The desktop can now complete the payment you approved there.",
      );
      await companion.syncNow();
    } catch (reason) {
      setActionNotice("");
      companion.setError(readableError(reason));
    } finally {
      setPairingBusy(false);
    }
  };

  const checkFastPayApproval = async () => {
    if (busy || !companion.session || !companion.stored?.pilotEnabled) {
      companion.setError(
        !companion.stored?.pilotEnabled
          ? "Agent Fast Pay approvals are disabled in this build."
          : "Connect to HPAY Desktop before checking Fast Pay approvals.",
      );
      return;
    }
    setPairingBusy("decision");
    companion.setError("");
    setActionNotice("");
    try {
      const result = await agentCompanionApi.pendingFastPay();
      setFastPayApproval(result.commitment);
      if (!result.commitment) {
        setActionNotice("No Agent Fast Pay approval is waiting.");
      }
    } catch (reason) {
      setFastPayApproval(null);
      companion.setError(readableError(reason));
    } finally {
      setPairingBusy(false);
    }
  };

  const decideFastPay = async (decision: "approve" | "reject") => {
    const approval = fastPayApproval;
    if (busy || !approval) return;
    setPairingBusy("decision");
    companion.setError("");
    setActionNotice("");
    try {
      const result = await agentCompanionApi.decideFastPay(
        decision,
        approval.operation_id,
      );
      if (
        result.operationId !== approval.operation_id ||
        result.approvalId !== approval.approval_id ||
        result.approved !== (decision === "approve")
      ) {
        throw new Error("The desktop did not confirm the exact Fast Pay decision.");
      }
      setFastPayApproval(null);
      setActionNotice(
        decision === "approve"
          ? "Fast Pay was approved on this phone. No payment was submitted yet."
          : "Fast Pay was rejected. No payment bill was signed or submitted.",
      );
    } catch (reason) {
      companion.setError(
        `${readableError(reason)} If Android finished the fingerprint but the desktop answer was lost, tap the same choice to retry safely.`,
      );
    } finally {
      setPairingBusy(false);
    }
  };

  const checkHvmApproval = async () => {
    if (busy || !companion.session || !companion.stored?.pilotEnabled) {
      companion.setError(
        !companion.stored?.pilotEnabled
          ? "HVM Fast Pay approvals are disabled in this build."
          : "Connect to HPAY Desktop before checking HVM approvals.",
      );
      return;
    }
    setPairingBusy("decision");
    companion.setError("");
    setActionNotice("");
    try {
      const result = await agentCompanionApi.pendingHvmFastPay();
      setHvmApproval(result.commitment);
      if (!result.commitment) {
        setActionNotice("No HVM Fast Pay approval is waiting.");
      }
    } catch (reason) {
      setHvmApproval(null);
      companion.setError(readableError(reason));
    } finally {
      setPairingBusy(false);
    }
  };

  const decideHvm = async (decision: "approve" | "reject") => {
    const approval = hvmApproval;
    if (busy || !approval) return;
    setPairingBusy("decision");
    companion.setError("");
    setActionNotice("");
    try {
      const result = await agentCompanionApi.decideHvmFastPay(
        decision,
        approval.operation_id,
      );
      if (
        result.operationId !== approval.operation_id ||
        result.approvalId !== approval.approval_id ||
        result.approved !== (decision === "approve")
      ) {
        throw new Error("The desktop did not confirm the exact HVM decision.");
      }
      setHvmApproval(null);
      setActionNotice(
        decision === "approve"
          ? "HVM Fast Pay was approved on this phone. No payment was submitted yet."
          : "HVM Fast Pay was rejected. No bill was signed or submitted.",
      );
    } catch (reason) {
      companion.setError(
        readableError(reason) +
          " If Android finished the fingerprint but the desktop answer was lost, tap the same choice to retry safely.",
      );
    } finally {
      setPairingBusy(false);
    }
  };

  const resetCompanion = () => {
    if (resetText !== "RESET COMPANION") return;
    if (busy) {
      companion.setError(BUSY_REFUSAL);
      return;
    }
    void companion
      .resetCompanion()
      .then(() => {
        setPairing(null);
          setResetConfirm(false);
        setResetText("");
      })
      .catch(() => undefined);
  };

  /**
   * Retires a pairing bound to a companion key this phone no longer holds.
   *
   * Only reachable when the native state view reports the identity as replaced
   * or absent, and the native side re-reads the Keystore and refuses anyway if
   * the key is still live.
   */
  const retirePairing = () => {
    if (retireText !== "RETIRE THIS PAIRING") return;
    if (busy) {
      companion.setError(BUSY_REFUSAL);
      return;
    }
    void companion
      .retireOrphanedPairing()
      .then(() => {
        setPairing(null);
        setRetireConfirm(false);
        setRetireText("");
      })
      .catch(() => undefined);
  };

  /**
   * Ends this phone's intent to sign the one payment it is still holding.
   *
   * The operation id comes from the native stored state, which is the record
   * being discarded, so the press can only ever discard the payment the screen
   * showed. It signs nothing, cancels nothing and un-signs nothing.
   */
  const discardHeldConsent = () => {
    const held = companion.stored?.pendingConsent;
    if (!held) return;
    if (discardText !== COMPANION_DISCARD_CONSENT_PHRASE) return;
    if (busy) {
      companion.setError(BUSY_REFUSAL);
      return;
    }
    void companion
      .discardHeldConsent(held.operationId)
      .then(() => {
        setDiscardConfirm(false);
        setDiscardText("");
      })
      .catch(() => undefined);
  };

  const continueRotation = async () => {
    if (busy) {
      companion.setError(BUSY_REFUSAL);
      return;
    }
    setPairingBusy("rotation");
    companion.setError("");
    try {
      await agentCompanionApi.rotationStep();
      await companion.refreshStoredState();
    } catch (reason) {
      companion.setError(readableError(reason));
    } finally {
      setPairingBusy(false);
    }
  };

  const configured = Boolean(companion.stored?.configured);
  // One status, one meaning. "Paired, disconnected" used to be shown both for a
  // phone the desktop had admitted and for one it had never finalized, which
  // are opposite situations with opposite next steps. This is presentation
  // only: it reads existing state and decides nothing.
  const pairingState = companionPairingStateView({
    configured,
    pendingPairingFinalization: Boolean(companion.stored?.pendingPairingFinalization),
    pairingInProgress: pairing !== null,
    hasSession: companion.session !== null,
    hasTrustedSnapshot: companion.trustedSnapshot !== null,
    lastError: companion.error,
    // What the Security tab actually renders in this state. Without these the
    // strip named Create mobile identity for a handset that cannot host one and
    // for a phone whose identity status could not be read, and neither of those
    // screens has that button.
    identityKnown: companion.identity !== null,
    platformSupported: companion.identity?.platformSupported !== false,
    identityConfigured: Boolean(companion.identity?.configured),
    // The scanner is gated on `ready`, not on `configured`. Without this the
    // strip told a phone whose identity is locked to use Scan desktop QR, and
    // the pairing panel renders no scanner in that state.
    identityReady: companion.identity?.ready,
    // A trusted snapshot that vanished because one request expired is not the
    // connection failing. The strip must not say it is checking when it is not.
    approvalExpiredThisTick: companion.approvalExpiredThisTick,
  });

  // One control, one owner. The stale-approval message tells the owner to tap
  // Refresh the status now, so that button has to exist on the screen that
  // shows the message rather than inside a card further down.
  const pageContent = (
    <>
      {configured && page === "overview" ? (
        <CompanionOverview
          snapshot={companion.trustedSnapshot}
          hasSession={companion.session !== null}
          onOpenActivity={() => setPage("activity")}
        />
      ) : null}
      {configured && page === "agents" ? (
        <CompanionAgents
          snapshot={companion.trustedSnapshot}
          hasSession={companion.session !== null}
        />
      ) : null}
      {configured && page === "rules" ? (
        <CompanionRules
          snapshot={companion.trustedSnapshot}
          hasSession={companion.session !== null}
        />
      ) : null}
      {configured && page === "activity" ? (
        <>
          <AgentFastPayApprovalCard
            approval={fastPayApproval}
            busy={busy}
            connected={companion.session !== null}
            onCheck={() => void checkFastPayApproval()}
            onDecision={(decision) => void decideFastPay(decision)}
          />
          <AgentHvmApprovalCard
            approval={hvmApproval}
            busy={busy}
            connected={companion.session !== null}
            onCheck={() => void checkHvmApproval()}
            onDecision={(decision) => void decideHvm(decision)}
          />
          <CompanionActivity
            snapshot={companion.trustedSnapshot}
            // syncNow returns immediately while the eight-second heartbeat is in
            // flight, so without this the button was enabled and the press did
            // nothing at all: no spinner, no error, no change.
            busy={busy || companion.syncInFlight}
            hasSession={companion.session !== null}
            onRefresh={companion.session ? () => void companion.syncNow() : undefined}
            onDecision={(approval, decision) =>
              void decidePayment(approval, decision)
            }
            onWitness={(operation) => void witnessPending(operation)}
          />
        </>
      ) : null}
      {page === "security" ? (
        <CompanionSecurity
          identity={companion.identity}
          stored={companion.stored}
          busy={busy}
          createConfirm={createConfirm}
          resetConfirm={resetConfirm}
          resetText={resetText}
          onBeginCreate={() => setCreateConfirm(true)}
          onCancelCreate={() => setCreateConfirm(false)}
          onCreate={finishIdentityCreation}
          onRetry={() => {
            companion.setError("");
            // Settled, not all. This is the only control the identity-unknown
            // state offers, and running the two reads as one promise meant a
            // stored state that would not validate discarded a perfectly
            // readable identity with it, so the button could never move the
            // screen forward.
            void Promise.allSettled([
              companion.refreshIdentity(),
              companion.refreshStoredState(),
            ]).then((results) => {
              const failed = results.find((result) => result.status === "rejected");
              if (failed && failed.status === "rejected") {
                companion.setError(readableError(failed.reason));
              }
            });
          }}
          onBeginReset={() => setResetConfirm(true)}
          onCancelReset={() => {
            setResetConfirm(false);
            setResetText("");
          }}
          onResetText={setResetText}
          onReset={resetCompanion}
          onRotationStep={() => void continueRotation()}
          retireConfirm={retireConfirm}
          retireText={retireText}
          onBeginRetire={() => setRetireConfirm(true)}
          onCancelRetire={() => {
            setRetireConfirm(false);
            setRetireText("");
          }}
          onRetireText={setRetireText}
          onRetire={retirePairing}
          revocationSuspected={companionRevocationSuspected(companion.error)}
          discardConfirm={discardConfirm}
          discardText={discardText}
          onBeginDiscard={() => setDiscardConfirm(true)}
          onCancelDiscard={() => {
            setDiscardConfirm(false);
            setDiscardText("");
          }}
          onDiscardText={setDiscardText}
          onDiscard={discardHeldConsent}
        />
      ) : null}
    </>
  );

  // The pairing panel, the connection card and the health card are the same on
  // every tab and are roughly a screen tall. Leaving them above the selected
  // page pushed that page's own content off the bottom of the phone, so tapping
  // Agents or Rules looked like it did nothing. The same fault applied to the
  // shared blocks themselves: a phone waiting on Send my confirmation rendered
  // the whole Security tab above the only control that state has.
  //
  // Presentation only. The block that owns the one control this state depends
  // on goes directly under the one-line status strip; every other block keeps
  // the order it already had, and no block is added, removed or re-wired.
  const layout = {
    page,
    platformSupported: companion.identity?.platformSupported !== false,
    identityConfigured: Boolean(companion.identity?.configured),
    configured,
    pairingInProgress: pairing !== null,
    pairingCompleted: Boolean(pairing?.completion),
    pendingPairingFinalization: Boolean(companion.stored?.pendingPairingFinalization),
    hasSession: companion.session !== null,
    hasTrustedSnapshot: companion.trustedSnapshot !== null,
    connectRetryAvailable: companion.connectRetryAvailable,
    pendingApprovals: companion.trustedSnapshot?.pendingApprovals.length ?? 0,
  };
  const blockOrder = companionBlockOrder(layout);

  // Which single control this state is about. Nothing reads it to decide
  // whether an action is allowed, only how loudly it is drawn.
  const primaryAction = companionPrimaryAction(layout);

  // The status strip, and the three transient notices that report what just
  // happened. Never a control this state depends on, so nothing here competes
  // with the block directly under it.
  const statusStripBlock = (
    <>
      {/* One line at rest, on every tab, in place of the standing notice and
          the eighteen-line health card that used to open all five of them.
          Nothing was deleted: every sentence and every row is inside the
          disclosure below, which opens by itself while something is unresolved
          so a refusal is never hidden from the owner who is stuck in it. */}
      <section className="agent-status-strip" role="status" aria-live="polite">
        <details className="agent-disclosure" open={pairingState.nextAction !== ""}>
          <summary>
            <span className="agent-status-text">{pairingState.label}</span>
            <span className="agent-state-pill">{pairingState.pill}</span>
          </summary>
          {/* The status alone never said what it meant or what to do about
              it, so the same six words were read as "broken" and as "fine". */}
          <p className="agent-muted">{pairingState.detail}</p>
          {pairingState.nextAction ? (
            <p className="agent-muted"><strong>What to do next:</strong> {pairingState.nextAction}</p>
          ) : null}
          <p className="agent-muted">
            <strong>
              {companion.stored?.pilotEnabled
                ? "Testnet payment pilot active"
                : "Testnet payment pilot disabled"}
            </strong>{" "}
            {companion.stored?.pilotEnabled
              ? "Only exact V3, Type 2 testnet approvals with a verified network binding can be authorized. The HPAY wallet fee is always zero."
              : "This companion remains read only. Payment approval and witness signing are unavailable in this build."}
          </p>
          <dl className="agent-detail-list">
            {/* A stored pairing the desktop never finalized is not a pairing:
                the desktop holds no admission record and refuses the device.
                companionPairingStateView gives every one of those situations a
                label no other situation uses. */}
            <Detail label="Companion health" value={pairingState.label} />
            <Detail
              label="Payment network"
              value={companion.stored?.pilotEnabled ? "Testnet only" : "Disabled"}
            />
            <Detail label="HPAY wallet fee" value="None" />
            <Detail label="Agent private key" value="Not stored on mobile" />
          </dl>
        </details>
        {/* The old notice was a three-line warning card repeated above all
            five tabs. The fact it carried is worth one short line, and the
            full explanation is one tap away where it always was. */}
        <p className="agent-boundary-line">
          No wallet key on this phone.
          <button
            type="button"
            className="agent-inline-link"
            onClick={() =>
              void openUrl(AGENT_WALLET_HOW_IT_WORKS_URL).catch((reason) =>
                companion.setError(readableError(reason)),
              )
            }
          >
            What is an AI Agent Wallet?
          </button>
        </p>
      </section>

      {companion.error ? (
        /* "Companion unavailable" was the heading for every failure, from a
           refused pairing to a dropped Wi-Fi, and named none of them.
           The retry button that used to sit here has moved into the
           connection block below, where the only other connect button
           already was. Two buttons calling connectAndSync, side by side and
           both drawn as primary, is exactly the "which one do I need" the
           owner reported; the button itself is unchanged and still reads
           Try connecting again whenever a failure is on screen. */
        <section className="agent-boundary-card" role="alert">
          <strong>That step did not go through</strong>
          <p>{companion.error}</p>
        </section>
      ) : null}
      {actionNotice ? (
        <section className="agent-safe-note agent-action-notice" role="status" aria-live="polite">
          {actionNotice}
        </section>
      ) : null}
      {nativeWait ? (
        <section className="agent-boundary-card" role="status">
          <strong>Waiting for Android security approval</strong>
          <p>{NATIVE_WAIT_TEXT[nativeWait]}</p>
        </section>
      ) : null}
    </>
  );

  const onboardingBlock = !companion.stored?.configured ? (
    <section className="agent-onboarding-hero">
      <div className="agent-robot-orb" aria-hidden>
        <svg viewBox="0 0 24 24"><rect x="5" y="7" width="14" height="12" rx="3" /><path d="M12 3v4M8 12h.01M16 12h.01M9 16h6" /></svg>
      </div>
      <span className="agent-state-pill">{pairingState.pill}</span>
      <h2>Connect your AI Agent Wallet</h2>
      <p>
        An AI Agent Wallet is a separate wallet that a software agent can
        ask for payments from, under limits you set. The agent never holds
        a key and cannot spend anything without your approval.
      </p>
      <p>
        Pair this phone with that wallet on your trusted desktop. Your
        personal wallet stays separate and its keys are never shared.
      </p>
      {/* "Prepare secure identity" did not say where it went or what it
          cost. It opens the Security tab; it creates nothing by itself.
          Once the identity exists, that sentence is no longer true and
          its button competed with the scanner for the same tap, so both
          are dropped and the scanner below is the only primary left.

          On the Security tab both sentences would be false as well: that
          screen is this screen, and the control that creates the identity
          is already above this block. */}
      {companion.identity?.ready || page === "security" ? null : (
        <>
          <p>
            Start here. The next screen creates this phone's secure
            identity. It costs nothing, moves no money and creates no
            wallet key.
          </p>
          <button
            type="button"
            className="agent-primary-action"
            onClick={() => setPage("security")}
          >
            {COMPANION_OPEN_SECURITY_SETUP_ACTION}
          </button>
        </>
      )}
    </section>
  ) : null;

  const pairingBlock =
    !companion.stored?.configured || pairing?.completion ? (
      <CompanionPairingPanel
        identity={companion.identity}
        pairing={pairing}
        busy={busy}
        error={companion.error}
        onOffer={(raw) => void acceptOffer(raw)}
        onConfirmation={acceptConfirmation}
        onRetryRequest={() => void retryPairingRequest()}
        onConfirm={() => void confirmPairing()}
        onRetryAck={() => void retryAck()}
        onCancel={() => void cancelPairing()}
      />
    ) : null;

  const pendingPairingStepBlock =
    companion.stored?.pendingPairingFinalization && !pairing?.completion ? (
      <section className="agent-panel agent-companion-step" role="status">
        <p className="agent-eyebrow">One last step</p>
        <h2>Complete pairing on HPAY Desktop</h2>
        <p className="agent-muted">
          This phone has started pairing, but HPAY Desktop has not completed
          the pairing yet. Until it does, the desktop does not recognise this
          phone and every connection attempt is refused.
        </p>
        {/* The old sentence sent the owner to "Connected Devices", a screen
            that does not exist on HPAY Desktop. The list is called
            Authorized mobile devices and it sits inside Pair your phone. */}
        <p className="agent-muted">
          On HPAY Desktop open AI Agent Wallet and find Pair your phone.
          Check that the six digit code there matches the one this phone
          showed, then choose Yes, the codes match. The paired phone then
          appears under Authorized mobile devices.
        </p>
        {/* Three buttons used to be reachable here with nothing to say
            which one the owner needed. They are numbered now, in the only
            order that works, Step 1 is the only primary, and the reason
            each one is safe sits behind the button it belongs to instead of
            above it. No button was added, removed or re-wired. */}
        <p className="agent-muted">
          <strong>Step 1 on this phone.</strong> Send your confirmation to
          the desktop.
        </p>
        <button
          type="button"
          className="agent-primary-action"
          disabled={busy}
          onClick={() => void resendPendingAck()}
        >
          {COMPANION_SEND_CONFIRMATION_ACTION}
        </button>
        <details className="agent-disclosure">
          <summary>What does Step 1 cost?</summary>
          <p className="agent-muted">
            This is safe to repeat: it sends nothing but the pairing
            confirmation, spends no money and signs no payment.
          </p>
        </details>
        {pendingAckSent ? (
          <p className="agent-safe-note">
            Confirmation sent. Now do step 2 on HPAY Desktop, then come back
            and tap {COMPANION_RETRY_AFTER_APPROVAL_ACTION}.
          </p>
        ) : null}
        <p className="agent-muted">
          <strong>Step 2 on HPAY Desktop.</strong> Open AI Agent Wallet,
          find Pair your phone, check the six digits match and choose Yes,
          the codes match. Only the desktop can approve this phone. No
          button on this phone can do it for you.
        </p>
        <p className="agent-muted">
          <strong>Step 3, back on this phone.</strong> Once the desktop says
          the phone is paired, tap the button below.
        </p>
        <button
          type="button"
          disabled={busy}
          onClick={() => void companion.retryAfterDesktopApproval()}
        >
          {COMPANION_RETRY_AFTER_APPROVAL_ACTION}
        </button>
        <details className="agent-disclosure">
          <summary>What does Step 3 do?</summary>
          <p className="agent-muted">
            It only checks the desktop and opens the connection. It spends
            nothing and cannot approve this phone by itself.
          </p>
          <dl className="agent-detail-list">
            {/* This phone's own identity already exists; what is missing is
                the desktop's record of it. Saying "Identity setup: Pending"
                sent owners to re-create a key that was never the problem. */}
            <Detail label="Desktop record of this phone" value="Not created yet" />
            <Detail label="Desktop approval" value="Required" />
            <Detail label="Transport" value="Not authorized" />
            <Detail label="Witness" value="Not initialized" />
          </dl>
        </details>
        {/* Beside the buttons that produced it. On a phone the alert at the
            top of the page is a whole screen away. */}
        {companion.error ? (
          <p className="agent-safe-note" role="alert">{companion.error}</p>
        ) : null}
      </section>
    ) : null;

  const connectionBlock = companion.stored?.configured ? (
    <>
      <CompanionConnectionPanel
        stored={companion.stored}
        session={companion.session}
        busy={busy}
        syncBusy={busy || companion.syncInFlight}
        hasTrustedSnapshot={companion.trustedSnapshot !== null}
        lastError={companion.error}
        retryAvailable={companion.connectRetryAvailable}
        primaryActionId={primaryAction.id}
        onConnect={() => void companion.connectAndSync()}
        onSync={() => void companion.syncNow()}
        onDisconnect={() => void companion.disconnect()}
      />
      {companion.session && !companion.trustedSnapshot ? (
        <section className="agent-boundary-card" role="status">
          <strong>Waiting for fresh desktop data</strong>
          <p>
            The encrypted session is connected, but wallet data stays hidden
            until a current authenticated snapshot passes every validation.
          </p>
        </section>
      ) : null}
    </>
  ) : null;

  const renderBlock = (id: CompanionBlockId) => {
    switch (id) {
      case "status_strip":
        return <Fragment key={id}>{statusStripBlock}</Fragment>;
      case "onboarding":
        return <Fragment key={id}>{onboardingBlock}</Fragment>;
      case "pairing":
        return <Fragment key={id}>{pairingBlock}</Fragment>;
      case "pending_pairing_step":
        return <Fragment key={id}>{pendingPairingStepBlock}</Fragment>;
      case "connection":
        return <Fragment key={id}>{connectionBlock}</Fragment>;
      case "page_content":
        return <Fragment key={id}>{pageContent}</Fragment>;
    }
  };

  return (
    <div className="agent-mobile-shell">
      <header className="agent-mobile-header">
        <div className="agent-mobile-brand">
          <WalletLogo size="sm" variant="mark" />
          <div>
            <h1>AI Agent Wallet</h1>
            <p>
              {companion.stored?.pilotEnabled
                ? "Testnet payment pilot"
                : "Read-only companion"}
            </p>
          </div>
        </div>
        {/* "Disconnected" was shown for a phone that was never paired, for one
            the desktop had not finalized and for a paired phone whose link had
            simply dropped. One badge, three unrelated meanings. */}
        <ConnectionState
          connected={companion.session !== null}
          label={pairingState.pill}
        />
      </header>

      <main className="agent-mobile-main">
        {/* Top first, decided in companionLayout. The block that owns the one
            control this state depends on renders directly under the one-line
            status strip; everything else keeps the order it already had. */}
        {blockOrder.map((id) => renderBlock(id))}
      </main>

      <nav className="agent-mobile-nav" aria-label="AI Agent Wallet">
        {PAGES.map((item) => (
          <button
            key={item.id}
            type="button"
            className={page === item.id ? "active" : ""}
            aria-current={page === item.id ? "page" : undefined}
            onClick={() => {
              setPage(item.id);
              window.scrollTo({ top: 0, behavior: "smooth" });
            }}
          >
            <AgentNavIcon kind={item.id} />
            <span>{item.label}</span>
            {item.id === "activity" && (companion.trustedSnapshot?.pendingApprovals.length ?? 0) > 0 ? (
              <span className="agent-nav-badge" aria-label={`${companion.trustedSnapshot?.pendingApprovals.length} pending approvals`}>
                {companion.trustedSnapshot?.pendingApprovals.length}
              </span>
            ) : null}
          </button>
        ))}
      </nav>
    </div>
  );
}

/** Which native call the phone is waiting on. "" means it is waiting on none. */
type NativeWaitReason =
  | ""
  | "pairing"
  | "send_confirmation"
  | "cancel"
  | "decision"
  | "rotation";

/**
 * What the waiting banner says, per reason.
 *
 * Every one of these is a real Android biometric prompt, but only one of them
 * is pairing. Telling an owner who has just tapped Approve that they are in the
 * middle of pairing is an error naming the wrong cause.
 */
const NATIVE_WAIT_TEXT: Record<Exclude<NativeWaitReason, "">, string> = {
  pairing:
    "Complete or cancel the fingerprint prompt to continue pairing. Nothing is paired and no money moves either way.",
  send_confirmation:
    "Complete or cancel the fingerprint prompt to send this phone's confirmation to the desktop. It sends the pairing confirmation only, spends nothing and signs no payment.",
  cancel:
    "Complete or cancel the fingerprint prompt to stop this pairing attempt. Nothing was paired and nothing was spent either way.",
  decision:
    "Complete or cancel the fingerprint prompt to record your decision on this exact testnet payment. Cancelling the prompt decides nothing and pays nothing.",
  rotation:
    "Complete or cancel the fingerprint prompt to continue the approval phone rotation. It moves no money and signs no payment.",
};

/** Shown in place of a bare return when a control is pressed while busy. */
const BUSY_REFUSAL =
  "This phone is still finishing the last step, so that press was not used. Nothing was paid, signed or changed. Wait for the step above to finish, then try again.";

/**
 * Why a scanned pairing offer was not used, or "" when it will be.
 *
 * `acceptOffer` used to return silently on this guard. The scanner fires
 * onValue exactly once and then closes the camera, so the owner saw the camera
 * shut and nothing else happen - the confirmed historical defect, verbatim.
 */
export function scanRefusal(input: {
  busy: boolean;
  configured: boolean;
  identityReady: boolean;
}): string {
  if (input.configured) {
    return "This phone is already paired with an Agent Wallet, so that code was not used and nothing changed. To pair it with a different desktop, run Reset this phone's pairing only on the Security tab first.";
  }
  if (!input.identityReady) {
    return "This phone's secure identity is not ready, so that code was not used and nothing was paired. Open the Security tab: create the identity if it does not exist yet, or unlock the phone and confirm the fingerprint prompt if it does.";
  }
  if (input.busy) {
    return `${BUSY_REFUSAL} The code you scanned was not used, so scan it again afterwards.`;
  }
  return "";
}

function parseRotationOfferEnvelope(raw: string): {
  offer: ReturnType<typeof parseCompanionOffer>;
} | null {
  try {
    const value = JSON.parse(raw) as Record<string, unknown>;
    if (value.kind !== "hpay_rotation_candidate_offer_v1" || !value.offer) return null;
    return { offer: parseCompanionOffer(JSON.stringify(value.offer)) };
  } catch {
    return null;
  }
}

function parseRotationConfirmationEnvelope(raw: string): {
  confirmation: unknown;
  ticket: SignedRotationPairingTicket;
} | null {
  try {
    const value = JSON.parse(raw) as Record<string, unknown>;
    if (
      value.kind !== "hpay_rotation_candidate_confirmation_v1"
      || !value.confirmation
      || !value.ticket
    ) return null;
    return {
      confirmation: value.confirmation,
      ticket: value.ticket as SignedRotationPairingTicket,
    };
  } catch {
    return null;
  }
}

function AgentNavIcon({ kind }: { kind: AgentPage }) {
  const path = kind === "overview"
    ? "M3 11.5 12 4l9 7.5v8H6v-8M10 20v-5h4v5"
    : kind === "agents"
      ? "M8 11a3 3 0 1 0 0-6 3 3 0 0 0 0 6Zm8-1a2.5 2.5 0 1 0 0-5M3 20v-2a5 5 0 0 1 10 0v2M14 14a4 4 0 0 1 7 3v3"
      : kind === "rules"
        ? "M12 3 5 6v5c0 4.8 3 8 7 10 4-2 7-5.2 7-10V6l-7-3Zm-3 9 2 2 4-4"
        : kind === "activity"
          ? "M4 5v5h5M5 10a8 8 0 1 0 2-5M12 7v5l3 2"
          : "M12 3 5 6v5c0 4.8 3 8 7 10 4-2 7-5.2 7-10V6l-7-3ZM9 12l2 2 4-4";
  return <svg className="agent-nav-icon" viewBox="0 0 24 24" aria-hidden><path d={path} /></svg>;
}
function ConnectionState({
  connected,
  label,
}: {
  connected: boolean;
  label: string;
}) {
  return (
    <span className={`agent-connection ${connected ? "connected" : "disconnected"}`}>
      {label}
    </span>
  );
}

/**
 * Copy only. One funnel so no raw Rust Display ever reaches the owner, and
 * every refusal arrives with a cause and a next action. No refusal is softened
 * or swallowed: the failing path still fails, and still fails closed.
 */
function readableError(error: unknown): string {
  return companionFailureText(error);
}

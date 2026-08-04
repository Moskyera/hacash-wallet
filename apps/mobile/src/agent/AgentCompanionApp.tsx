import { useState } from "react";
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
  companionPageLeadsWithOwnContent,
  companionPrimaryAction,
  type AgentCompanionPage,
} from "./companionLayout";
import {
  authorizedAgentForApproval,
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
import { useCompanionSession } from "./useCompanionSession";
import type {
  AgentCompanionPendingApproval,
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
  const [pairingBusy, setPairingBusy] = useState(false);
  const [pendingAckSent, setPendingAckSent] = useState(false);
  const [createConfirm, setCreateConfirm] = useState(false);
  const [resetConfirm, setResetConfirm] = useState(false);
  const [resetText, setResetText] = useState("");
  const [actionNotice, setActionNotice] = useState("");
  const busy = Boolean(companion.busy) || pairingBusy;

  const acceptOffer = async (raw: string) => {
    if (busy || companion.stored?.configured || !companion.identity?.ready) return;
    setPairingBusy(true);
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
    if (!pairing || !pairing.automaticTransport || busy) return;
    setPairingBusy(true);
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
    if (!pairing || busy) return;
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
    if (!pairing?.confirmation || busy) return;
    const humanCode = pairing.confirmation.verification_code;
    setPairingBusy(true);
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
    await companion.refreshStoredState();
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
    if (!pairing?.completion || pairing.rotationTicket || busy) return;
    setPairingBusy(true);
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
    if (busy) return;
    setPairingBusy(true);
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
    setPairingBusy(true);
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
        `This payment request can no longer be approved from this phone, so nothing was paid or signed. It has expired, or its details changed since it was shown. Tap ${COMPANION_REFRESH_ACTION} to load the current list from HPAY Desktop.`,
      );
      return;
    }
    setPairingBusy(true);
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

  const resetCompanion = () => {
    if (resetText !== "RESET COMPANION" || busy) return;
    void companion
      .resetCompanion()
      .then(() => {
        setPairing(null);
          setResetConfirm(false);
        setResetText("");
      })
      .catch(() => undefined);
  };

  const continueRotation = async () => {
    if (busy) return;
    setPairingBusy(true);
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
  });

  // One control, one owner. The stale-approval message tells the owner to tap
  // Refresh the status now, so that button has to exist on the screen that
  // shows the message rather than inside a card further down.
  const pageContent = (
    <>
      {configured && page === "overview" ? (
        <CompanionOverview
          snapshot={companion.trustedSnapshot}
          onOpenActivity={() => setPage("activity")}
        />
      ) : null}
      {configured && page === "agents" ? <CompanionAgents snapshot={companion.trustedSnapshot} /> : null}
      {configured && page === "rules" ? <CompanionRules snapshot={companion.trustedSnapshot} /> : null}
      {configured && page === "activity" ? (
        <CompanionActivity
          snapshot={companion.trustedSnapshot}
          busy={busy}
          onRefresh={companion.session ? () => void companion.syncNow() : undefined}
          onDecision={(approval, decision) =>
            void decidePayment(approval, decision)
          }
        />
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
            void Promise.all([
              companion.refreshIdentity(),
              companion.refreshStoredState(),
            ]).catch((reason) => companion.setError(readableError(reason)));
          }}
          onBeginReset={() => setResetConfirm(true)}
          onCancelReset={() => {
            setResetConfirm(false);
            setResetText("");
          }}
          onResetText={setResetText}
          onReset={resetCompanion}
          onRotationStep={() => void continueRotation()}
          revocationSuspected={companionRevocationSuspected(companion.error)}
        />
      ) : null}
    </>
  );

  // The pairing panel, the connection card and the health card are the same on
  // every tab and are roughly a screen tall. Leaving them above the selected
  // page pushed that page's own content off the bottom of the phone, so tapping
  // Agents or Rules looked like it did nothing. A tab now leads with its own
  // content whenever it has any: Security always does, and the other four are
  // drawn from the authenticated snapshot, so without one there is nothing to
  // lead with and the connection block - the only thing that produces a
  // snapshot - goes first instead. The unpaired onboarding order is untouched.
  const leadWithPage = companionPageLeadsWithOwnContent({
    page,
    configured,
    hasTrustedSnapshot: companion.trustedSnapshot !== null,
  });

  // Presentation only: which single control this state is about. Nothing reads
  // it to decide whether an action is allowed, only how loudly it is drawn.
  const primaryAction = companionPrimaryAction({
    page,
    platformSupported: companion.identity?.platformSupported !== false,
    identityConfigured: Boolean(companion.identity?.configured),
    configured,
    pairingInProgress: pairing !== null,
    pendingPairingFinalization: Boolean(companion.stored?.pendingPairingFinalization),
    hasSession: companion.session !== null,
    connectRetryAvailable: companion.connectRetryAvailable,
    pendingApprovals: companion.trustedSnapshot?.pendingApprovals.length ?? 0,
  });

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

        {!companion.stored?.configured ? (
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
                are dropped and the scanner below is the only primary left. */}
            {companion.identity?.ready ? null : (
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
        ) : null}
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
        {pairingBusy ? (
          <section className="agent-boundary-card" role="status">
            <strong>Waiting for Android security approval</strong>
            <p>Complete or cancel the fingerprint prompt to continue pairing.</p>
          </section>
        ) : null}

        {leadWithPage ? pageContent : null}

        {!companion.stored?.configured || pairing?.completion ? (
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
        ) : null}

        {companion.stored?.pendingPairingFinalization && !pairing?.completion ? (
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
        ) : null}
        {companion.stored?.configured ? (
          <CompanionConnectionPanel
            stored={companion.stored}
            session={companion.session}
            busy={busy}
            lastError={companion.error}
            retryAvailable={companion.connectRetryAvailable}
            primaryActionId={primaryAction.id}
            onConnect={() => void companion.connectAndSync()}
            onSync={() => void companion.syncNow()}
            onDisconnect={() => void companion.disconnect()}
          />
        ) : null}

        {companion.stored?.configured && companion.session && !companion.trustedSnapshot ? (
          <section className="agent-boundary-card" role="status">
            <strong>Waiting for fresh desktop data</strong>
            <p>
              The encrypted session is connected, but wallet data stays hidden
              until a current authenticated snapshot passes every validation.
            </p>
          </section>
        ) : null}

        {leadWithPage ? null : pageContent}
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

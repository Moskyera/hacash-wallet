import { useEffect, useState } from "react";
import {
  CompanionQrDisplay,
  CompanionQrScanner,
  encodeCompanionRequest,
} from "@hacash/wallet-ui";
import type {
  AgentCompanionIdentityStatus,
  CompanionPairingCompletionView,
  CompanionPairingConfirmation,
  CompanionPairingOffer,
  CompanionPairingRequest,
  CompanionSessionView,
  CompanionStoredStateView,
  SignedRotationCandidateAcceptance,
  SignedRotationPairingTicket,
} from "./types";
import { shortValue } from "./companionView";
import {
  COMPANION_CONNECT_ACTION,
  COMPANION_SEND_CONFIRMATION_ACTION,
  COMPANION_TRY_AGAIN_ACTION,
  COMPANION_TRY_AGAIN_IS_SAFE,
  companionPairingStateView,
} from "./companionStatus";
import {
  COMPANION_CONNECTION_SECTION_TITLE,
  COMPANION_CREATE_IDENTITY_ACTION,
  COMPANION_PLATFORM_UNSUPPORTED_BODY,
  COMPANION_PLATFORM_UNSUPPORTED_ROUTE,
  COMPANION_PLATFORM_UNSUPPORTED_TITLE,
  COMPANION_RECHECK_IDENTITY_ACTION,
  COMPANION_REFRESH_ACTION,
  COMPANION_SCAN_QR_ACTION,
  type CompanionPrimaryActionId,
} from "./companionLayout";

export type PairingFlow = {
  offer: CompanionPairingOffer;
  request: CompanionPairingRequest;
  confirmation: CompanionPairingConfirmation | null;
  completion: CompanionPairingCompletionView | null;
  rotationTicket: SignedRotationPairingTicket | null;
  signedAcceptance: SignedRotationCandidateAcceptance | null;
  ackDelivered: boolean;
  automaticTransport: boolean;
};

type PairingProps = {
  identity: AgentCompanionIdentityStatus | null;
  pairing: PairingFlow | null;
  busy: boolean;
  error: string;
  onOffer: (raw: string) => void;
  onConfirmation: (raw: string) => void;
  onRetryRequest: () => void;
  onConfirm: () => void;
  onRetryAck: () => void;
  onCancel: () => void;
};

export function CompanionPairingPanel({
  identity,
  pairing,
  busy,
  error,
  onOffer,
  onConfirmation,
  onRetryRequest,
  onConfirm,
  onRetryAck,
  onCancel,
}: PairingProps) {
  const [nowUnix, setNowUnix] = useState(() => Math.floor(Date.now() / 1000));
  useEffect(() => {
    if (!pairing?.confirmation || pairing.completion) return undefined;
    const timer = window.setInterval(
      () => setNowUnix(Math.floor(Date.now() / 1000)),
      1_000,
    );
    return () => window.clearInterval(timer);
  }, [pairing?.completion, pairing?.confirmation]);

  const expiresAt = Number(pairing?.confirmation?.expires_at ?? "0");
  const expired = Number.isFinite(expiresAt) && expiresAt > 0 && expiresAt <= nowUnix;
  if (!identity) {
    // The identity status could not be read at all. The Security tab renders
    // only "Check this phone's security status again" in that state, so naming
    // Create mobile identity here named a button that is not on the screen.
    return (
      <Unavailable
        title="This phone's security status could not be read"
        body={`Pairing cannot start until this phone can read its own secure identity. Nothing is wrong with your wallet, nothing was paired and nothing was changed. Open the Security tab and use ${COMPANION_RECHECK_IDENTITY_ACTION}. It reads this phone only and costs nothing.`}
      />
    );
  }
  if (!identity.ready) {
    // Three different reasons used to render one sentence that sent every one
    // of them to "Create mobile identity". On a handset that cannot hold the
    // key that button never appears, and on a phone whose key exists but is
    // locked it does not appear either, so for two of the three the instruction
    // named a control that was not on the screen.
    if (!identity.platformSupported) {
      return (
        <Unavailable
          title={COMPANION_PLATFORM_UNSUPPORTED_TITLE}
          body={`${COMPANION_PLATFORM_UNSUPPORTED_BODY} ${COMPANION_PLATFORM_UNSUPPORTED_ROUTE}`}
        />
      );
    }
    if (identity.configured) {
      return (
        <Unavailable
          title="This phone's secure identity is locked"
          body={`The identity exists but Android will not open it right now, so pairing cannot start. Unlock the phone and confirm the fingerprint or face prompt, then open the Security tab and use ${COMPANION_RECHECK_IDENTITY_ACTION}. Nothing is wrong with your wallet and nothing was changed.`}
        />
      );
    }
    return (
      <Unavailable
        title="This phone is not ready to pair yet"
        body={`Pairing needs this phone's secure identity, and it has not been created. Open the Security tab and choose ${COMPANION_CREATE_IDENTITY_ACTION}. It costs nothing and creates no wallet key. Then come back here and use ${COMPANION_SCAN_QR_ACTION}.`}
      />
    );
  }
  if (!pairing) {
    return (
      <section className="agent-panel agent-companion-step">
        <p className="agent-eyebrow">Step 1</p>
        <h2>Scan the QR from your desktop</h2>
        <p className="agent-muted">
          Keep this phone and your desktop on the same Wi-Fi. After scanning,
          Android will ask for your fingerprint.
        </p>
        {error ? <p className="agent-safe-note" role="alert">{error}</p> : null}
        <CompanionQrScanner
          label={COMPANION_SCAN_QR_ACTION}
          disabled={busy}
          onValue={onOffer}
        />
        {/* "Cancel pending connection" implied there was a connection to lose.
            There is not: nothing is paired and nothing has been spent. The
            explanation now sits behind the button it belongs to, so the scanner
            above is the only thing this screen asks for. */}
        <details className="agent-disclosure">
          <summary>Stuck part-way through a scan?</summary>
          <p className="agent-muted">
            Nothing is paired yet. The button below only clears a half-started
            pairing attempt on this phone. It changes nothing on the desktop and
            costs nothing.
          </p>
          <button type="button" disabled={busy} onClick={onCancel}>
            Clear this phone's half-started pairing
          </button>
        </details>
      </section>
    );
  }
  if (!pairing.confirmation) {
    if (pairing.automaticTransport) {
      return (
        <section className="agent-panel agent-companion-step">
          <p className="agent-eyebrow">Same Wi-Fi needed</p>
          <h2>The desktop was not reached</h2>
          <p className="agent-muted">
            Keep the pairing screen open on the desktop, check that both devices
            use the same Wi-Fi and try again. You do not need to scan another QR.
          </p>
          {error ? <p className="agent-safe-note" role="alert">{error}</p> : null}
          <button type="button" className="agent-primary-action" disabled={busy} onClick={onRetryRequest}>
            Try reaching the desktop again
          </button>
          <p className="agent-muted">
            Or stop here. Nothing has been paired and nothing has been spent, so
            stopping costs you only the QR code, which you can get again from
            HPAY Desktop.
          </p>
          <button type="button" disabled={busy} onClick={onCancel}>
            Stop pairing and start over
          </button>
        </section>
      );
    }
    return (
      <section className="agent-panel agent-companion-step">
        <p className="agent-eyebrow">Steps 2 and 3</p>
        <h2>Return the mobile request</h2>
        <CompanionQrDisplay
          value={encodeCompanionRequest(pairing.request)}
          label="Signed HPAY mobile pairing request"
        />
        <h3>Scan the desktop confirmation</h3>
        <CompanionQrScanner
          label="Scan desktop confirmation"
          disabled={busy}
          onValue={onConfirmation}
        />
        <button type="button" disabled={busy} onClick={onCancel}>
          Stop pairing and start over
        </button>
      </section>
    );
  }
  if (!pairing.completion) {
    return (
      <section className="agent-panel agent-companion-step">
        <p className="agent-eyebrow">Confirm connection</p>
        <h2>Check the same code on both devices</h2>
        <strong className="agent-verification-code">
          {pairing.confirmation.verification_code}
        </strong>
        <p className="agent-muted">
          If the desktop shows these same six digits, approve the connection.
          Your wallet keys always stay on the desktop.
        </p>
        {expired ? (
          <p className="agent-safe-note" role="alert">
            This pairing code ran out of time, so nothing was paired and nothing
            was spent. On HPAY Desktop open AI Agent Wallet, run Pair a phone
            and scan the new QR code with this phone.
          </p>
        ) : error ? (
          <p className="agent-safe-note" role="alert">{error}</p>
        ) : null}
        {expired ? null : (
          <p className="agent-muted">
            Confirming links this phone to the Agent Wallet on that desktop as a
            read-only companion. It moves no money, signs no payment and gives
            this phone no wallet key.
          </p>
        )}
        <button
          type="button"
          className="agent-primary-action"
          disabled={busy || expired}
          onClick={onConfirm}
        >
          Yes, the codes match
        </button>
        <button type="button" disabled={busy} onClick={onCancel}>
          {expired ? "Start over with a new code" : "Stop pairing and start over"}
        </button>
      </section>
    );
  }
  const automaticPairing = !pairing.rotationTicket;
  return (
    <section className="agent-panel agent-companion-step">
      <p className="agent-eyebrow">Phone confirmed</p>
      <h2>{pairing.ackDelivered ? "Finish on the desktop" : "Sending confirmation"}</h2>
      {automaticPairing ? (
        <>
          {/* "tap Finish" named a button the desktop does not have. The desktop
              control is Yes, the codes match, inside Pair your phone. */}
          <p className="agent-muted">
            {pairing.ackDelivered
              ? "This phone is confirmed. Now finish on HPAY Desktop: open AI Agent Wallet, find Pair your phone, check the six digits are the same and choose Yes, the codes match. Until you do that, the desktop refuses this phone."
              : "Keep both devices on the same Wi-Fi while HPAY sends your confirmation to the desktop."}
          </p>
          {!pairing.ackDelivered ? (
            <button type="button" className="agent-primary-action" disabled={busy} onClick={onRetryAck}>
              {COMPANION_SEND_CONFIRMATION_ACTION}
            </button>
          ) : null}
        </>
      ) : (
        <>
          <CompanionQrDisplay
            value={JSON.stringify({
              kind: "hpay_rotation_candidate_ack_v1",
              encryptedAck: pairing.completion.encryptedAck,
              signedAcceptance: pairing.signedAcceptance,
            })}
            label="Encrypted HPAY rotation acknowledgement"
          />
          <p className="agent-muted">Scan this final rotation QR on the desktop.</p>
          {/* Warned before the press, not after it. This QR is the only
              delivery path for step 4 of the desktop rotation flow, it is held
              in React state alone, and the pairing block stops rendering once
              the durable state is installed - so dismissing it destroys the
              only copy. The button below reads "hide", which promises the
              opposite. */}
          <p className="agent-warning-copy" role="alert">
            This QR code cannot be shown again. HPAY Desktop has to scan it to
            finish the rotation, and there is no control on this phone or on the
            desktop that brings it back. Leave this screen open until the
            desktop has scanned it.
          </p>
        </>
      )}
      {/* "Done" reads like "finish pairing". It does not: it only hides these
          steps on this phone. The desktop step is still outstanding.

          On the rotation path it is destructive rather than merely tidy, so it
          says which one it is and carries the danger styling. */}
      <button
        type="button"
        className={automaticPairing ? "" : "agent-danger-action"}
        disabled={busy}
        onClick={onCancel}
      >
        {automaticPairing
          ? "Hide these steps on this phone"
          : "Discard this rotation QR permanently"}
      </button>
    </section>
  );
}

type ConnectionProps = {
  stored: CompanionStoredStateView;
  session: CompanionSessionView | null;
  busy: boolean;
  /** The most recent failure text, so the state can name the real cause. */
  lastError: string;
  /** A connect attempt has failed and the retry wording applies. */
  retryAvailable: boolean;
  /** A heartbeat already owns the status read, so the refresh cannot run. */
  syncBusy: boolean;
  /** A snapshot that passed every check is on screen. */
  hasTrustedSnapshot: boolean;
  /** The one control this whole screen is about, decided in companionLayout. */
  primaryActionId: CompanionPrimaryActionId;
  onConnect: () => void;
  onSync: () => void;
  onDisconnect: () => void;
};

export function CompanionConnectionPanel({
  stored,
  session,
  busy,
  lastError,
  retryAvailable,
  syncBusy,
  hasTrustedSnapshot,
  primaryActionId,
  onConnect,
  onSync,
  onDisconnect,
}: ConnectionProps) {
  // The heading used to be "Desktop disconnected" for a paired phone whose link
  // had dropped, for one waiting on the desktop, and for one the desktop had
  // refused outright. Same words, three different next steps.
  const state = companionPairingStateView({
    configured: stored.configured,
    pendingPairingFinalization: stored.pendingPairingFinalization,
    pairingInProgress: false,
    hasSession: session !== null,
    hasTrustedSnapshot: false,
    lastError,
  });
  const devicePill = (
    <span className="agent-state-pill">
      {stored.pilotEnabled ? "Testnet approval phone" : "Status companion"}
    </span>
  );
  const walletLine = (
    <p className="agent-muted">
      Wallet {stored.agentWalletId ? shortValue(stored.agentWalletId) : "Unavailable"}
    </p>
  );
  const boundaryNote = (
    <p className="agent-muted">
      The phone can view authenticated Agent Wallet status. In the testnet
      pilot it can approve or reject only an exact verified request with a
      fingerprint. It cannot sign arbitrary transactions or access My Wallet.
    </p>
  );

  if (!session) {
    // One button, and its label is whatever the copy on screen is calling it.
    // Every mapped failure text says "tap Try connecting again", so after a
    // failure that has to be what the button says; from cold, the status line
    // names Connect to the desktop and so does the button.
    const retryWording = Boolean(lastError) || retryAvailable;
    // While the desktop has not approved this phone, connecting is certain to
    // be refused and the pairing step above owns the only useful control. The
    // button is hidden in that one state rather than left to fail.
    const offerConnect =
      primaryActionId === "connect" || primaryActionId === "try_again";
    return (
      <section className="agent-panel agent-session-bar" aria-label="Desktop connection">
        <div className="agent-record-head">
          <div>
            <p className="agent-eyebrow">{COMPANION_CONNECTION_SECTION_TITLE}</p>
            <h2>{state.label}</h2>
          </div>
          {devicePill}
        </div>
        {/* "Connect and sync" said nothing about what it costs or what it
            would do if the desktop has not finished its side. */}
        <p className="agent-muted">{state.detail}</p>
        {/* The reason belongs beside the button that produced it. The card at
            the top of the page is a full screen away on a phone, so a refused
            connect looked like a dead button. */}
        {lastError ? (
          <p className="agent-safe-note" role="alert">{lastError}</p>
        ) : null}
        {offerConnect ? (
          <>
            <button
              type="button"
              className="agent-primary-action"
              disabled={busy}
              onClick={onConnect}
            >
              {busy
                ? "Connecting..."
                : retryWording
                  ? COMPANION_TRY_AGAIN_ACTION
                  : COMPANION_CONNECT_ACTION}
            </button>
            {/* A refused connection commits nothing on either device: no
                sequence advances, no permit is consumed, and no wallet, pairing
                or witness state changes. Pressing again is therefore always
                safe, and for a self-clearing refusal it is the whole fix.
                Without saying so, a transient refusal looked exactly like a
                permanent one, which is what pushes an owner towards resetting
                the pairing - the one action that makes it worse. */}
            {retryWording ? (
              <p className="agent-safe-note">{COMPANION_TRY_AGAIN_IS_SAFE}</p>
            ) : null}
          </>
        ) : (
          <p className="agent-muted">
            There is nothing to connect to yet. Use{" "}
            {COMPANION_SEND_CONFIRMATION_ACTION} in the pairing step on this
            screen, then finish on HPAY Desktop.
          </p>
        )}
        {state.nextAction ? (
          <p className="agent-muted"><strong>What to do next:</strong> {state.nextAction}</p>
        ) : null}
        <details className="agent-disclosure">
          <summary>What does connecting do?</summary>
          <p className="agent-muted">
            Connecting opens the encrypted link on your private Wi-Fi and loads
            the latest status. It moves no money, signs nothing and changes
            nothing on the desktop.
          </p>
          {boundaryNote}
          {walletLine}
        </details>
      </section>
    );
  }

  // Connected and healthy: one line at rest. Everything the expanded card used
  // to show, including both controls, is one tap inside.
  return (
    <section className="agent-panel agent-session-bar" aria-label="Desktop connection">
      {/* Open by itself while the wallet figures are missing: the four
          read-only tabs name Refresh the status now for exactly that state, and
          it lives in here. A named control folded away by default is the same
          defect as one that is not on the screen. */}
      <details className="agent-disclosure" open={!hasTrustedSnapshot}>
        <summary>
          <span className="agent-status-text">{COMPANION_CONNECTION_SECTION_TITLE}</span>
          {devicePill}
        </summary>
        <h2>Connected to HPAY Desktop</h2>
        {walletLine}
        {boundaryNote}
        <div className="agent-control-row">
          {/* syncNow returns immediately while the heartbeat is in flight, so
              an enabled button there produced no spinner, no error and no
              change at all. */}
          <button type="button" disabled={syncBusy} onClick={onSync}>
            {COMPANION_REFRESH_ACTION}
          </button>
          <button type="button" disabled={busy} onClick={onDisconnect}>
            Close the connection
          </button>
        </div>
        <p className="agent-muted">
          Refreshing reloads the status from the desktop. Closing the connection
          only ends this link: this phone stays paired and can connect again
          with {COMPANION_CONNECT_ACTION}. Neither moves money.
        </p>
      </details>
    </section>
  );
}

function Unavailable({ title, body }: { title: string; body: string }) {
  return (
    <section className="agent-panel">
      <h2>{title}</h2>
      <p className="agent-muted">{body}</p>
    </section>
  );
}

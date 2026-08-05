import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  type MutableRefObject,
} from "react";
import {
  agentWalletApi,
  type EncryptedCompanionFrame,
  type MobileCompanionStatus,
  type MobileCompanionDevice,
  type MobilePairingConfirmation,
  type MobilePairingOffer,
} from "./api";
import {
  encodeConfirmation,
  encodeOffer,
  parseAck,
  parseRequest,
} from "./companionPairing";
import {
  companionPairingWaitingView,
  companionPhoneAppName,
} from "./companionWaitingView";
import {
  COMPANION_ACTION_GUIDE,
  COMPANION_PAIR_ACTION,
  COMPANION_REVOKED_GUIDANCE,
  COMPANION_REVOKE_ACTION,
  COMPANION_REVOKE_WARNING,
  COMPANION_START_LINK_ACTION,
  COMPANION_STOP_LINK_ACTION,
  companionActionErrorMessage,
  companionAttemptBudgetView,
  companionAuthorizedDeviceLabel,
  companionRevokedDeviceGuidance,
  companionRevokedDeviceLabel,
  companionStepErrorMessage,
  type CompanionPairingStep,
  type CompanionRevokedGuidance,
  type CompanionStepFailure,
} from "./companionPairingFeedback";
import { DESKTOP_CONTROLS } from "./desktopControls";
import { CompanionQrDisplay, CompanionQrScanner } from "@hacash/wallet-ui";
import { pairingRefusalText, type AgentWalletWriteReadiness } from "./access";
import {
  PHONE_CONNECTION_REFUSED_WHILE_STOPPED,
  PHONE_LISTENER_FAILED_ROUTE,
  PHONE_LISTENER_RELEASED_INFO,
} from "./overviewLayout";

/**
 * What the Overview strip needs to know about the phone, in primitives only.
 *
 * Functions are deliberately absent: they change identity on every render, and
 * putting them in parent state turns a status report into a render loop. The
 * two actions the strip can trigger are handed over through `actionsRef`.
 */
export type CompanionSnapshot = {
  statusLoaded: boolean;
  belongsToAnotherWallet: boolean;
  enabled: boolean;
  /**
   * The listener slot is held but its server is no longer running.
   * `agent_wallet_companion_status` reports `"enabled": true` for this phase,
   * so it has to be carried separately or Overview reads a dead listener as a
   * healthy one.
   */
  listenerFailed: boolean;
  /** A pairing offer is live, so the pairing owns the private-LAN port. */
  pairingActive: boolean;
  hasAuthorizedPhone: boolean;
  /** This desktop knows its private Wi-Fi address. */
  addressReady: boolean;
  canTurnOn: boolean;
  /** The panel is offering "Turn off the phone connection" right now. */
  canTurnOff: boolean;
  canStartPairing: boolean;
  /** The panel is offering "Try automatic setup again" right now. */
  canRetryAutomaticSetup: boolean;
};

export const EMPTY_COMPANION_SNAPSHOT: CompanionSnapshot = {
  statusLoaded: false,
  belongsToAnotherWallet: false,
  enabled: false,
  listenerFailed: false,
  pairingActive: false,
  hasAuthorizedPhone: false,
  addressReady: false,
  canTurnOn: false,
  canTurnOff: false,
  canStartPairing: false,
  canRetryAutomaticSetup: false,
};

/**
 * The exact same calls the panel's own buttons make, so the one-line strip at
 * the top of Overview can press them without a second implementation.
 */
export type CompanionActions = {
  turnOn: (() => void) | null;
  /**
   * Releases the listener slot. It is the only control that can succeed while
   * the slot is held and its server is dead, so the strip presses this one.
   */
  turnOff: (() => void) | null;
  startPairing: (() => void) | null;
  /**
   * Without a private Wi-Fi address neither phone control can run, so this is
   * the control that state depends on. It was reachable only by scrolling into
   * this panel; the strip presses the same handler.
   */
  retryAutomaticSetup: (() => void) | null;
};

type Props = {
  walletId: string;
  busy: boolean;
  run: (work: () => Promise<void>) => Promise<void>;
  onInfo: (message: string) => void;
  /**
   * What genuinely stops a phone from being paired. This is a UI mirror of the
   * refusals Rust already returns from `start_companion_pairing`; it adds no
   * new refusal. Payment prerequisites are deliberately absent: pairing spends
   * nothing, contacts no node and needs no witness.
   */
  pairingBlockers: AgentWalletWriteReadiness[];
  /**
   * What stops the emergency stop being cleared from this desktop. The pairing
   * refusal names "Enable locally" as the escape route, and this is what says
   * whether that route is itself open.
   */
  localEnableBlockers: AgentWalletWriteReadiness[];
  /**
   * Bumped by the parent after anything that can tear the listener down
   * (the emergency stop) or after a manual Refresh. The panel's own refresh is
   * idempotent, so re-running it is a read and nothing else.
   */
  refreshToken?: number;
  /** Reports the phone state upward so the top strip can show one line. */
  onSnapshot?: (snapshot: CompanionSnapshot) => void;
  /** Filled with this panel's own handlers. Never called during render. */
  actionsRef?: MutableRefObject<CompanionActions>;
  /** Locks this Agent Wallet and returns to the picker on the unlock screen. */
  onLockAndSwitch?: () => void;
};

export default function MobileCompanionPanel({
  walletId,
  busy,
  run,
  onInfo,
  pairingBlockers,
  localEnableBlockers,
  refreshToken = 0,
  onSnapshot,
  actionsRef,
  onLockAndSwitch,
}: Props) {
  const [status, setStatus] = useState<MobileCompanionStatus | null>(null);
  const [statusLoaded, setStatusLoaded] = useState(false);
  const [otherWallet, setOtherWallet] = useState(false);
  const [endpoint, setEndpoint] = useState("");
  const [offer, setOffer] = useState<MobilePairingOffer | null>(null);
  const [confirmation, setConfirmation] =
    useState<MobilePairingConfirmation | null>(null);
  const [ack, setAck] = useState<EncryptedCompanionFrame | null>(null);
  const [ackReceived, setAckReceived] = useState(false);
  const [typedCode, setTypedCode] = useState("");
  const [localError, setLocalError] = useState("");
  const [stepFailure, setStepFailure] = useState<CompanionStepFailure>(null);
  const [attemptBudget, setAttemptBudget] = useState<{
    attemptsUsed: number;
    attemptsRemaining: number;
    maxAttempts: number;
  } | null>(null);
  const [devices, setDevices] = useState<MobileCompanionDevice[]>([]);
  const [revokeConfirmId, setRevokeConfirmId] = useState<string | null>(null);
  const [nowUnix, setNowUnix] = useState(() => Math.floor(Date.now() / 1000));
  const refreshGeneration = useRef(0);

  /**
   * Runs one pairing action and keeps its failure attached to the button that
   * caused it.
   *
   * `run` reports into the alert at the top of <main>, which sits above the
   * connector and metrics panels and is off screen from here, so a refused
   * click looked like a dead button. The reason is re-thrown so that top-level
   * alert still fires; this only adds a copy the owner can actually see.
   */
  const runPairingStep = useCallback(
    (step: CompanionPairingStep, work: () => Promise<void>) =>
      run(async () => {
        setStepFailure(null);
        try {
          await work();
        } catch (reason) {
          setStepFailure({
            step,
            message: companionActionErrorMessage(reason),
          });
          throw reason;
        }
      }),
    [run],
  );

  const refresh = useCallback(async () => {
    const generation = ++refreshGeneration.current;
    const [nextStatus, pairingStatus, nextDevices] = await Promise.all([
      agentWalletApi.companionStatus(),
      agentWalletApi.companionPairingStatus(walletId),
      agentWalletApi.companionDevices(walletId),
    ]);
    if (generation !== refreshGeneration.current) return;
    if (nextStatus.walletId && nextStatus.walletId !== walletId) {
      setStatus(null);
      setOtherWallet(true);
      setLocalError("The active mobile listener belongs to another Agent Wallet.");
    } else {
      setStatus(nextStatus);
      setOtherWallet(false);
    }
    setStatusLoaded(true);
    setDevices(nextDevices);
    setOffer(pairingStatus?.offer ?? null);
    setConfirmation(pairingStatus?.confirmation ?? null);
    setAckReceived(pairingStatus?.ackReceived ?? false);
    setAttemptBudget(
      pairingStatus
        ? {
            attemptsUsed: pairingStatus.attemptsUsed,
            attemptsRemaining: pairingStatus.attemptsRemaining,
            maxAttempts: pairingStatus.maxAttempts,
          }
        : null,
    );
    if (pairingStatus?.ackReceived) {
      setAck(null);
    }
    if (!pairingStatus) {
      setAck(null);
      setTypedCode("");
    }
  }, [walletId]);

  useEffect(() => {
    void refresh().catch((reason) => {
      // A failed read is not an answer. Setting statusLoaded and leaving the
      // device list empty asserted "no phone is authorized yet" from a read
      // that never happened, and Overview then offered Pair a phone as its
      // primary action - which ends at PairingDeviceAlreadyRegistered for an
      // owner whose phone was paired all along. The state stays unknown and
      // the failure is named.
      setStatus(null);
      setLocalError(
        `This desktop could not read the phone connection status, so nothing below is known to be current. Nothing was changed and no phone was unpaired. Choose ${DESKTOP_CONTROLS.refresh} at the top of this page to read it again. ${readableError(reason)}`,
      );
    });
  }, [refresh, refreshToken]);

  useEffect(() => {
    if (!offer) return undefined;
    const expiresAt = Number(offer.expires_at);
    if (!Number.isSafeInteger(expiresAt)) return undefined;

    const tick = () => {
      setNowUnix(Math.floor(Date.now() / 1_000));
      void refresh().catch((reason) => setLocalError(readableError(reason)));
    };
    tick();
    const ticker = window.setInterval(tick, 750);
    const timeout = window.setTimeout(
      () => void refresh().catch((reason) => setLocalError(readableError(reason))),
      Math.max(0, expiresAt * 1_000 - Date.now()) + 250,
    );
    return () => {
      window.clearInterval(ticker);
      window.clearTimeout(timeout);
    };
  }, [offer, refresh]);

  useEffect(() => {
    if (endpoint) return;
    void agentWalletApi
      .suggestCompanionEndpoint()
      .then(setEndpoint)
      .catch((reason) => setLocalError(readableError(reason)));
  }, [endpoint]);

  const bindAddress = useMemo(
    () => endpoint.trim().replace(/^hpay-lan:\/\//, ""),
    [endpoint],
  );
  const pairingSecondsRemaining = offer
    ? Math.max(0, Number(offer.expires_at) - nowUnix)
    : null;
  const pairingExpired = pairingSecondsRemaining === 0;
  const hasAuthorizedDevice = devices.some((device) => !device.revoked_at);
  // "failed" means the slot is still held and the server behind it is not
  // running. The backend reports enabled:true for it exactly as it does for a
  // healthy listener, so reading enabled alone told the owner the connection
  // was on while every phone was being refused.
  const listenerFailed = status?.phase === "failed";
  const linkOn = Boolean(status?.enabled) && !listenerFailed;
  const paymentsSuspended = pairingBlockers.includes("payments_suspended");
  // Explaining the refusal before the click is the whole point. Rust already
  // rejects pairing while the emergency stop is engaged; saying so here turns a
  // thrown error into an instruction that names the escape route, and says so
  // when that escape route is itself closed.
  const pairingRefusal = pairingRefusalText(pairingBlockers, localEnableBlockers);
  const pairingIsBlocked = pairingBlockers.length > 0;
  // Presentation only. While the phone's acknowledgement is outstanding the
  // finish step cannot render, so without this the owner stares at a six digit
  // code with no next step and assumes the desktop is broken.
  const waiting = companionPairingWaitingView({
    hasOffer: Boolean(offer),
    hasConfirmation: Boolean(confirmation),
    ackReceived,
    hasScannedAck: Boolean(ack),
    secondsRemaining: pairingSecondsRemaining,
  });
  // The retry budget the desktop already tracks. Showing it is the difference
  // between "Attempt 2 of 5" and a sixth press that kills the pairing silently.
  const attempts = companionAttemptBudgetView(attemptBudget);

  /** The failure of the step that owns this button, or "" for every other. */
  function stepError(step: CompanionPairingStep): string {
    return companionStepErrorMessage(stepFailure, step);
  }

  function clearPairing() {
    refreshGeneration.current += 1;
    setOffer(null);
    setConfirmation(null);
    setAck(null);
    setAckReceived(false);
    setTypedCode("");
    setLocalError("");
    setStepFailure(null);
    setAttemptBudget(null);
  }

  async function cancelPairing() {
    await agentWalletApi.cancelCompanionPairing(walletId);
    clearPairing();
    onInfo("Mobile companion pairing was cancelled.");
  }

  // Written as the refusal, not the permission, so the exact condition the
  // previous control used is preserved verbatim. `listenerFailed` is added
  // because CompanionSupervisor::start refuses outright while a dead slot is
  // still held ("stop the active mobile companion before starting another"), so
  // in that one state the control could not succeed.
  const turnOnUnavailable =
    busy ||
    !bindAddress ||
    !hasAuthorizedDevice ||
    Boolean(offer) ||
    listenerFailed;
  const canTurnOn = !turnOnUnavailable;
  // Written as the condition the button is rendered and enabled under, so the
  // strip can never offer a press this panel is not offering.
  const canTurnOff = !busy && !Boolean(offer) && (linkOn || listenerFailed);
  const startPairingUnavailable =
    busy || !endpoint.trim() || pairingBlockers.length > 0 || Boolean(offer);
  const canStartPairing = !startPairingUnavailable;
  // The exact condition the panel's own button is rendered and enabled under,
  // written once so the strip can never offer a control this panel is not.
  //
  // It used to read `!endpoint`, while every sentence that named it and the
  // Overview row that pressed it were derived from `bindAddress`, which is the
  // endpoint with "hpay-lan://" stripped. An endpoint holding only the scheme,
  // or a half-edited address, produced a state that told the owner twice to
  // choose a button that neither surface rendered.
  const canRetryAutomaticSetup = !busy && !bindAddress && !offer;

  const turnOffConnection = useCallback(() => {
    void run(async () => {
      await agentWalletApi.stopCompanion(walletId);
      await refresh();
      onInfo(
        listenerFailed
          ? PHONE_LISTENER_RELEASED_INFO
          : "The phone connection is off. Every paired phone stays paired and can connect again once you turn it back on.",
      );
    });
  }, [run, walletId, refresh, onInfo, listenerFailed]);

  const turnOnConnection = useCallback(() => {
    void runPairingStep("reconnect", async () => {
      await agentWalletApi.startCompanion(walletId, bindAddress);
      await refresh();
      onInfo(
        paymentsSuspended
          ? `The phone connection is open on your private Wi-Fi. ${PHONE_CONNECTION_REFUSED_WHILE_STOPPED}`
          : "The phone connection is on. A paired phone can now reach this desktop on your private Wi-Fi.",
      );
    });
  }, [runPairingStep, walletId, bindAddress, refresh, onInfo, paymentsSuspended]);

  const startPairing = useCallback(() => {
    void runPairingStep("start", async () => {
      setLocalError("");
      const next = await agentWalletApi.startCompanionPairing(
        walletId,
        endpoint.trim(),
      );
      setOffer(next);
      // "HPAY Agent Wallet" was the name of nothing. The phone app is
      // companionPhoneAppName, and companionWaiting.test.ts pins that against
      // the phone sources.
      onInfo(`Open ${companionPhoneAppName} on the phone and scan this QR once.`);
    });
  }, [runPairingStep, walletId, endpoint, onInfo]);

  // Exactly what the panel's own button does, lifted so the strip presses the
  // same call rather than a second implementation of it.
  const retryAutomaticSetup = useCallback(() => {
    void agentWalletApi
      .suggestCompanionEndpoint()
      .then((value) => {
        setEndpoint(value);
        setLocalError("");
      })
      .catch((reason) => setLocalError(readableError(reason)));
  }, []);

  // Assigned, never read, during render. No state changes here, so this cannot
  // feed back into the parent and re-render it.
  useEffect(() => {
    if (!actionsRef) return;
    actionsRef.current = {
      turnOn: canTurnOn ? turnOnConnection : null,
      turnOff: canTurnOff ? turnOffConnection : null,
      startPairing: canStartPairing ? startPairing : null,
      retryAutomaticSetup: canRetryAutomaticSetup ? retryAutomaticSetup : null,
    };
  });

  useEffect(() => {
    onSnapshot?.({
      statusLoaded,
      belongsToAnotherWallet: otherWallet,
      enabled: linkOn,
      listenerFailed,
      pairingActive: Boolean(offer),
      hasAuthorizedPhone: hasAuthorizedDevice,
      addressReady: Boolean(bindAddress),
      canTurnOn,
      canTurnOff,
      canStartPairing,
      canRetryAutomaticSetup,
    });
  }, [
    onSnapshot,
    statusLoaded,
    otherWallet,
    linkOn,
    listenerFailed,
    offer,
    hasAuthorizedDevice,
    bindAddress,
    canTurnOn,
    canTurnOff,
    canStartPairing,
    canRetryAutomaticSetup,
  ]);

  return (
    <section className="agent-panel agent-mobile-companion">
      <div className="agent-record-head">
        <div>
          <span className="agent-eyebrow">Phone connection</span>
          <h2>Pair your phone</h2>
          <p>Read-only safety companion. It can never spend.</p>
        </div>
        <span className={`agent-status ${status?.phase === "listening" ? "ok" : "stopped"}`}>
          {status ? companionPhaseLabel(status.phase) : "Status unavailable"}
        </span>
      </div>

      {localError && (
        <div className="alert" role="alert">
          <span>{localError}</span>
          {/* An instruction with no control is what this used to be: the panel
              named another Agent Wallet and offered nothing at all. Locking
              returns to the unlock screen, which does have a wallet picker. */}
          {otherWallet && onLockAndSwitch && (
            <button type="button" disabled={busy} onClick={onLockAndSwitch}>
              {DESKTOP_CONTROLS.lock_and_switch_wallet}
            </button>
          )}
        </div>
      )}

      {/* The action first. Everything that explains it is below it or behind a
          disclosure: this is the control the whole phone connection depends on
          and it used to sit 2.8 screens below the fold. */}
      <div className="agent-companion-primary">
        {linkOn || listenerFailed ? (
          <div className="agent-control-row">
            <code>{status?.localAddress}</code>
            <button
              type="button"
              className={listenerFailed ? "agent-primary-action" : ""}
              disabled={!canTurnOff}
              onClick={turnOffConnection}
            >
              {COMPANION_STOP_LINK_ACTION}
            </button>
          </div>
        ) : null}

        {/* The listener slot is still held and its server is not running, so
            every phone is refused and starting it again is refused too. Only
            the control that can succeed is offered, and the sentence names the
            two presses in the order that works. */}
        {listenerFailed && !offer && (
          <p className="agent-warning" role="status">
            {PHONE_LISTENER_FAILED_ROUTE}
          </p>
        )}

        {/* Turning the connection on is hidden, not disabled, when there is
            nothing for it to connect to: with no authorized phone the desktop
            refuses it outright. The sentence that replaces it names the control
            that does work. */}
        {!linkOn && !listenerFailed && !offer && hasAuthorizedDevice && (
          <>
            <div className="agent-control-row">
              <span className="agent-muted">
                A phone is paired but cannot reach this desktop.
              </span>
              <button
                type="button"
                className="agent-primary-action"
                disabled={!canTurnOn}
                title={
                  bindAddress
                    ? ""
                    : "Waiting for your private Wi-Fi address. Open Advanced connection settings if automatic detection did not fill it in."
                }
                onClick={turnOnConnection}
              >
                {COMPANION_START_LINK_ACTION}
              </button>
            </div>
            {!bindAddress && (
              <p className="agent-warning" role="status">
                {COMPANION_START_LINK_ACTION} is unavailable because this desktop
                has no private Wi-Fi address yet. Choose{" "}
                {DESKTOP_CONTROLS.retry_automatic_setup} just below, or open
                Advanced connection settings and enter it.
              </p>
            )}
            {/* Said before the press, not after it: the listener really does
                start, and every session a phone then opens is still refused. */}
            {bindAddress && paymentsSuspended && (
              <p className="agent-warning" role="status">
                {PHONE_CONNECTION_REFUSED_WHILE_STOPPED}
              </p>
            )}
            {stepError("reconnect") && (
              <PairingFailure message={stepError("reconnect")} />
            )}
          </>
        )}

        {!linkOn && !listenerFailed && !offer && statusLoaded && !hasAuthorizedDevice && (
          <p className="agent-muted" role="status">
            {COMPANION_START_LINK_ACTION} is not shown because no phone is
            authorized on this Agent Wallet yet. There is nothing for it to
            connect to. Use {COMPANION_PAIR_ACTION} below first.
          </p>
        )}

        {offer && (
          <p className="agent-muted" role="status">
            Pairing is using the private Wi-Fi connection right now, so it cannot
            be turned on or off until pairing finishes or is cancelled.
          </p>
        )}

        {!offer && pairingRefusal && (
          <p className="agent-warning" role="status">{pairingRefusal}</p>
        )}

        {!offer && (
          <div className="agent-control-row">
            <span className="agent-muted">
              {hasAuthorizedDevice
                ? "Adding another phone, or setting one up again from the start."
                : "First time setup for a phone. Costs nothing, moves no money."}
            </span>
            <button
              type="button"
              className={hasAuthorizedDevice ? "" : "agent-primary-action"}
              disabled={!canStartPairing}
              title={
                pairingRefusal ||
                (endpoint.trim()
                  ? ""
                  : "Waiting for your private Wi-Fi address. Open Advanced connection settings if automatic detection did not fill it in.")
              }
              onClick={startPairing}
            >
              {COMPANION_PAIR_ACTION}
            </button>
          </div>
        )}
        {/* Verified against the Rust pairing path before this sentence was
            written: `AgentCompanionSupervisor::start_pairing` suspends the
            session listener, hands the private-LAN port to the pairing
            transport, and gives it back when the pairing completes or is
            cancelled. Pairing while the connection is on is supported and
            needs no button pressed first. */}
        {!offer && linkOn && (
          <p className="agent-muted">
            Pairing takes over the phone connection while it runs and turns it
            back on when it finishes. Paired phones stay paired. If the
            connection is still off afterwards, use {COMPANION_START_LINK_ACTION}.
          </p>
        )}
        {/* A disabled button that never says why reads as broken. */}
        {!offer && !endpoint.trim() && !pairingIsBlocked && (
          <p className="agent-warning" role="status">
            {COMPANION_PAIR_ACTION} is unavailable because this desktop has no
            private Wi-Fi address yet. Choose{" "}
            {DESKTOP_CONTROLS.retry_automatic_setup} just below, or open
            Advanced connection settings and enter it.
          </p>
        )}
        {!offer && stepError("start") && (
          <PairingFailure message={stepError("start")} />
        )}

        {/* Rendered from `bindAddress`, the same fact every sentence that names
            this button and the Overview row that presses it are derived from.
            It used to render from `endpoint`, so an endpoint holding only
            "hpay-lan://" left two sentences pointing at a button that was not
            on the screen. It is a read: it asks this desktop for its own
            private Wi-Fi address and costs nothing. */}
        {!bindAddress && !offer ? (
          <button type="button" disabled={busy} onClick={retryAutomaticSetup}>
            {DESKTOP_CONTROLS.retry_automatic_setup}
          </button>
        ) : null}

        {offer && pairingSecondsRemaining !== null && (
          <p className="agent-muted" role="status">
            {pairingExpired
              ? "This pairing offer expired and is being cancelled."
              : `Pairing expires in ${formatPairingRemaining(
                  pairingSecondsRemaining,
                )}. Expired offers are cancelled automatically.`}
          </p>
        )}

        {offer && attempts && (
          <p
            className={attempts.lastTry || attempts.exhausted ? "alert" : "agent-muted"}
            role="status"
          >
            <strong>{attempts.label}</strong> {attempts.detail}
          </p>
        )}

        {offer && !confirmation && (
          <div className="agent-companion-step">
            <h3>1. Scan this QR with your phone</h3>
            {/* The phone's scan control is rendered from
                COMPANION_SCAN_QR_ACTION in apps/mobile/src/agent/companionStatus.ts
                and reads "Scan desktop QR". This said "Scan QR", which is not a
                label that appears anywhere on the phone. */}
            <p>Open AI Agent Wallet on the phone, tap Scan desktop QR and approve the Android fingerprint prompt.</p>
            <CompanionQrDisplay
              value={encodeOffer(offer)}
              label="One-time HPAY phone pairing"
              showTransferActions={false}
            />
            <p className="agent-safe-note" role="status">
              Waiting for the phone. Keep both devices on the same Wi-Fi.
            </p>
            <details className="agent-advanced-details">
              <summary>Manual fallback</summary>
              <p>Use this only when the two devices cannot communicate on the same Wi-Fi.</p>
              <CompanionQrScanner
                label="Scan mobile request"
                disabled={busy || pairingExpired}
                onValue={(raw) =>
                  void runPairingStep("request", async () => {
                    setLocalError("");
                    const request = parseRequest(raw, walletId, offer.pairing_id);
                    setConfirmation(
                      await agentWalletApi.acceptCompanionPairingRequest(walletId, request),
                    );
                  })
                }
              />
            </details>
            {/* Outside the collapsible fallback on purpose: a refused scan
                must stay readable even if the owner closes it. */}
            {stepError("request") && (
              <PairingFailure message={stepError("request")} />
            )}
          </div>
        )}

        {offer && confirmation && !ack && !ackReceived && (
          <div className="agent-companion-step">
            <h3>2. Check the code on both devices</h3>
            <strong className="agent-verification-code">
              {confirmation.verification_code}
            </strong>
            <p>
              Stop if the phone shows a different code. HPAY will not complete
              pairing without the same human-confirmed code.
            </p>
            <p className="agent-safe-note" role="status">
              Approve the matching code with your fingerprint on the phone.
            </p>
            <details className="agent-advanced-details">
              <summary>Manual fallback</summary>
              <CompanionQrDisplay
                value={encodeConfirmation(confirmation)}
                label="Signed desktop pairing confirmation"
              />
              <CompanionQrScanner
                label="Scan encrypted acknowledgement"
                disabled={busy || pairingExpired}
                onValue={(raw) => {
                  try {
                    setLocalError("");
                    setAck(
                      parseAck(
                        raw,
                        confirmation.session_id,
                        confirmation.mobile_device_id,
                        confirmation.desktop_device_id,
                      ),
                    );
                  } catch (reason) {
                    setStepFailure({
                      step: "acknowledgement",
                      message: companionActionErrorMessage(reason),
                    });
                    setLocalError(readableError(reason));
                  }
                }}
              />
            </details>
            {stepError("acknowledgement") && (
              <PairingFailure message={stepError("acknowledgement")} />
            )}
          </div>
        )}

        {waiting && (
          <div className="agent-companion-step" role="status">
            <h3>3. {waiting.heading}</h3>
            <p>{waiting.phoneInstruction}</p>
            {waiting.expired ? (
              <p className="alert" role="alert">{waiting.validity}</p>
            ) : (
              /* aria-live off: this line ticks every second and must not be
                 announced on every tick. */
              <p className="agent-safe-note" aria-live="off">
                {waiting.validity}
              </p>
            )}
            <p>{waiting.humanCheck}</p>
            <p className="agent-muted">{waiting.restart}</p>
            {waiting.restartAction && (
              <button
                type="button"
                className="agent-primary-action"
                disabled={busy}
                onClick={() => void runPairingStep("cancel", cancelPairing)}
              >
                {waiting.restartAction}
              </button>
            )}
            {stepError("cancel") && (
              <PairingFailure message={stepError("cancel")} />
            )}
          </div>
        )}

        {offer && confirmation && ackReceived && !ack && (
          <div className="agent-companion-step">
            <h3>3. Finish on this desktop</h3>
            <strong className="agent-verification-code">
              {confirmation.verification_code}
            </strong>
            <p>Finish only if the phone shows the same six digits.</p>
            <button
              type="button"
              className="agent-primary-action"
              disabled={busy || pairingExpired}
              onClick={() =>
                void runPairingStep("finish", async () => {
                  await agentWalletApi.completeAutomaticCompanionPairing(
                    walletId,
                    confirmation.verification_code,
                  );
                  await agentWalletApi.startCompanion(walletId, bindAddress);
                  clearPairing();
                  await refresh();
                  onInfo("Phone paired successfully. The encrypted connection is ready.");
                })
              }
            >
              Yes, the codes match
            </button>
            {/* The reason belongs under the button that produced it. The
                page-level alert is above the connector and metrics panels
                and is off screen from here, which is what made a refused
                finish look like a dead button. */}
            {stepError("finish") && (
              <PairingFailure message={stepError("finish")} />
            )}
          </div>
        )}

        {offer && confirmation && ack && (
          <div className="agent-companion-step">
            {/* This is step 3 of the manual fallback path, which goes 1, 2,
                then here. It was numbered 5 because the automatic path has two
                steps of its own that the fallback never renders, so an owner on
                this path went looking for two steps that do not exist. */}
            <h3>3. Confirm locally on this desktop</h3>
            <label className="agent-field">
              Enter the code shown above
              <input
                value={typedCode}
                inputMode="numeric"
                autoComplete="off"
                onChange={(event) => setTypedCode(event.target.value.trim())}
                disabled={busy || pairingExpired}
              />
            </label>
            <button
              type="button"
              className="agent-primary-action"
              disabled={
                busy ||
                pairingExpired ||
                typedCode !== confirmation.verification_code
              }
              onClick={() =>
                void runPairingStep("confirm", async () => {
                  await agentWalletApi.completeCompanionPairing(
                    walletId,
                    ack,
                    typedCode,
                  );
                  clearPairing();
                  await refresh();
                  onInfo(
                    "The mobile device is authorized for read-only companion sync.",
                  );
                })
              }
            >
              Complete read-only pairing
            </button>
            {stepError("confirm") && (
              <PairingFailure message={stepError("confirm")} />
            )}
          </div>
        )}

        {/* The waiting card renders the same control, with the same handler and
            the same label, as its own primary once the offer has expired. Two
            identical buttons would be the same press twice. */}
        {offer && !waiting?.restartAction && (
          <>
            <button
              type="button"
              disabled={busy}
              onClick={() => void runPairingStep("cancel", cancelPairing)}
            >
              {DESKTOP_CONTROLS.cancel_phone_pairing}
            </button>
            {stepError("cancel") && (
              <PairingFailure message={stepError("cancel")} />
            )}
          </>
        )}
      </div>

      <div className="agent-companion-devices">
        <h3>Authorized mobile devices</h3>
        {devices.length === 0 ? (
          // Only claimed once the list has actually been read. An unread list
          // is not an empty list, and asserting "no phone is authorized yet"
          // from a failed read is what sent an owner whose phone was already
          // paired into a pairing that ends at "already authorized".
          statusLoaded ? (
            <p className="agent-muted">
              No phone is authorized yet. A phone that shows One last step or
              Complete pairing on HPAY Desktop is not authorized here and every
              connection it attempts will be refused until{" "}
              {COMPANION_PAIR_ACTION} is finished on this desktop.
            </p>
          ) : (
            <p className="agent-muted" role="status">
              The list of authorized phones has not been read yet, so this is
              not a statement that no phone is paired. Choose{" "}
              {DESKTOP_CONTROLS.refresh} at the top of this page to read it.
            </p>
          )
        ) : (
          devices.map((device) => (
            <div className="agent-companion-device" key={device.device_id}>
              <div className="agent-companion-device-identity">
                <strong>{shortFingerprint(device.identity_fingerprint)}</strong>
                <p className="agent-muted">
                  {device.revoked_at
                    ? companionRevokedDeviceLabel(formatUnix(device.revoked_at))
                    : companionAuthorizedDeviceLabel(
                        formatUnix(device.paired_at),
                        status?.phase === "listening",
                      )}
                </p>
                {/* A revoked row used to be a date and nothing else: no
                    statement that it is permanent, no next step, and the
                    action button hidden. That is a dead end that does not
                    admit it is one. Revocation itself is unchanged. */}
                {device.revoked_at && <RevokedDeviceExplanation />}
              </div>
              {!device.revoked_at && (
                <div className="agent-companion-device-action">
                  {/* Said before the first press, not only after it. */}
                  {revokeConfirmId !== device.device_id && (
                    <p className="agent-muted">
                      Permanent. Use only for a lost, sold or compromised phone.
                    </p>
                  )}
                  {revokeConfirmId === device.device_id && (
                    <p className="alert" role="alert">
                      {COMPANION_REVOKE_WARNING}
                    </p>
                  )}
                  <button
                    type="button"
                    className={revokeConfirmId === device.device_id ? "agent-danger" : ""}
                    disabled={busy}
                    onClick={() => {
                      if (revokeConfirmId !== device.device_id) {
                        setRevokeConfirmId(device.device_id);
                        return;
                      }
                      void run(async () => {
                        await agentWalletApi.revokeCompanionDevice(
                          walletId,
                          device.device_id,
                        );
                        setRevokeConfirmId(null);
                        await refresh();
                        onInfo("The mobile companion was revoked and active sessions were closed.");
                      });
                    }}
                  >
                    {/* "Revoke device" was the shortest label on the panel and
                        the only irreversible one. The first press now says so
                        before anything happens. */}
                    {revokeConfirmId === device.device_id
                      ? "Yes, revoke permanently"
                      : COMPANION_REVOKE_ACTION}
                  </button>
                </div>
              )}
            </div>
          ))
        )}
        {/* The stuck state, named. An owner whose only phone was revoked sees
            a list, a Pair a phone button that will refuse at the last click,
            and no explanation anywhere. */}
        {devices.length > 0 && !hasAuthorizedDevice && (
          <p className="agent-warning" role="status">
            Every phone on this Agent Wallet is revoked, so no phone can connect.
            A revoked phone can never be paired again while it presents the same
            identity. Open "Why this phone cannot be paired again" for the
            two ways to get a phone working again.
          </p>
        )}
      </div>

      {/* Five controls used to sit side by side with nothing to say which one
          an owner needed, and the permanent one was the shortest label on the
          screen. This is copy only: no control is added, removed or gated. */}
      <details className="agent-advanced-details">
        <summary>Which button do I need?</summary>
        <dl className="agent-detail-list">
          {COMPANION_ACTION_GUIDE.map((entry) => (
            <div key={entry.action}>
              <dt>{entry.action}</dt>
              <dd>
                {entry.when} {entry.cost}
              </dd>
            </div>
          ))}
        </dl>
        <p>
          Your phone can safely view Agent Wallet status. The encrypted
          connection works only on your private Wi-Fi. Keep both devices on the
          same network while pairing. The phone never receives the Agent Wallet
          or Personal Wallet private key, and it cannot send Hacash
          transactions.
        </p>
      </details>

      <details className="agent-advanced-details">
        <summary>Advanced connection settings</summary>
        <label className="agent-field">
          Private Wi-Fi address
          <input
            value={endpoint}
            disabled={busy || Boolean(offer)}
            spellCheck={false}
            placeholder="hpay-lan://192.168.1.20:42492"
            onChange={(event) => setEndpoint(event.target.value)}
          />
          <small>
            HPAY fills this automatically. Change it only if automatic
            detection fails.
          </small>
        </label>
        {/* Once an address had been detected once, the retry above stopped
            rendering for good, so an owner whose private Wi-Fi address changed
            had no way to detect the new one. Same handler, same read, always
            reachable. */}
        <p className="agent-muted">
          Moved to a different Wi-Fi network? This asks the desktop for its
          current private address and overwrites the field above. It costs
          nothing, moves no money and unpairs no phone.
        </p>
        <button
          type="button"
          disabled={busy || Boolean(offer)}
          onClick={retryAutomaticSetup}
        >
          {DESKTOP_CONTROLS.retry_automatic_setup}
        </button>
      </details>
    </section>
  );
}

/**
 * One refused pairing step, rendered beside the button that produced it.
 *
 * When the refusal is "this phone is revoked" the raw sentence is not enough:
 * the owner also needs to know that it is permanent and what the two real
 * routes back are. This adds copy only; it changes no refusal.
 */
function PairingFailure({ message }: { message: string }) {
  const guidance = companionRevokedDeviceGuidance(message);
  return (
    <div className="alert" role="alert">
      <p>{message}</p>
      {guidance && <RevokedDeviceGuidance guidance={guidance} />}
    </div>
  );
}

/** Why a revoked row is a dead end, and how to get a phone working again. */
function RevokedDeviceExplanation() {
  return (
    <details className="agent-advanced-details agent-companion-revoked-note">
      <summary>Why this phone cannot be paired again</summary>
      <RevokedDeviceGuidance guidance={COMPANION_REVOKED_GUIDANCE} />
    </details>
  );
}

function RevokedDeviceGuidance({
  guidance,
}: {
  guidance: CompanionRevokedGuidance;
}) {
  return (
    <>
      <p>{guidance.permanence}</p>
      <p>{guidance.ineffective}</p>
      <ul>
        {guidance.options.map((option) => (
          <li key={option}>{option}</li>
        ))}
      </ul>
    </>
  );
}

/**
 * What this badge reports is whether THIS DESKTOP is accepting phone
 * connections. It is not a statement about any phone.
 *
 * "Phone ready" read as "your phone is connected", which it never meant, so an
 * owner with a refused phone saw a green badge and looked everywhere else.
 */
function companionPhaseLabel(phase: MobileCompanionStatus["phase"]): string {
  if (phase === "listening") return "Phone connection is on";
  if (phase === "stopping") return "Phone connection is stopping";
  if (phase === "failed") return "Phone connection failed to start";
  return "Phone connection is off";
}
function shortFingerprint(value: string): string {
  return value.length > 18
    ? `${value.slice(0, 10)}...${value.slice(-6)}`
    : value;
}

function formatPairingRemaining(seconds: number): string {
  const minutes = Math.floor(seconds / 60);
  const remainder = String(seconds % 60).padStart(2, "0");
  return `${minutes}:${remainder}`;
}

function formatUnix(raw: string): string {
  if (!/^(0|[1-9]\d{0,15})$/.test(raw)) return "unknown time";
  const seconds = Number(raw);
  if (!Number.isSafeInteger(seconds) || seconds > Number.MAX_SAFE_INTEGER / 1_000) {
    return "unknown time";
  }
  const date = new Date(seconds * 1_000);
  return Number.isNaN(date.getTime()) ? "unknown time" : date.toLocaleString();
}
function readableError(reason: unknown): string {
  return reason instanceof Error
    ? reason.message
    : typeof reason === "string"
      ? reason
      : "Mobile companion operation failed.";
}

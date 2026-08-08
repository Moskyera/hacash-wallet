import { useCallback, useEffect, useRef, useState } from "react";
import { agentCompanionApi } from "./api";
import { companionFailureText } from "./companionStatus";
import {
  authenticatedSnapshot,
  companionSessionExpiryMilliseconds,
  snapshotBlockedOnlyByExpiredApproval,
  validateCompanionStatusSnapshot,
  validatePong,
  validatedIdentityStatus,
  validatedSession,
  validatedStoredState,
} from "./companionView";
import type {
  AgentCompanionIdentityStatus,
  AgentCompanionSnapshot,
  CompanionSessionView,
  CompanionStoredStateView,
} from "./types";

const HEARTBEAT_INTERVAL_MS = 8_000;

export function useCompanionSession() {
  const [identity, setIdentity] = useState<AgentCompanionIdentityStatus | null>(null);
  const [stored, setStored] = useState<CompanionStoredStateView | null>(null);
  const [session, setSession] = useState<CompanionSessionView | null>(null);
  const [snapshot, setSnapshot] = useState<AgentCompanionSnapshot | null>(null);
  const [busy, setBusy] = useState("");
  const [error, setError] = useState("");
  const [connectFailed, setConnectFailed] = useState(false);
  /**
   * Mirrors `heartbeatInFlight` into render.
   *
   * `syncNow` opens with a bare `return` while the eight-second heartbeat is
   * running, and the ref never reached `busy`, so "Refresh the status now" was
   * fully enabled and tapping it did nothing at all: no spinner, no error, no
   * state change. That is the same shape as the acceptOffer defect, on the very
   * button the stale-request message tells the owner to tap.
   */
  const [syncInFlight, setSyncInFlight] = useState(false);
  const [snapshotClock, setSnapshotClock] = useState(() => Date.now());
  const storedRef = useRef<CompanionStoredStateView | null>(null);
  const connectInFlight = useRef(false);
  const heartbeatInFlight = useRef(false);
  const lifecycleCloseInFlight = useRef(false);
  const autoConnectAttempted = useRef(false);

  const trustedSnapshot = authenticatedSnapshot(
    snapshot,
    Math.max(snapshotClock, Date.now()),
  );
  /**
   * The trusted snapshot is null only because a payment request ran out of
   * time. Nothing is wrong with the connection and the next heartbeat clears
   * it, so the status must not report the state as "checking the data".
   */
  const approvalExpiredThisTick = snapshotBlockedOnlyByExpiredApproval(
    snapshot,
    Math.max(snapshotClock, Date.now()),
  );

  useEffect(() => {
    storedRef.current = stored;
  }, [stored]);

  const refreshIdentity = useCallback(async () => {
    const next = validatedIdentityStatus(await agentCompanionApi.identityStatus());
    setIdentity(next);
    return next;
  }, []);

  const refreshStoredState = useCallback(async () => {
    const next = validatedStoredState(await agentCompanionApi.state());
    storedRef.current = next;
    setStored(next);
    if (!next.configured) {
      setSession(null);
      setSnapshot(null);
    }
    return next;
  }, []);

  useEffect(() => {
    let cancelled = false;
    setBusy("bootstrap");
    setError("");
    void Promise.allSettled([
      agentCompanionApi.identityStatus(),
      agentCompanionApi.state(),
    ])
      .then(([identityResult, stateResult]) => {
        if (cancelled) return;
        // Validated and applied separately. They used to share one try: the
        // identity was validated first and the state second, inside the same
        // then, so a state that failed validation threw before setIdentity ran
        // and left identity null as well. Every control on the Security tab is
        // gated on identity.platformSupported, so one unreadable field in the
        // stored state removed the whole screen.
        const failures: unknown[] = [];
        if (identityResult.status === "fulfilled") {
          try {
            setIdentity(validatedIdentityStatus(identityResult.value));
          } catch (reason) {
            failures.push(reason);
          }
        } else {
          failures.push(identityResult.reason);
        }
        if (stateResult.status === "fulfilled") {
          try {
            const nextState = validatedStoredState(stateResult.value);
            storedRef.current = nextState;
            setStored(nextState);
          } catch (reason) {
            failures.push(reason);
          }
        } else {
          failures.push(stateResult.reason);
        }
        if (failures.length > 0) setError(readableError(failures[0]));
      })
      .catch((reason) => {
        if (!cancelled) setError(readableError(reason));
      })
      .finally(() => {
        if (!cancelled) setBusy("");
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const closeForLifecycle = useCallback(() => {
    setSession(null);
    setSnapshot(null);
    if (lifecycleCloseInFlight.current) return;
    lifecycleCloseInFlight.current = true;
    void agentCompanionApi
      .lifecycle("webview_closing")
      .catch(() => undefined)
      .finally(() => {
        lifecycleCloseInFlight.current = false;
      });
  }, []);

  useEffect(() => {
    const onVisibilityChange = () => {
      if (document.visibilityState === "hidden") closeForLifecycle();
    };
    const onPageHide = () => closeForLifecycle();
    document.addEventListener("visibilitychange", onVisibilityChange);
    window.addEventListener("pagehide", onPageHide);
    return () => {
      document.removeEventListener("visibilitychange", onVisibilityChange);
      window.removeEventListener("pagehide", onPageHide);
      // StrictMode replays cleanup; native close is intentionally not called here.
    };
  }, [closeForLifecycle]);

  useEffect(() => {
    if (!session) return;
    let cancelled = false;

    const heartbeat = async () => {
      if (
        cancelled ||
        heartbeatInFlight.current ||
        document.visibilityState === "hidden"
      ) {
        return;
      }
      heartbeatInFlight.current = true;
      setSyncInFlight(true);
      try {
        const lifecycle = await agentCompanionApi.lifecycle("foreground_heartbeat");
        if (lifecycle.sessionAllowedInBackground || !lifecycle.nativeDisconnectEnforced) {
          throw new Error("The native companion lifecycle policy is invalid.");
        }
        validatePong(await agentCompanionApi.ping(), session);
        const currentStored = storedRef.current;
        if (!currentStored) throw new Error("Companion pairing state is unavailable.");
        const nextSnapshot = validateCompanionStatusSnapshot(
          await agentCompanionApi.sync(),
          session,
          currentStored,
        );
        if (!cancelled) {
          setSnapshot(nextSnapshot);
          setSnapshotClock(Date.now());
          setError("");
        }
      } catch (reason) {
        if (!cancelled) {
          setSession(null);
          setSnapshot(null);
          setError(readableError(reason));
          void agentCompanionApi.lifecycle("webview_closing").catch(() => undefined);
        }
      } finally {
        heartbeatInFlight.current = false;
        setSyncInFlight(false);
      }
    };

    void heartbeat();
    const interval = window.setInterval(() => void heartbeat(), HEARTBEAT_INTERVAL_MS);
    return () => {
      cancelled = true;
      window.clearInterval(interval);
      // Do not disconnect here because React StrictMode replays effect cleanup.
    };
  }, [session]);

  useEffect(() => {
    const accepted = authenticatedSnapshot(snapshot);
    if (!accepted) return;
    const expiresAt = companionSessionExpiryMilliseconds(accepted);
    if (expiresAt === null) return;
    const timeout = window.setTimeout(
      () => setSnapshotClock(Date.now()),
      Math.max(0, expiresAt - Date.now() + 1),
    );
    return () => window.clearTimeout(timeout);
  }, [snapshot]);

  const connectAndSync = useCallback(async (options?: { ignorePendingFinalization?: boolean }) => {
    if (connectInFlight.current) return;
    connectInFlight.current = true;
    setBusy("connect");
    setError("");
    setConnectFailed(false);
    try {
      const nextStored = await refreshStoredState();
      if (!nextStored.configured) throw new Error("Pair this phone before connecting.");
      // The desktop refuses an unfinalized device before its first write, so the
      // transport can only answer with an end of stream. Naming the real blocker
      // here is a local reading of local state, not a claim about the wire.
      //
      // This flag is the phone's belief, not the desktop's. The desktop can have
      // finished pairing while the phone still holds a stale pending flag that
      // only a successful connection clears, so refusing every attempt turned a
      // recoverable state into a deadlock. The explicit retry says "the desktop
      // is done": it must be allowed to find out.
      if (nextStored.pendingPairingFinalization && !options?.ignorePendingFinalization) {
        // companionFailureText owns the owner-facing wording for this refusal,
        // including the exact desktop step and the exact phone button to press
        // afterwards. The marker sentence here is what selects it.
        throw new Error(
          "Pairing is not complete on HPAY Desktop. Finish the pending phone request on the desktop first.",
        );
      }
      const nextSession = validatedSession(await agentCompanionApi.connect(), nextStored);
      const lifecycle = await agentCompanionApi.lifecycle("foreground_heartbeat");
      if (lifecycle.sessionAllowedInBackground || !lifecycle.nativeDisconnectEnforced) {
        throw new Error("The native companion lifecycle policy is invalid.");
      }
      validatePong(await agentCompanionApi.ping(), nextSession);
      const nextSnapshot = validateCompanionStatusSnapshot(
        await agentCompanionApi.sync(),
        nextSession,
        nextStored,
      );
      setSession(nextSession);
      setSnapshot(nextSnapshot);
      setSnapshotClock(Date.now());
      await refreshStoredState();
    } catch (reason) {
      setSession(null);
      setSnapshot(null);
      setError(readableError(reason));
      // A refused connect attempt commits nothing: it advances no sequence,
      // consumes no permit and changes no wallet, pairing or witness state. So
      // pressing Connect and sync again is always safe, and for the whole class
      // of transient refusals - a challenge sequence the phone has already
      // passed, an expired challenge, a busy or slow desktop - it is the only
      // thing that fixes it. Until now this path offered no button at all, and
      // the only retry in the surface was wired exclusively to the pending
      // pairing case, so the one state where pressing again would have worked
      // was the one state with nothing to press.
      setConnectFailed(true);
      void agentCompanionApi.lifecycle("webview_closing").catch(() => undefined);
    } finally {
      connectInFlight.current = false;
      setBusy("");
    }
  }, [refreshStoredState]);

  /**
   * Re-reads the stored pairing state and connects only once the desktop has
   * actually finalized this pairing. It never creates a device identity, never
   * starts a second pairing, never clears the pending state and never changes a
   * witness epoch, so it cannot stand in for the desktop approval it waits on.
   */
  const retryAfterDesktopApproval = useCallback(async () => {
    if (connectInFlight.current) return;
    setError("");
    // The owner is asserting that the desktop side is finished. The phone's own
    // pending flag cannot confirm or deny that, and it is cleared only by a
    // successful connection, so the attempt has to be made rather than refused
    // on the strength of stale local belief. A desktop that has not finished
    // still refuses the device, and that refusal now arrives as a named reason.
    await connectAndSync({ ignorePendingFinalization: true });
  }, [connectAndSync]);

  /**
   * Whether to offer "Try connecting again" for the last failure.
   *
   * Derived from state, never from the wording of the error, so a reworded or
   * newly named refusal can never silently remove the retry. It appears only
   * once a connect attempt has actually failed, and not while the pending
   * pairing panel already owns the retry for that case.
   */
  const connectRetryAvailable =
    connectFailed &&
    !session &&
    Boolean(stored?.configured) &&
    !stored?.pendingPairingFinalization;

  useEffect(() => {
    if (
      busy === "bootstrap" ||
      !stored?.configured ||
      // While the desktop has not finalized this pairing it holds no admission
      // record, so begin() refuses the device and closes without a reply. The
      // attempt can only ever produce an end-of-stream error that reads like a
      // network fault. Waiting for the desktop is the actual next step.
      stored.pendingPairingFinalization ||
      session ||
      autoConnectAttempted.current ||
      document.visibilityState === "hidden"
    ) {
      return;
    }
    autoConnectAttempted.current = true;
    void connectAndSync();
  }, [busy, connectAndSync, session, stored?.configured, stored?.pendingPairingFinalization]);

  const syncNow = async () => {
    // Still a guard, never a silent one: `syncInFlight` disables the button
    // that calls this, so the press cannot land here and vanish.
    if (!session || heartbeatInFlight.current) return;
    heartbeatInFlight.current = true;
    setSyncInFlight(true);
    setBusy("sync");
    setError("");
    try {
      validatePong(await agentCompanionApi.ping(), session);
      const currentStored = storedRef.current;
      if (!currentStored) throw new Error("Companion pairing state is unavailable.");
      const next = validateCompanionStatusSnapshot(
        await agentCompanionApi.sync(),
        session,
        currentStored,
      );
      setSnapshot(next);
      setSnapshotClock(Date.now());
    } catch (reason) {
      setSession(null);
      setSnapshot(null);
      setError(readableError(reason));
    } finally {
      heartbeatInFlight.current = false;
      setSyncInFlight(false);
      setBusy("");
    }
  };

  const disconnect = async () => {
    setBusy("disconnect");
    setError("");
    try {
      const result = await agentCompanionApi.disconnect();
      if (!result.disconnected) throw new Error("Native disconnect was not confirmed.");
      setSession(null);
      setSnapshot(null);
      await refreshStoredState();
    } catch (reason) {
      setError(readableError(reason));
    } finally {
      setBusy("");
    }
  };

  const createIdentity = async () => {
    setBusy("identity");
    setError("");
    try {
      setIdentity(validatedIdentityStatus(await agentCompanionApi.createIdentity()));
    } catch (reason) {
      setError(readableError(reason));
      throw reason;
    } finally {
      setBusy("");
    }
  };

  const resetCompanion = async () => {
    await runReset("reset", () => agentCompanionApi.reset());
  };

  /**
   * Retires a pairing whose Android identity this phone no longer holds.
   *
   * The native side re-reads the Keystore and refuses if the key is still live,
   * so this cannot erase a working phone's rollback memory. It exists because a
   * revoked phone that also holds witness state had no way out at all: the
   * pairing-only reset refuses, and being refused permanently replaced the
   * reset section with a rotation that desktop can no longer run with it.
   */
  const retireOrphanedPairing = async () => {
    await runReset("retire", () => agentCompanionApi.retireOrphanedPairing());
  };

  /**
   * Ends this phone's intent to sign one exact payment it is still holding.
   *
   * Not a reset: no pairing, identity, witness memory or session is touched, so
   * this deliberately does not go through `runReset`. Afterwards the stored
   * state is re-read, because clearing the record is what unblocks the reset,
   * pairing and every other payment - and the screen has to see that.
   */
  const discardHeldConsent = async (operationId: string) => {
    setBusy("discard");
    setError("");
    try {
      const result = await agentCompanionApi.discardHeldConsent(operationId);
      if (result.discarded.operationId !== operationId) {
        throw new Error(
          "The native side discarded a different payment than the one shown.",
        );
      }
      await refreshStoredState();
    } catch (reason) {
      setError(readableError(reason));
      throw reason;
    } finally {
      setBusy("");
    }
  };

  const runReset = async (
    label: string,
    call: () => Promise<Awaited<ReturnType<typeof agentCompanionApi.reset>>>,
  ) => {
    setBusy(label);
    setError("");
    try {
      const result = await call();
      if (
        !result.reset ||
        !result.disconnected ||
        !result.pairingCancelled ||
        !result.hardwareIdentityRetained ||
        !result.requiresNewPairing
      ) {
        throw new Error("The native companion reset was not fully confirmed.");
      }
      setSession(null);
      setSnapshot(null);
      await Promise.all([refreshStoredState(), refreshIdentity()]);
    } catch (reason) {
      setError(readableError(reason));
      throw reason;
    } finally {
      setBusy("");
    }
  };

  return {
    identity,
    stored,
    session,
    trustedSnapshot,
    approvalExpiredThisTick,
    busy,
    /** A status read is already running, so the refresh control is disabled. */
    syncInFlight,
    error,
    setError,
    connectRetryAvailable,
    refreshIdentity,
    refreshStoredState,
    connectAndSync,
    retryAfterDesktopApproval,
    syncNow,
    disconnect,
    createIdentity,
    resetCompanion,
    retireOrphanedPairing,
    discardHeldConsent,
  };
}

/**
 * Copy only. Every failure that reaches the owner passes through one place, so
 * a raw Rust Display such as "companion backend rejected the operation" can
 * never be shown verbatim. It changes no control flow and swallows nothing:
 * the same failures still fail, and still fail closed.
 */
function readableError(error: unknown): string {
  return companionFailureText(error);
}
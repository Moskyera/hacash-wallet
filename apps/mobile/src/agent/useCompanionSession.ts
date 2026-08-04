import { useCallback, useEffect, useRef, useState } from "react";
import { agentCompanionApi } from "./api";
import { companionFailureText } from "./companionStatus";
import {
  authenticatedSnapshot,
  companionSessionExpiryMilliseconds,
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
    void Promise.all([agentCompanionApi.identityStatus(), agentCompanionApi.state()])
      .then(([identityValue, stateValue]) => {
        if (cancelled) return;
        const nextIdentity = validatedIdentityStatus(identityValue);
        const nextState = validatedStoredState(stateValue);
        storedRef.current = nextState;
        setIdentity(nextIdentity);
        setStored(nextState);
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
    if (!session || heartbeatInFlight.current) return;
    heartbeatInFlight.current = true;
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
    setBusy("reset");
    setError("");
    try {
      const result = await agentCompanionApi.reset();
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
    busy,
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
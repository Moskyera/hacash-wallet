import { useEffect, useRef, useState } from "react";
import type { UnlistenFn } from "@tauri-apps/api/event";
import { WebviewWindow } from "@tauri-apps/api/webviewWindow";
import MobileApp from "./MobileApp";
import { api } from "./api";
import { AGENT_COMPANION_WEBVIEW_LABEL } from "./agent/companionWindow";
import "./agent/agent-wallet.css";

export type WalletSpace = "personal" | "agent";

const AGENT_CREATE_TIMEOUT_MS = 12_000;
const AGENT_CLOSE_POLL_MS = 500;

function isTauri(): boolean {
  return typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
}

type AgentWebviewLookup = {
  checked: boolean;
  webview: WebviewWindow | null;
};

async function findAgentWebview(): Promise<AgentWebviewLookup> {
  try {
    return {
      checked: true,
      webview: await WebviewWindow.getByLabel(AGENT_COMPANION_WEBVIEW_LABEL),
    };
  } catch {
    return { checked: false, webview: null };
  }
}

function waitForWebviewCreation(webview: WebviewWindow): Promise<void> {
  return new Promise((resolve, reject) => {
    let settled = false;
    let timeout: number | null = null;
    let createdUnlisten: Promise<UnlistenFn> | null = null;
    let errorUnlisten: Promise<UnlistenFn> | null = null;

    const cleanup = async () => {
      const listeners = [createdUnlisten, errorUnlisten].filter(
        (listener): listener is Promise<UnlistenFn> => listener !== null,
      );
      const results = await Promise.allSettled(listeners);
      for (const result of results) {
        if (result.status === "fulfilled") {
          try {
            result.value();
          } catch {
            // Listener cleanup is best effort after the promise has settled.
          }
        }
      }
    };

    const settle = (error?: Error) => {
      if (settled) return;
      settled = true;
      if (timeout !== null) window.clearTimeout(timeout);
      void cleanup().finally(() => {
        if (error) reject(error);
        else resolve();
      });
    };

    createdUnlisten = webview.once("tauri://created", () => settle());
    errorUnlisten = webview.once<unknown>("tauri://error", (event) => {
      const message =
        typeof event.payload === "string"
          ? event.payload
          : "AI Agent Wallet view could not be created";
      settle(new Error(message));
    });
    timeout = window.setTimeout(
      () => settle(new Error("AI Agent Wallet view timed out")),
      AGENT_CREATE_TIMEOUT_MS,
    );
  });
}

export default function WalletSpacesApp() {
  const [openingAgent, setOpeningAgent] = useState(false);
  const [agentActive, setAgentActive] = useState(false);
  const [personalMounted, setPersonalMounted] = useState(true);
  const [openError, setOpenError] = useState("");
  const openingRef = useRef(false);
  const mountedRef = useRef(true);

  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
    };
  }, []);

  useEffect(() => {
    if (!agentActive || !isTauri()) return;
    let disposed = false;
    let checking = false;

    const checkForClose = async () => {
      if (checking) return;
      checking = true;
      try {
        const current = await WebviewWindow.getByLabel(
          AGENT_COMPANION_WEBVIEW_LABEL,
        );
        if (!disposed && !current) {
          setAgentActive(false);
          setPersonalMounted(true);
          setOpenError("");
        }
      } catch {
        // Fail closed: an uncertain child state must not remount Personal UI.
      } finally {
        checking = false;
      }
    };

    const interval = window.setInterval(
      () => void checkForClose(),
      AGENT_CLOSE_POLL_MS,
    );
    void checkForClose();
    return () => {
      disposed = true;
      window.clearInterval(interval);
    };
  }, [agentActive]);

  const openAgentCompanion = async () => {
    if (openingRef.current) return;
    openingRef.current = true;
    setOpeningAgent(true);
    setOpenError("");

    try {
      if (!isTauri()) {
        window.location.assign("/?wallet-space=agent");
        return;
      }

      // Remove Personal data from the DOM before yielding to native lock IPC.
      setPersonalMounted(false);
      try {
        await api.lock();
      } catch {
        setOpenError(
          "My Wallet lock could not be confirmed. Restart HPAY before continuing.",
        );
        return;
      }

      let createdChild: WebviewWindow | null = null;
      try {
        const existing = await findAgentWebview();
        if (!existing.checked) {
          throw new Error("AI Agent Wallet state could not be confirmed");
        }
        if (existing.webview) {
          setAgentActive(true);
          await existing.webview.show();
          await existing.webview.setFocus();
          return;
        }

        createdChild = new WebviewWindow(AGENT_COMPANION_WEBVIEW_LABEL, {
          title: "HPAY AI Agent Wallet",
          url: "/?wallet-space=agent",
          activityName: "AgentCompanionActivity",
          createdByActivityName: "MainActivity",
          focus: true,
          visible: true,
          contentProtected: true,
          backgroundColor: { red: 0, green: 0, blue: 0, alpha: 255 },
        });
        await waitForWebviewCreation(createdChild);
        setAgentActive(true);
      } catch {
        const live = await findAgentWebview();
        if (live.webview) {
          setAgentActive(true);
          setOpenError(
            "AI Agent Wallet could not be focused. My Wallet remains locked. Retry to focus it.",
          );
          return;
        }

        if (!live.checked) {
          setOpenError(
            "AI Agent Wallet state could not be confirmed. My Wallet remains locked. Restart HPAY.",
          );
          return;
        }

        if (createdChild) {
          await createdChild.close().catch(() => undefined);
        }
        setAgentActive(false);
        setPersonalMounted(true);
        setOpenError(
          "AI Agent Wallet could not open. My Wallet was locked for safety.",
        );
      }
    } finally {
      openingRef.current = false;
      if (mountedRef.current) setOpeningAgent(false);
    }
  };

  return (
    <div className="wallet-spaces-root">
      <nav className="wallet-space-switcher" aria-label="Wallet space">
        <button
          type="button"
          aria-label="Open AI Agent Wallet"
          disabled={openingAgent || agentActive}
          onClick={() => void openAgentCompanion()}
        >
          <span>{openingAgent ? "Opening..." : "AI Agent Wallet"}</span>
          <span aria-hidden>⌄</span>
        </button>
      </nav>

      {openError ? (
        <p className="agent-error" role="alert">
          {openError}
        </p>
      ) : null}

      <div className="wallet-space-stage">
        {personalMounted ? (
          <MobileApp onOpenAgent={() => void openAgentCompanion()} />
        ) : (
          <section className="agent-boundary-card" role="status">
            <strong>My Wallet is locked</strong>
            <p>
              Personal Wallet data stays cleared while the isolated AI Agent
              Wallet companion is open.
            </p>
          </section>
        )}
      </div>
    </div>
  );
}

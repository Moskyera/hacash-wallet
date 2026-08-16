import { useRef, useState } from "react";
import { agentCompanionApi } from "./api";
import AgentCompanionApp from "./AgentCompanionApp";

const AGENT_CLOSE_CLEANUP_GRACE_MS = 1_000;

async function requestBoundedLifecycleCleanup(): Promise<void> {
  let timeout: number | undefined;
  await Promise.race([
    agentCompanionApi.lifecycle("webview_closing").catch(() => undefined),
    new Promise<void>((resolve) => {
      timeout = window.setTimeout(resolve, AGENT_CLOSE_CLEANUP_GRACE_MS);
    }),
  ]).finally(() => {
    if (timeout !== undefined) window.clearTimeout(timeout);
  });
}

export default function AgentCompanionWindowApp() {
  const [closeError, setCloseError] = useState("");
  const [closing, setClosing] = useState(false);
  const closingRef = useRef(false);

  const returnToPersonal = async () => {
    if (closingRef.current) return;
    closingRef.current = true;
    setClosing(true);
    setCloseError("");
    try {
      if ("__TAURI_INTERNALS__" in window) {
        try {
          await requestBoundedLifecycleCleanup();
        } finally {
          const result = await agentCompanionApi.closeActivity();
          if (!result.closed) {
            throw new Error("Agent Activity close was not confirmed");
          }
        }
      } else {
        window.location.assign("/");
      }
    } catch {
      setCloseError("Could not return to My Wallet. Please retry.");
      closingRef.current = false;
      setClosing(false);
    }
  };

  return (
    <div className="wallet-spaces-root">
      <nav className="wallet-space-switcher" aria-label="Wallet space">
        <button
          type="button"
          className="active"
          aria-pressed="true"
          disabled={closing}
          onClick={() => void returnToPersonal()}
        >
          <span>{closing ? "Closing..." : "AI Agent Wallet"}</span>
          <span aria-hidden>{"\u2304"}</span>
        </button>
      </nav>

      {closeError ? <p className="agent-error" role="alert">{closeError}</p> : null}

      <div className="wallet-space-stage">
        <AgentCompanionApp />
      </div>
    </div>
  );
}

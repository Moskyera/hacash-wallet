import { useRef, useState } from "react";
import { getCurrentWindow } from "@tauri-apps/api/window";
import { agentCompanionApi } from "./api";
import AgentCompanionApp from "./AgentCompanionApp";

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
          await agentCompanionApi.lifecycle("webview_closing");
        } finally {
          await getCurrentWindow().close();
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

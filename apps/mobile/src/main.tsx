import React from "react";
import ReactDOM from "react-dom/client";
import { getCurrentWebview } from "@tauri-apps/api/webview";
import WalletSpacesApp from "./WalletSpacesApp";
import AgentCompanionWindowApp from "./agent/AgentCompanionWindowApp";
import { shouldRenderAgentCompanionRoot } from "./agent/companionWindow";
import { LocaleProvider } from "./locale";
import { installSafeAreaInsets } from "./utils/safeArea";
import "./mobile.css";
import "./dashboard.css";

installSafeAreaInsets();

const tauriRuntime = "__TAURI_INTERNALS__" in window;
let currentWebviewLabel: string | null = null;
if (tauriRuntime) {
  try {
    currentWebviewLabel = getCurrentWebview().label;
  } catch {
    // Fail closed to the Personal root when native identity is unavailable.
  }
}

const RootApp = shouldRenderAgentCompanionRoot({
  search: window.location.search,
  tauriRuntime,
  currentWebviewLabel,
})
  ? AgentCompanionWindowApp
  : WalletSpacesApp;

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <LocaleProvider>
      <RootApp />
    </LocaleProvider>
  </React.StrictMode>,
);

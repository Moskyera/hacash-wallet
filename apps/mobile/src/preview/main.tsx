/**
 * Dev-only entry point for reviewing the mobile UI in a browser.
 *
 * Start it with `yarn dev` in apps/mobile and open /preview.html. See ipcMock.ts
 * for what is faked and why. Not part of the production bundle: the Rollup input
 * stays index.html only.
 */
import React from "react";
import ReactDOM from "react-dom/client";

import { PreviewErrorBoundary } from "./PreviewErrorBoundary";
import { installPreviewIpc, seedPreviewPriceCache } from "./ipcMock";
import { installSafeAreaInsets } from "../utils/safeArea";
import "../mobile.css";
import "../dashboard.css";
import "../agent/agent-wallet.css";

installPreviewIpc();
seedPreviewPriceCache();
installSafeAreaInsets();

// Imported after the mock is installed so nothing reaches for a real IPC bridge
// while the module graph is still evaluating.
const [
  { default: WalletSpacesApp },
  { default: AgentCompanionWindowApp },
  { hasAgentCompanionRoute },
  { LocaleProvider },
] = await Promise.all([
  import("../WalletSpacesApp"),
  import("../agent/AgentCompanionWindowApp"),
  import("../agent/companionWindow"),
  import("../locale"),
]);

/*
 * On a device the companion lives in its own webview, which a browser tab has
 * no equivalent for. The same query the app routes on picks it here, so
 * /preview.html?wallet-space=agent reviews the Agent Wallet screens.
 */
const RootApp = hasAgentCompanionRoute(window.location.search)
  ? AgentCompanionWindowApp
  : WalletSpacesApp;

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <PreviewErrorBoundary>
      <LocaleProvider>
        <RootApp />
      </LocaleProvider>
    </PreviewErrorBoundary>
  </React.StrictMode>,
);

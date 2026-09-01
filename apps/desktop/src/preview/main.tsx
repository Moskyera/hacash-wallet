/**
 * Dev-only entry point for reviewing the desktop UI in a browser.
 *
 * Start it with `yarn dev` and open /preview.html. See ipcMock.ts for what is
 * faked and why. This file is not part of the production bundle: the Rollup
 * input stays index.html only.
 */
import React from "react";
import ReactDOM from "react-dom/client";

import { PreviewErrorBoundary } from "./PreviewErrorBoundary";
import { installPreviewIpc, seedPreviewPriceCache } from "./ipcMock";
import "../styles.css";
import "../dashboard.css";

installPreviewIpc();
seedPreviewPriceCache();

// Imported after the mock is installed so nothing can reach for a real IPC
// bridge while the module graph is still evaluating.
const [{ default: App }, { LocaleProvider }] = await Promise.all([
  import("../App"),
  import("../locale"),
]);

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <PreviewErrorBoundary>
      <LocaleProvider>
        <App />
      </LocaleProvider>
    </PreviewErrorBoundary>
  </React.StrictMode>,
);

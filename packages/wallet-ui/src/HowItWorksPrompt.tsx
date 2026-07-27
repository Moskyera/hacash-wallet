import { useState } from "react";

import "./howItWorks.css";

import { HOW_IT_WORKS_URL } from "./securityPolicy";

const DISMISSED_KEY = "hacash_wallet_how_it_works_dismissed";

export type HowItWorksPromptCopy = {
  title: string;
  body: string;
  open: string;
  later: string;
  never: string;
};

export function howItWorksDismissed(): boolean {
  try {
    return localStorage.getItem(DISMISSED_KEY) === "1";
  } catch {
    return false;
  }
}

export function dismissHowItWorks(): void {
  try {
    localStorage.setItem(DISMISSED_KEY, "1");
  } catch {
    // A display preference must never prevent the wallet from opening.
  }
}

/**
 * Same first-run safety prompt for both shells. Platform URL opening stays injected,
 * so this shared component does not gain Tauri or browser privileges of its own.
 */
export function HowItWorksPrompt({
  copy,
  openExternal,
  onError,
}: {
  copy: HowItWorksPromptCopy;
  openExternal: (url: string) => void | Promise<void>;
  onError?: (cause: unknown) => void;
}) {
  const [visible, setVisible] = useState(() => !howItWorksDismissed());
  if (!visible) return null;

  return (
    <aside className="card how-it-works-prompt" aria-label={copy.title}>
      <h2>{copy.title}</h2>
      <p className="muted small">{copy.body}</p>
      <button
        type="button"
        className="primary"
        onClick={() => {
          try {
            void Promise.resolve(openExternal(HOW_IT_WORKS_URL)).catch(onError);
          } catch (cause) {
            onError?.(cause);
          }
        }}
      >
        {copy.open}
      </button>
      <div className="how-it-works-actions">
        <button type="button" onClick={() => setVisible(false)}>
          {copy.later}
        </button>
        <button
          type="button"
          onClick={() => {
            dismissHowItWorks();
            setVisible(false);
          }}
        >
          {copy.never}
        </button>
      </div>
    </aside>
  );
}

export const AGENT_COMPANION_WEBVIEW_LABEL = "agent-companion";
export const AGENT_COMPANION_QUERY = "wallet-space";

export function hasAgentCompanionRoute(search: string): boolean {
  return new URLSearchParams(search).get(AGENT_COMPANION_QUERY) === "agent";
}

type AgentCompanionRootInput = {
  search: string;
  tauriRuntime: boolean;
  currentWebviewLabel: string | null;
};

/**
 * Tauri capabilities are attached to webview labels, so the native app must
 * never select the Agent root from URL input alone. The query remains a
 * secondary guard against accidentally loading the Agent root at the wrong
 * local route. Browser preview has no native command surface and may use the
 * route by itself.
 */
export function shouldRenderAgentCompanionRoot({
  search,
  tauriRuntime,
  currentWebviewLabel,
}: AgentCompanionRootInput): boolean {
  if (!hasAgentCompanionRoute(search)) return false;
  return (
    !tauriRuntime ||
    currentWebviewLabel === AGENT_COMPANION_WEBVIEW_LABEL
  );
}

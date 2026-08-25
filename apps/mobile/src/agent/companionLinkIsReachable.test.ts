/**
 * A BUTTON THAT CANNOT WORK, IN THE ONE PLACE THAT EXPLAINS THE FEATURE.
 *
 * "What is an AI Agent Wallet?" is the single explanatory control on the
 * companion screen, sitting next to the line "No wallet key on this phone." It
 * called `openUrl(...)` from `@tauri-apps/plugin-opener`, which invokes
 * `plugin:opener|open_url` and needs `opener:allow-open-url`.
 *
 * This code runs only in the agent-companion webview, and
 * `apps/mobile/src-tauri/capabilities/agent-companion.json` grants exactly
 * `["allow-agent-companion"]` - no opener, no core:default. So the call is
 * refused every single time, and the refusal is not even quiet: the raw Tauri
 * permission string lands under the heading "That step did not go through".
 *
 * The least-privilege grant is CORRECT and must not be widened to make the
 * button work - `crates/wallet-tauri-common/tests/acl_inventory.rs` asserts that
 * permission list verbatim, deliberately. The fix is that the wallet answers the
 * question itself, in the app, where it needs no permission at all, and shows
 * the URL for anyone who wants the full document.
 */
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

const companion = readFileSync(
  new URL("./AgentCompanionApp.tsx", import.meta.url),
  "utf8",
);
const capability = readFileSync(
  new URL("../../src-tauri/capabilities/agent-companion.json", import.meta.url),
  "utf8",
);

describe("the companion explains itself without a permission it does not have", () => {
  it("keeps the companion capability least-privilege", () => {
    const granted = JSON.parse(capability).permissions as string[];
    expect(granted).toEqual(["allow-agent-companion"]);
    expect(
      granted.some((p) => p.startsWith("opener")),
      "widening this grant is not the fix; acl_inventory asserts it verbatim",
    ).toBe(false);
  });

  it("does not call openUrl from the companion webview", () => {
    expect(
      companion,
      "openUrl needs opener:allow-open-url, which this webview is never granted",
    ).not.toMatch(/\bopenUrl\s*\(/);
  });

  it("does not import the opener plugin at all", () => {
    expect(companion).not.toContain("@tauri-apps/plugin-opener");
  });

  it("answers the question in the app instead", () => {
    expect(companion).toContain("What is an AI Agent Wallet?");
    // The substance, not just the heading.
    expect(companion).toMatch(/agent-boundary-explainer/);
  });

  it("still shows the URL, so the full document is findable by hand", () => {
    expect(companion).toContain("AGENT_WALLET_HOW_IT_WORKS_URL");
  });
});

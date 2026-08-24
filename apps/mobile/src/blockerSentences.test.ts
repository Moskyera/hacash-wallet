import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import { explainBlocker } from "@hacash/wallet-ui";

const HERE = dirname(fileURLToPath(import.meta.url));
const READINESS = join(HERE, "../../../crates/l2-fast-pay-hub/src/readiness.rs");

/**
 * Every blocker a Hub can publish must have a plain sentence beside it.
 *
 * The card prints identifiers verbatim on purpose, because a summarised cause
 * sends a person off to change providers when the provider was fine. But
 * `fullnode_below_pinned_mainnet_checkpoint_765432` tells a human nothing, so
 * the sentence sits beside the identifier rather than replacing it.
 *
 * This scans the Hub's own source instead of restating a list, so a Hub that
 * grows a new blocker fails here until somebody writes what it means. That is
 * the point: an unexplained identifier is a screen that has stopped speaking.
 */
function blockerIdentifiers(): string[] {
  const source = readFileSync(READINESS, "utf8");
  const found = new Set<string>();
  for (const match of source.matchAll(/"([a-z][a-z0-9_]{13,})"/g)) {
    const id = match[1];
    if (!/(?:_not_|^no_|^not_|_is_not$|missing|below_|cannot|could_not|latched|_not_enabled$|_not_configured$|_not_evaluated$)/.test(id)) {
      continue;
    }
    if (id === "close_blockers") continue;
    found.add(id);
  }
  // Built with format! and a trailing height, so the constant carries the stem.
  if (source.includes("fullnode_below_pinned_mainnet_checkpoint_")) {
    found.add("fullnode_below_pinned_mainnet_checkpoint_765432");
  }
  return [...found].sort();
}

describe("what a Hub says is stopping it", () => {
  it("finds the Hub's blockers in its own source", () => {
    const ids = blockerIdentifiers();
    // A silent regex change that matched nothing would make every assertion
    // below pass while checking nothing at all.
    expect(ids.length).toBeGreaterThanOrEqual(10);
  });

  it("has a plain sentence for every one of them", () => {
    const unexplained = blockerIdentifiers().filter((id) => !explainBlocker(id));
    expect(unexplained).toEqual([]);
  });

  it("leaves an identifier it does not know alone rather than guessing", () => {
    expect(explainBlocker("some_blocker_a_future_hub_invents")).toBeNull();
  });

  it("matches the checkpoint blocker whatever height it names", () => {
    expect(explainBlocker("fullnode_below_pinned_mainnet_checkpoint_765432")).toMatch(/finish syncing/);
    expect(explainBlocker("fullnode_below_pinned_mainnet_checkpoint_999999")).toMatch(/finish syncing/);
  });

  it("says the voucher is the answer when the wallet cannot exit alone", () => {
    // This blocker has an action behind it, and the action is the whole point
    // of the voucher work: take one before paying anything.
    expect(explainBlocker("wallet_cannot_build_a_unilateral_exit_without_the_hub")).toMatch(
      /close voucher before you pay/,
    );
  });
});

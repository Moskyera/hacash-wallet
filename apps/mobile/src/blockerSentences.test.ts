import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import { explainBlocker, FAST_PAY_MAINNET_CHANNEL_REFUSED } from "@hacash/wallet-ui";

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

  it("never tells this wallet to take a voucher it cannot take", () => {
    // This sentence used to end "Take a close voucher before you pay
    // anything". This wallet has no close-voucher command, so that was an
    // instruction to do something impossible, printed a few hundred pixels
    // from the consent box that says there is no way out. The instruction is
    // gone and must not come back while the command is absent.
    const sentence = explainBlocker("wallet_cannot_build_a_unilateral_exit_without_the_hub");
    expect(sentence).not.toBeNull();
    expect(sentence).not.toMatch(/take a close voucher before you pay/i);
  });

  it("keeps the true half of the no-way-out sentence word for word", () => {
    // Removing an instruction must not remove the disclosure. This half was
    // always true and is the stronger statement of the two.
    expect(explainBlocker("wallet_cannot_build_a_unilateral_exit_without_the_hub")).toContain(
      "Your wallet cannot build a way out on its own.",
    );
  });

  it("names where the exit does exist instead of only saying no", () => {
    const sentence = explainBlocker("wallet_cannot_build_a_unilateral_exit_without_the_hub")!;
    // Where the voucher lives, and that it is behind its own gates.
    expect(sentence).toMatch(/Agent Wallet/);
    // NOT "build flag". That clause was here and it was the wrong gate to
    // name: the flag is already on in every official desktop release, so it is
    // the one barrier the reader has already cleared. Pin the two that really
    // stop them instead, because those are what decide whether the trip is
    // worth starting.
    expect(sentence).not.toMatch(/build flag/);
    expect(sentence).toMatch(/separate wallet/);
    expect(sentence).toMatch(/their own Hacash full node and their own Fast Pay Hub/);
    // What this wallet now does about it, said before any money moves.
    expect(sentence).toMatch(/refuses to open a channel/);
    // And that the rail it points at is a trusted arrangement, not a
    // guarantee. Nothing in this system is trustless and nothing may say so.
    expect(sentence).toMatch(/nothing compels it/);
    expect(sentence.toLowerCase()).not.toContain("trustless");
  });
});

/**
 * A sentence rendered on two platforms has to be true on both of them.
 *
 * This is a real defect that shipped in this file's neighbour and was caught
 * only by going and looking. FAST_PAY_MAINNET_CHANNEL_REFUSED is imported by
 * the desktop Fast Pay screen AND by this app's Fast Pay screen, and it said
 * the close voucher sits "behind its own consent and its own build flag". On
 * the desktop that flag is already on. On the phone there is no agent wallet
 * code in the build at all and no voucher command in the ACL, so the sentence
 * invited a person to go looking on their device for something that is not on
 * it, which is the "message that goes nowhere" shape this codebase keeps
 * producing.
 *
 * The guard is deliberately about DEVICE-SPECIFIC words rather than about the
 * particular wording that was wrong, because the next version of this mistake
 * will not repeat the phrase "build flag". Anything that tells the reader what
 * is or is not present "here" is a claim about one device, and one of the two
 * screens will be the other device.
 */
describe("sentences shared by the phone and the desktop", () => {
  it("never makes a claim that is only true on one of the two screens", () => {
    // A word that points at the reader's own device. Safe on a screen that
    // exists once; a lie on a screen that renders in two places.
    const DEVICE_SPECIFIC = [
      /\bthis phone\b/i,
      /\byour phone\b/i,
      /\bthis device\b/i,
      /\byour device\b/i,
      /\bon this computer\b/i,
      /\bthe desktop app\b/i,
      /\bswitch on here\b/i,
      /\bbuild flag\b/i,
    ];
    for (const pattern of DEVICE_SPECIFIC) {
      expect(FAST_PAY_MAINNET_CHANNEL_REFUSED).not.toMatch(pattern);
      expect(
        explainBlocker("wallet_cannot_build_a_unilateral_exit_without_the_hub"),
      ).not.toMatch(pattern);
    }
  });

  it("still names the gates that decide whether the trip is worth starting", () => {
    // Dropping the false clause must not leave a refusal with no destination,
    // which reads as a broken build. Both sentences keep the two facts that
    // actually cost a person something.
    for (const sentence of [
      FAST_PAY_MAINNET_CHANNEL_REFUSED,
      explainBlocker("wallet_cannot_build_a_unilateral_exit_without_the_hub")!,
    ]) {
      expect(sentence).toMatch(/Agent Wallet/);
      expect(sentence).toMatch(/separate/);
      expect(sentence).toMatch(/own node and Hub|own Hacash full node and their own Fast Pay Hub/);
    }
  });
});

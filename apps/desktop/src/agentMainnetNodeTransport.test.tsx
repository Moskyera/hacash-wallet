import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import { mainnetSigningTransportIsEligible } from "@hacash/wallet-ui";

const HERE = dirname(fileURLToPath(import.meta.url));
const AGENT_APP = join(HERE, "agent/AgentWalletApp.tsx");

/**
 * Remove comments so a source guard reads what the program does rather than
 * what it says about itself. Crude on purpose: it looks for a predicate, it
 * does not parse TSX.
 *
 * The line-comment rule refuses to fire on a `//` preceded by a colon, and that
 * is not a nicety. The first version of this helper did not, so it treated the
 * `//` inside the literal `"https://"` as the start of a comment and deleted
 * the rest of the line, including the very call the guard exists to find. The
 * guard then passed against code that had the defect reinstated, which is the
 * failure it was written to prevent, committed by the test itself. Verified by
 * putting the broken predicate back and watching this fail.
 */
function stripComments(source: string): string {
  return source
    .replace(/\/\*[\s\S]*?\*\//g, " ")
    .replace(/(^|[^:])\/\/[^\n]*/g, "$1");
}

/**
 * One transport rule, asked in one way.
 *
 * The create-agent-wallet screen used to compute its own error message with
 * `!mainnetNodeUrl.startsWith("https://")` while the submit button beside it
 * asked `mainnetSigningTransportIsEligible`. Those two disagree on exactly one
 * input, and it is the input that matters: a node on this same machine, which
 * is what an owner actually runs and what the core rule
 * (`validate_signing_node_url` in crates/wallet-core/src/settings.rs) has
 * always accepted over plain HTTP because there is no network hop to intercept.
 *
 * The result was a screen showing a red "requires HTTPS" error above an enabled
 * button. A person believes the error. Nothing was broken and they stop anyway.
 */
describe("the mainnet node transport rule on the agent create screen", () => {
  it("accepts the loopback node an owner actually runs", () => {
    for (const url of [
      "http://127.0.0.1:8080",
      "http://localhost:8080",
      "http://[::1]:8080",
      "https://node.example.org",
    ]) {
      expect(mainnetSigningTransportIsEligible(url, "mainnet")).toBe(true);
    }
  });

  it("still refuses plaintext to a remote host", () => {
    // The relaxation is loopback only. A node across a network still needs TLS,
    // because there the hop exists and a transaction can be substituted on it.
    for (const url of ["http://nodeapi.hacash.org", "http://198.51.100.7:8080"]) {
      expect(mainnetSigningTransportIsEligible(url, "mainnet")).toBe(false);
    }
  });

  it("does not hand-roll the rule anywhere in the agent screen", () => {
    // This is the guard that would have caught the original defect, and it
    // guards the SHAPE rather than the one wording that was wrong: any screen
    // that decides transport eligibility by inspecting the URL string itself
    // has forked a security rule, and the fork will drift.
    //
    // Comments are stripped first, and that is not a convenience. This file and
    // AgentWalletApp.tsx both QUOTE the old broken predicate in prose, to say
    // why it was wrong. A guard that cannot tell code from an explanation of
    // code punishes writing the explanation down, and the explanation is the
    // thing most likely to stop the mistake being made a third time.
    const source = stripComments(readFileSync(AGENT_APP, "utf8"));
    const handRolled = [
      /startsWith\(\s*["'`]https:\/\//,
      /!==\s*["'`]https:["'`]/,
      /\bprotocol\s*===?\s*["'`]https:["'`]/,
    ];
    for (const pattern of handRolled) {
      expect(source).not.toMatch(pattern);
    }
    // And it must still be asking the shared predicate, so this test cannot
    // pass by the screen simply dropping the check altogether.
    expect(source).toMatch(/mainnetSigningTransportIsEligible\(/);
  });
});

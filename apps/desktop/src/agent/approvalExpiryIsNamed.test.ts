/**
 * A GREY "APPROVE" WITH NO SENTENCE ATTACHED TO IT.
 *
 * The Agent Wallet's pending-approval review ends in one control:
 *
 *   disabled={busy || approvalIsExpired(approval) || !approvalIsExactAndFeeFree(approval)}
 *
 * Two of those three conditions block a person who has just read the recipient,
 * the fee and the total debit and decided yes. The malformed-or-fee branch
 * renders an explicit reason right above the button ("This approval is malformed
 * or contains a wallet fee. Signing is blocked."). The expiry branch rendered
 * NOTHING: grepping the whole file for "expired" returned only two lines, both
 * belonging to the unrelated witness-window copy.
 *
 * So the owner got a grey rectangle. The "Expires" value was one cell in a
 * seven-cell detail grid and did not say it had passed. This repository has
 * shipped the greyed version before, and that is the thing being fixed.
 *
 * THE GATE DOES NOT MOVE. An expired approval is still refused - it is a
 * commitment whose window has closed, and the core refuses it too. What changes
 * is that the refusal has a cause on screen.
 */
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

const source = readFileSync(new URL("./AgentAdminPages.tsx", import.meta.url), "utf8");

describe("an expired approval says so", () => {
  it("renders a named reason when the approval has expired", () => {
    expect(
      source,
      "the review must render an expiry reason, not only disable the button",
    ).toMatch(/approvalIsExpired\(approval\)\s*&&\s*</);
  });

  it("uses the word expired in the copy a person reads", () => {
    // Excluding the two witness-window lines, which are about something else.
    const withoutWitness = source
      .split("\n")
      .filter((line) => !line.includes("witness"))
      .join("\n");
    expect(withoutWitness).toMatch(/approval (has )?expired|expired.{0,40}sign/i);
  });

  it("says nothing was signed, so the owner is not left wondering", () => {
    expect(source).toMatch(/expired[\s\S]{0,400}Nothing (was|has been) signed/i);
  });

  it("tells the owner what to do about it", () => {
    // A cause with no next step is half an answer. The agent has to ask again.
    expect(source).toMatch(/expired[\s\S]{0,500}(ask|request|new approval|again)/i);
  });

  it("keeps the expiry check itself unchanged", () => {
    // The naming fix must not become a weakened gate.
    expect(source).toContain(
      "return expiresAt === null || Math.floor(Date.now() / 1_000) >= expiresAt;",
    );
    expect(source).toContain("approvalIsExpired(approval)");
  });

  it("still refuses a malformed or fee-bearing approval by name", () => {
    expect(source).toContain(
      "This approval is malformed or contains a wallet fee. Signing is blocked.",
    );
  });
});

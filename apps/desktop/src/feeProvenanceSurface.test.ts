import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

const read = (name: string) =>
  readFileSync(new URL(`./${name}`, import.meta.url), "utf8");

/**
 * A fee warning that is computed and never rendered is the same as no warning.
 *
 * The wallet measures whether a network fee was quoted by the node or invented
 * from its own floor, and carries the reason across three surfaces. Each of
 * those crossings was added by hand and each can be deleted by hand without a
 * single Rust test noticing, because the Rust side stops at the struct field.
 * These assertions are the other end of that wire.
 *
 * They are source-text assertions on purpose. The alternative is mounting the
 * screens, which this app does not do anywhere else, and the property being
 * protected is simply "this value reaches JSX at all".
 */
describe("a guessed network fee reaches the person paying it", () => {
  it("is rendered on the send preview", () => {
    const send = read("screens/SendScreen.tsx");
    const index = send.indexOf("preview.plan.fee_estimate_degraded");
    expect(index, "the send screen never reads the warning").toBeGreaterThan(0);
    // Rendered, not merely read into a variable that goes nowhere.
    expect(send).toContain("{preview.plan.fee_estimate_degraded}");
  });

  it("is rendered on both agent channel reviews, which are the owner's confirm step", () => {
    const agent = read("agent/AgentWalletApp.tsx");
    // The open. This one replaced a blanket refusal, so if the render is gone
    // the agent silently opens channels at an invented fee again.
    expect(agent).toContain("{setup.fee_estimate_degraded}");
    // The close. Same money, same disclosure.
    expect(agent).toContain("{close.fee_estimate_degraded}");
  });

  it("is typed as nullable on both agent reviews, so absent reads as unknown rather than fine", () => {
    const api = read("agent/api.ts");
    const occurrences = api.split("fee_estimate_degraded: string | null;").length - 1;
    expect(
      occurrences,
      "expected the field on both AgentChannelSetupReview and AgentChannelCloseReview",
    ).toBe(2);
  });
});

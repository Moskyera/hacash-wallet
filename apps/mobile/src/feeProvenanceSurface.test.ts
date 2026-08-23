import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

const read = (name: string) =>
  readFileSync(new URL(`./${name}`, import.meta.url), "utf8");

/**
 * The phone half of the same wire.
 *
 * The wallet measures whether a network fee was quoted by the node or invented
 * from its own compiled-in floor. On the phone that reaches exactly one
 * surface, the pay preview, and nothing on the Rust side fails if the render
 * is removed.
 */
describe("a guessed network fee reaches the person paying it", () => {
  it("is rendered on the pay preview", () => {
    const pay = read("screens/PayTab.tsx");
    const index = pay.indexOf("preview.plan.fee_estimate_degraded");
    expect(index, "the pay screen never reads the warning").toBeGreaterThan(0);
    expect(pay).toContain("{preview.plan.fee_estimate_degraded}");
  });

  it("is typed on the payment plan the screen reads", () => {
    const api = read("api.ts");
    expect(api).toContain("fee_estimate_degraded?: string | null;");
  });
});

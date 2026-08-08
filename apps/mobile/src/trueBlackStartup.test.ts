import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

const styles = readFileSync(new URL("./agent/agent-wallet.css", import.meta.url), "utf8");

describe("mobile startup theme", () => {
  it("keeps wallet-space controls true black with gold-only emphasis", () => {
    expect(styles).toMatch(/\.wallet-space-switcher\s*{[^}]*background:\s*#000;/s);
    expect(styles).toMatch(/\.wallet-space-switcher button\s*{[^}]*background:\s*#000;/s);
    expect(styles).toMatch(
      /\.wallet-space-switcher button\.active\s*{[^}]*background:\s*#000;/s,
    );
  });
});
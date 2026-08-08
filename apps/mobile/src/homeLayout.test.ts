import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const HERE = dirname(fileURLToPath(import.meta.url));
const read = (path: string) => readFileSync(join(HERE, path), "utf8");

describe("mobile Home layout contract", () => {
  it("keeps Recent transactions, Fast Pay status and secondary tools out of the fixed Home viewport", () => {
    const home = read("screens/HomeTab.tsx");
    expect(home).not.toContain("mobile-activity-card");
    expect(home).not.toContain("Wallet tools");
    expect(home).not.toContain("Fast Pay status");
    expect(home).not.toContain("TxRecord");
    expect(home).toContain('<QuickAction kind="airgap"');
    expect(home).toContain('<QuickAction kind="chat"');
    expect(home).toContain('<QuickAction kind="hacd"');
    expect(home).toContain('<QuickAction kind="fastpay"');
  });

  it("opens the Menu page and labels the fifth navigation item from nav.more", () => {
    const app = read("MobileApp.tsx");
    const nav = read("components/BottomNav.tsx");
    expect(app).toContain('if (next === "more") setMorePage("menu")');
    expect(nav).toContain('if (item === "more") return t("nav.more")');
  });

  it("locks Home scrolling and gives each asset a spacious neutral panel", () => {
    const css = read("dashboard.css");
    expect(css).toMatch(/\.app-main-home\s*\{[^}]*overflow:\s*hidden;/s);
    expect(css).toMatch(/\.balance-asset-card\s*\{[^}]*min-height:\s*64px;[^}]*border:\s*1px solid #242424;/s);
    expect(css).toMatch(/\.balance-asset-heading \.asset-mark\s*\{[^}]*width:\s*32px;/s);
  });
});
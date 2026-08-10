import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const HERE = dirname(fileURLToPath(import.meta.url));
const read = (path: string) => readFileSync(join(HERE, path), "utf8");

describe("mobile Home layout contract", () => {
  /*
   * This contract was reversed on the owner's instruction, and the reversal is
   * deliberate rather than a test that drifted.
   *
   * Home used to be pinned to one viewport with overflow hidden, and recent
   * activity, Fast Pay status and the secondary tools were kept off it so that
   * everything fitted without scrolling. The owner asked for the screen in the
   * product design, which carries all three plus a way into the Agent Wallet,
   * and that cannot fit a fixed height on a phone.
   *
   * What survives from the old contract is the part that mattered: the balance
   * and the four actions still land above the fold. Only what was added sits
   * below it.
   */
  it("carries activity, Fast Pay and the Agent Wallet on Home, with Send and Receive as primary actions", () => {
    const home = read("screens/HomeTab.tsx");
    expect(home).toContain("mobile-activity-card");
    expect(home).toContain("Fast Pay status");
    expect(home).toContain("TxRecord");
    expect(home).toContain("AI Agent Wallet");

    // Send and Receive replaced air-gap signing and the messenger here, because
    // the two actions a wallet is opened for had no button on its home screen.
    // Neither tool was removed: both keep their entry under Menu.
    expect(home).toContain('<QuickAction kind="send"');
    expect(home).toContain('<QuickAction kind="receive"');
    expect(home).toContain('<QuickAction kind="hacd"');
    expect(home).toContain('<QuickAction kind="fastpay"');
  });

  /*
   * The Agent Wallet card states what the phone is, and must not grow figures
   * it cannot have. Reading an agent balance, a spend total or a pending count
   * needs the Agent Wallet's own key, which the Personal space does not hold,
   * so any such number on this card would be invented.
   */
  it("shows no agent balance, spend figure or pending count on the Home agent card", () => {
    const home = read("screens/HomeTab.tsx");
    expect(home).not.toMatch(/Agent (?:wallet )?balance/i);
    expect(home).not.toMatch(/autonomous action/i);
    expect(home).not.toMatch(/saved fees/i);
    expect(home).not.toMatch(/pending approvals/i);
  });

  it("opens the Menu page and labels the fifth navigation item from nav.more", () => {
    const app = read("MobileApp.tsx");
    const nav = read("components/BottomNav.tsx");
    expect(app).toContain('if (next === "more") setMorePage("menu")');
    expect(nav).toContain('if (item === "more") return t("nav.more")');
  });

  it("lets Home scroll and gives each asset a spacious neutral panel", () => {
    const css = read("dashboard.css");
    expect(css).toMatch(/\.app-main-home\s*\{[^}]*overflow-y:\s*auto;/s);
    // A fixed height would clip the sections added below the fold.
    expect(css).toMatch(/\.app-main-home\s*\{[^}]*min-height:/s);
    expect(css).toMatch(/\.balance-asset-card\s*\{[^}]*min-height:\s*64px;[^}]*border:\s*1px solid #242424;/s);
    expect(css).toMatch(/\.balance-asset-heading \.asset-mark\s*\{[^}]*width:\s*32px;/s);
  });
});
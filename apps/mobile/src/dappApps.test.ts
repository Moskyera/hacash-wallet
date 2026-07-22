import { describe, expect, it } from "vitest";
import {
  MONEYNEX_REINJECT_INTERVAL_MS,
  OWNED_HACD_BATCH_SIZE,
  WALLET_DAPP_CATALOG,
  canOpenDapp,
  createMoneyNexInjectScript,
  hacdExplorerUrl,
  isCatalogDappOrigin,
  normalizeOwnedHacdNames,
  ownedHacdVisibleBatch,
  shortWalletAddress,
  walletDappById,
} from "@hacash/wallet-ui";

describe("reviewed dApp catalog", () => {
  it("contains only compiled exact HTTPS origins", () => {
    expect(WALLET_DAPP_CATALOG).toHaveLength(1);
    expect(WALLET_DAPP_CATALOG[0]).toMatchObject({
      id: "hacd-launchpad",
      origin: "https://hacd.it",
      launchUrl: "https://hacd.it/launchpad",
    });
    expect(isCatalogDappOrigin("https://hacd.it")).toBe(true);
    expect(isCatalogDappOrigin("https://www.hacd.it")).toBe(false);
    expect(isCatalogDappOrigin("https://hacd.it.evil.example")).toBe(false);
    expect(walletDappById("unknown")).toBeNull();
  });

  it("allows opening an app only after an authorized connection", () => {
    expect(canOpenDapp({ status: "connected", address: "1Example" })).toBe(true);
    expect(canOpenDapp({ status: "checking" })).toBe(false);
    expect(canOpenDapp({ status: "disconnected" })).toBe(false);
    expect(canOpenDapp({ status: "connecting" })).toBe(false);
    expect(canOpenDapp({ status: "disconnecting", address: "1Example" })).toBe(false);
    expect(canOpenDapp({ status: "error" })).toBe(false);
  });

  it("builds the bridge from the current version and exposes disconnect", () => {
    const script = createMoneyNexInjectScript("v0.1.55");
    expect(script).toContain("version: \"0.1.55\"");
    expect(script).toContain("wallet_dapp_disconnect");
    expect(script).not.toContain("0.1.48");
    expect(MONEYNEX_REINJECT_INTERVAL_MS).toBeGreaterThanOrEqual(4_000);
    expect(MONEYNEX_REINJECT_INTERVAL_MS).toBeLessThanOrEqual(5_000);
  });
});

describe("owned HACD gallery inputs", () => {
  it("normalizes, validates, and de-duplicates node results", () => {
    expect(
      normalizeOwnedHacdNames([" eyueyz ", "EYUEYZ", "BAD", "W?TYU", "WTYUIA"]),
    ).toEqual(["EYUEYZ", "WTYUIA"]);
  });

  it("builds explorer links only for exact valid HACD names", () => {
    expect(hacdExplorerUrl(" eyueyz ")).toBe(
      "https://explorer.hacash.org/diamond/EYUEYZ",
    );
    expect(hacdExplorerUrl("W?TYU")).toBeNull();
    expect(hacdExplorerUrl("BAD")).toBeNull();
  });

  it("reveals owned metadata cards in bounded batches without hiding any", () => {
    const names = Array.from({ length: 29 }, (_, index) => `HACD-${index}`);
    const first = ownedHacdVisibleBatch(names, OWNED_HACD_BATCH_SIZE);
    expect(first.names).toHaveLength(12);
    expect(first.remaining).toBe(17);

    const second = ownedHacdVisibleBatch(names, OWNED_HACD_BATCH_SIZE * 2);
    expect(second.names).toHaveLength(24);
    expect(second.remaining).toBe(5);

    const all = ownedHacdVisibleBatch(names, OWNED_HACD_BATCH_SIZE * 3);
    expect(all.names).toEqual(names);
    expect(all.remaining).toBe(0);
  });

  it("shortens only long wallet addresses", () => {
    expect(shortWalletAddress("short-address")).toBe("short-address");
    expect(shortWalletAddress("1LFPqztfKhamVuzzV5WV6pHfykktGD5pMW")).toBe(
      "1LFPqztfKh...ktGD5pMW",
    );
  });
});

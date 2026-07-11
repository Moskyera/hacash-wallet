import { describe, expect, it } from "vitest";
import {
  clearPendingDeepLinks,
  parseUrlPay,
  stashDeepLinkUrl,
  takePendingDeepLinkUrl,
} from "./deepLink";

const ADDR = "1MzNY1oA3kfgYi75zquj3SRUPYztzXHzK9";

describe("parseUrlPay", () => {
  it("parses hacash:// native scheme with amount", () => {
    const payload = parseUrlPay(`hacash://${ADDR}?amount=12.5&label=Alice`);
    expect(payload).toEqual({
      address: ADDR,
      amount_mei: 12.5,
      label: "Alice",
    });
  });

  it("parses hacd:// native scheme", () => {
    const payload = parseUrlPay(`hacd://${ADDR}`);
    expect(payload).toEqual({ address: ADDR, amount_mei: undefined, label: undefined });
  });

  it("rejects invalid hacash address", () => {
    expect(parseUrlPay("hacash://bc1qtest")).toBeNull();
  });

  it("parses pay query on https URL", () => {
    const encoded = encodeURIComponent(`${ADDR}?amount=3`);
    const payload = parseUrlPay(`https://wallet.example/?pay=${encoded}`);
    expect(payload?.address).toBe(ADDR);
    expect(payload?.amount_mei).toBe(3);
  });
});

describe("pending deep link queue", () => {
  it("stashes and takes URLs in order", () => {
    clearPendingDeepLinks();
    stashDeepLinkUrl(`hacash://${ADDR}?amount=1`);
    stashDeepLinkUrl(`hacash://${ADDR}?amount=2`);
    expect(takePendingDeepLinkUrl()).toBe(`hacash://${ADDR}?amount=1`);
    expect(takePendingDeepLinkUrl()).toBe(`hacash://${ADDR}?amount=2`);
    expect(takePendingDeepLinkUrl()).toBeNull();
  });
});
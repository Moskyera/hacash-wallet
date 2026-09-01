import { describe, expect, it } from "vitest";
import type { ParsedAddress } from "@hacash/wallet-ui";
import { PEER_HAS_NO_INBOX_TEXT, peerRefusal } from "./messengerPeer";

function parsed(overrides: Partial<ParsedAddress> = {}): ParsedAddress {
  return {
    address: "1AVRUVLKKCrzMBtwvbcUgsQBd9JJmvNRT8",
    version: 0,
    kind: "private_key",
    network_mode: "mainnet",
    network_allowed: true,
    passive_receive: true,
    fast_pay_eligible: true,
    warning: null,
    ...overrides,
  };
}

describe("messenger recipients", () => {
  it("opens a conversation with an ordinary account address", () => {
    expect(peerRefusal(parsed())).toBeNull();
  });

  it("refuses every address kind that has no key to claim an inbox", () => {
    for (const kind of ["contract", "p2sh", "pqc", "hybrid"] as const) {
      expect(peerRefusal(parsed({ kind, version: 1 }))).toBe(PEER_HAS_NO_INBOX_TEXT);
    }
  });
});

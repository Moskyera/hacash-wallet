import { describe, expect, it } from "vitest";
import {
  MAX_TRANSACTION_HEX_CHARS,
  addressKindMessageKey,
  addressWarningMessageKey,
  assessIstanbulNode,
  isInspectableTransactionHex,
  istanbulFeatureMessageKey,
  normalizeTransactionHex,
  reconcileAddressDraft,
  type NodeCapabilities,
  type NodeFeatureFlags,
  type ParsedAddress,
} from "@hacash/wallet-ui";

type CapabilityOverrides = Omit<
  Partial<NodeCapabilities>,
  "features" | "istanbul" | "transactions"
> & {
  features?: Partial<NodeFeatureFlags>;
  istanbul?: Partial<NodeCapabilities["istanbul"]>;
  transactions?: Partial<NodeCapabilities["transactions"]>;
};

function capabilities(overrides: CapabilityOverrides = {}): NodeCapabilities {
  const base: NodeCapabilities = {
    ret: 0,
    api_version: 1,
    node: { name: "hacash-fullnode", version: "1.0.10", build_time: "test" },
    chain: { id: 0, height: 765_500, next_height: 765_501, mainnet: true },
    istanbul: { activation_height: 765_432, evaluation_height: 765_501, active: true },
    transactions: { registered: [1, 2, 3], enabled: [1, 2, 3] },
    actions: { registered: [16, 17, 18, 19, 22, 25, 26, 40, 41, 44, 46], enabled: [16, 17, 18, 19, 22, 25, 26, 40, 41, 44, 46] },
    features: {
      action_guard: true,
      tx_blob: true,
      ast: true,
      tex: true,
      native_assets: true,
      hip20_primitives: true,
      hip20: false,
      hvm: true,
      p2sh: true,
      account_abstraction: true,
      intent: true,
      contract_state_leasing: true,
      ir_decompilation: false,
      req_sign_list: true,
      type4_mainnet: false,
      exact_unsigned_simulation: false,
    },
    limits: {
      max_tx_size: 262_144,
      max_tx_actions: 200,
      max_type3_signers: 16,
      gas_max_byte: 255,
      gas_max: 1_000_000,
      ast_depth: 6,
    },
    source: "reported",
  };

  return {
    ...base,
    ...overrides,
    features: { ...base.features, ...overrides.features },
    istanbul: { ...base.istanbul, ...overrides.istanbul },
    transactions: { ...base.transactions, ...overrides.transactions },
  };
}

function parsedAddress(overrides: Partial<ParsedAddress> = {}): ParsedAddress {
  return {
    address: "18fT8iUWkcsJaKrQRVVad6BtRTt3GteZHa",
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

describe("Istanbul node readiness", () => {
  it("accepts the honest 1.0.10 feature set without claiming unfinished HIP-20", () => {
    const value = capabilities();
    expect(assessIstanbulNode(value)).toEqual({ status: "ready", missing: [] });
    expect(value.features.hip20).toBe(false);
    expect(istanbulFeatureMessageKey("hip20_primitives")).toBe("istanbul.feature.hip20_primitives");
    expect(istanbulFeatureMessageKey("hip20")).toBe("istanbul.feature.hip20");
  });

  it("fails closed when the capability endpoint is unavailable", () => {
    const result = assessIstanbulNode(capabilities({ source: "legacy_type2" }));
    expect(result.status).toBe("legacy");
    expect(result.missing).toContain("req_sign_list");
  });

  it("reports missing required capability without enabling Type 3 readiness", () => {
    const result = assessIstanbulNode(capabilities({ features: { req_sign_list: false } }));
    expect(result.status).toBe("partial");
    expect(result.missing).toEqual(["req_sign_list"]);
  });

  it("does not mark a pre-activation node ready", () => {
    const result = assessIstanbulNode(capabilities({ istanbul: { active: false } }));
    expect(result.status).toBe("inactive");
  });
});

describe("read-only Istanbul input helpers", () => {
  it("normalizes copied transaction hex without changing bytes", () => {
    expect(normalizeTransactionHex(" 0x01 02\n03 ")).toBe("010203");
    expect(isInspectableTransactionHex("0x01 02 03")).toBe(true);
  });

  it("rejects malformed, odd or oversized transaction hex", () => {
    expect(isInspectableTransactionHex("")).toBe(false);
    expect(isInspectableTransactionHex("123")).toBe(false);
    expect(isInspectableTransactionHex("zz")).toBe(false);
    expect(isInspectableTransactionHex("aa".repeat(MAX_TRANSACTION_HEX_CHARS / 2 + 1))).toBe(false);
  });

  it("uses stable locale keys for consensus terms", () => {
    expect(addressKindMessageKey("private_key")).toBe("istanbul.address.kind.private_key");
    expect(addressKindMessageKey("p2sh")).toBe("istanbul.address.kind.p2sh");
    expect(addressKindMessageKey("hybrid")).toBe("istanbul.address.kind.hybrid");
  });

  it("maps protocol warnings to localized categories without rendering node copy", () => {
    expect(addressWarningMessageKey(parsedAddress())).toBeNull();
    expect(addressWarningMessageKey(parsedAddress({ kind: "contract", warning: "node text" })))
      .toBe("istanbul.address.warning.contract");
    expect(addressWarningMessageKey(parsedAddress({
      kind: "pqc",
      network_allowed: false,
      warning: "node text",
    }))).toBe("istanbul.address.warning.quantumMainnet");
    expect(addressWarningMessageKey(parsedAddress({ warning: "node text" })))
      .toBe("istanbul.address.warning.generic");
  });

  it("preserves a draft until the current-address prop actually changes", () => {
    expect(reconcileAddressDraft("user draft", "current", "current")).toBe("user draft");
    expect(reconcileAddressDraft("user draft", " current ", "current")).toBe("user draft");
    expect(reconcileAddressDraft("user draft", "old", " new ")).toBe("new");
  });
});

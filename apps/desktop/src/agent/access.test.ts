import { describe, expect, it } from "vitest";
import type { AgentRuntimeStatus, AgentWalletOverview } from "./api";
import {
  HPAY_LOCAL_PILOT,
  agentWalletLocalEnableBlockers,
  agentWalletPairingBlockers,
  agentWalletPaymentBlockers,
  agentWalletUiState,
  emergencyStopControl,
} from "./access";

const runtime = (overrides: Partial<AgentRuntimeStatus> = {}): AgentRuntimeStatus => ({
  available: true,
  pilot_enabled: true,
  application_version: "1.0.2",
  build_profile: "release",
  error: null,
  wallets: [{ wallet_id: "wallet_one", address: "1Agent", created_at_unix: 1 }],
  connector: { phase: "stopped", walletId: null, endpoint: null, lastError: null },
  ...overrides,
});

const overview = (overrides: Partial<AgentWalletOverview> = {}): AgentWalletOverview => ({
  wallet_id: "wallet_one",
  address: "1Agent",
  network_mode: "testnet",
  node_url: HPAY_LOCAL_PILOT.nodeUrl,
  block_one_fingerprint: HPAY_LOCAL_PILOT.blockOne,
  node: {
    node_name: "hacash-fullnode",
    node_version: "1.0.10",
    network_kind: HPAY_LOCAL_PILOT.networkKind,
    node_profile_id: HPAY_LOCAL_PILOT.profileId,
    chain_id: 7,
    mainnet: false,
    current_height: 12,
    block_one_fingerprint: HPAY_LOCAL_PILOT.blockOne,
    network_instance_id: HPAY_LOCAL_PILOT.networkInstance,
    funding_confirmed: true,
    transaction_ready: true,
    transaction_format_version: 2,
  },
  node_status: "verified",
  node_error: null,
  unlocked: true,
  payments_suspended: false,
  mainnet_spending_ready: true,
  confirmed_balance_units: "1000000",
  reserved_units: "0",
  available_units: "1000000",
  spent_today_units: "0",
  spent_this_month_units: "0",
  authorized_agents: 0,
  pending_approvals: 0,
  pilot_enabled: true,
  mobile_witness_ready: true,
  mobile_witness_synchronized: true,
  latest_anchor_sequence: 1,
  witness_rotation_phase: null,
  unresolved_signed_operations: 0,
  stale: false,
  ...overrides,
});

describe("Agent Wallet UI access is independent from write readiness", () => {
  it("shows the explicit non-pilot state without selecting My Wallet", () => {
    expect(agentWalletUiState(runtime({ pilot_enabled: false }), null)).toBe(
      "unavailable_in_this_build",
    );
  });

  it("opens creation without a wallet, node, mobile or funds", () => {
    expect(agentWalletUiState(runtime({ wallets: [] }), null)).toBe("not_created");
  });

  it("opens unlock independently of network readiness", () => {
    expect(agentWalletUiState(runtime(), null)).toBe("locked");
  });

  it.each([
    ["offline node", { node_status: "offline" as const, node: null }],
    ["missing block one", { block_one_fingerprint: null }],
    ["zero balance", { confirmed_balance_units: "0" }],
    ["missing mobile", { mobile_witness_ready: false }],
    ["missing witness", { mobile_witness_synchronized: false }],
    ["mainnet node", { node: { ...overview().node!, mainnet: true } }],
  ])("keeps the dashboard open read-only for %s", (_label, change) => {
    expect(agentWalletUiState(runtime(), overview(change))).toBe("read_only");
  });

  it("reports every independent blocker instead of one readiness boolean", () => {
    const blockers = agentWalletPaymentBlockers(
      runtime(),
      overview({
        confirmed_balance_units: "0",
        mobile_witness_ready: false,
        mobile_witness_synchronized: false,
        payments_suspended: true,
        node: { ...overview().node!, funding_confirmed: false, transaction_ready: false },
      }),
    );
    expect(blockers).toEqual([
      "node_not_ready",
      "wallet_not_funded",
      "mobile_not_paired",
      "witness_not_initialized",
      "payments_suspended",
    ]);
  });

  it("becomes available only when every write prerequisite is satisfied", () => {
    expect(agentWalletUiState(runtime(), overview())).toBe("available");
  });
});

/**
 * The complete payment prerequisite set, one fixture per member, each fixture
 * isolating exactly one fault.
 *
 * This is the regression lock the task asks for: deleting any single condition
 * from `agentWalletPaymentBlockers` makes its row fail. A future edit cannot
 * quietly loosen the payment gate.
 */
type NodeInfo = NonNullable<AgentWalletOverview["node"]>;
/** A single isolated fault: runtime fields, overview fields and node fields. */
type PaymentBlockerCase = [
  string,
  Partial<AgentRuntimeStatus>,
  Partial<Omit<AgentWalletOverview, "node">>,
  Partial<NodeInfo>,
];

const PAYMENT_BLOCKER_CASES: PaymentBlockerCase[] = [
  ["disabled_by_build", { pilot_enabled: false }, {}, {}],
  ["missing_block_one", {}, { block_one_fingerprint: null }, {}],
  ["wrong_network", {}, {}, { mainnet: true }],
  ["node_not_ready", {}, {}, { transaction_ready: false }],
  ["wallet_not_funded", {}, { confirmed_balance_units: "0" }, {}],
  ["mobile_not_paired", {}, { mobile_witness_ready: false }, {}],
  ["witness_not_initialized", {}, { mobile_witness_synchronized: false }, {}],
  ["payments_suspended", {}, { payments_suspended: true }, {}],
  ["recovery_required", {}, { unresolved_signed_operations: 1 }, {}],
];

const faulted = (
  overviewChange: Partial<Omit<AgentWalletOverview, "node">>,
  nodeChange: Partial<NodeInfo>,
): AgentWalletOverview =>
  overview({ ...overviewChange, node: { ...overview().node!, ...nodeChange } });

describe("the payment gate keeps every prerequisite it has today", () => {
  it.each(PAYMENT_BLOCKER_CASES)(
    "still refuses a payment for %s on its own",
    (blocker, runtimeChange, overviewChange, nodeChange) => {
      expect(
        agentWalletPaymentBlockers(runtime(runtimeChange), faulted(overviewChange, nodeChange)),
      ).toContain(blocker);
    },
  );

  it("enumerates the whole payment set so no member can be dropped silently", () => {
    expect(PAYMENT_BLOCKER_CASES.map(([blocker]) => blocker)).toEqual([
      "disabled_by_build",
      "missing_block_one",
      "wrong_network",
      "node_not_ready",
      "wallet_not_funded",
      "mobile_not_paired",
      "witness_not_initialized",
      "payments_suspended",
      "recovery_required",
    ]);
    // Node faults accumulate rather than overwrite one another, so a single
    // fixture can carry every fault at once and independence is really tested.
    const everyFault = PAYMENT_BLOCKER_CASES.reduce(
      (accumulated, [, runtimeChange, overviewChange, nodeChange]) => ({
        runtime: { ...accumulated.runtime, ...runtimeChange },
        overview: { ...accumulated.overview, ...overviewChange },
        node: { ...accumulated.node, ...nodeChange },
      }),
      { runtime: {}, overview: {}, node: {} } as {
        runtime: Partial<AgentRuntimeStatus>;
        overview: Partial<Omit<AgentWalletOverview, "node">>;
        node: Partial<NodeInfo>;
      },
    );
    const blockers = agentWalletPaymentBlockers(
      runtime(everyFault.runtime),
      faulted(everyFault.overview, everyFault.node),
    );
    for (const [blocker] of PAYMENT_BLOCKER_CASES) {
      // wrong_network and node_not_ready are mutually exclusive by design: a
      // mismatched network short-circuits the node check. Every other member
      // must be reported independently.
      if (blocker === "node_not_ready") continue;
      expect(blockers).toContain(blocker);
    }
  });

  it("reports nothing when every payment prerequisite is satisfied", () => {
    expect(agentWalletPaymentBlockers(runtime(), overview())).toEqual([]);
  });
});

describe("clearing the emergency stop is a local desktop action, not a payment", () => {
  /** The exact state observed on this machine. */
  const deadlocked = () =>
    overview({
      payments_suspended: true,
      mobile_witness_ready: false,
      mobile_witness_synchronized: false,
      confirmed_balance_units: "0",
      available_units: "0",
      node_status: "offline",
      node: null,
    });

  it("is possible with no phone paired, an offline node and an unfunded wallet", () => {
    expect(agentWalletLocalEnableBlockers(runtime(), deadlocked())).toEqual([]);
  });

  it.each<[string, Partial<AgentWalletOverview>]>([
    ["no paired phone", { mobile_witness_ready: false }],
    ["an uninitialized witness", { mobile_witness_synchronized: false }],
    ["a node that is not transaction-ready", {
      node: { ...overview().node!, transaction_ready: false },
    }],
    ["an offline node", { node_status: "offline", node: null }],
    ["a zero balance", { confirmed_balance_units: "0" }],
  ])("does not require %s", (_label, change) => {
    expect(
      agentWalletLocalEnableBlockers(runtime(), overview({ payments_suspended: true, ...change })),
    ).toEqual([]);
  });

  it("is still refused when an unresolved signed operation requires recovery", () => {
    expect(
      agentWalletLocalEnableBlockers(
        runtime(),
        overview({ payments_suspended: true, unresolved_signed_operations: 1 }),
      ),
    ).toContain("recovery_required");
  });

  it.each<[string, Partial<AgentRuntimeStatus>, Partial<AgentWalletOverview>]>([
    ["a non-pilot build", { pilot_enabled: false }, {}],
    ["a wallet with no network anchor", {}, { block_one_fingerprint: null }],
    ["a mainnet node", {}, { node: { ...overview().node!, mainnet: true } }],
    ["a mismatched network", {}, { node_status: "network_mismatch" }],
  ])("is still refused for %s", (_label, runtimeChange, overviewChange) => {
    expect(
      agentWalletLocalEnableBlockers(
        runtime(runtimeChange),
        overview({ payments_suspended: true, ...overviewChange }),
      ).length,
    ).toBeGreaterThan(0);
  });

  it("never lists the suspension itself as an obstacle to clearing it", () => {
    expect(
      agentWalletLocalEnableBlockers(runtime(), overview({ payments_suspended: true })),
    ).not.toContain("payments_suspended");
  });

  it("escapes the circular deadlock through the interface", () => {
    // The exact state on this machine: emergency stop set, device revoked, no
    // paired phone, node not transaction-ready. Pairing a phone was refused
    // because of the stop, and clearing the stop was refused because no phone
    // was paired.
    const stuck = deadlocked();

    // Before: pairing is refused, and it now names the way out.
    const pairing = agentWalletPairingBlockers(runtime(), stuck);
    expect(pairing).toContain("payments_suspended");

    // The escape: the Enable locally control is present and pressable.
    const control = emergencyStopControl({
      paymentsSuspended: stuck.payments_suspended,
      busy: false,
      localEnableBlockers: agentWalletLocalEnableBlockers(runtime(), stuck),
    });
    expect(control.action).toBe("enable");
    expect(control.disabled).toBe(false);

    // After: with the stop cleared, pairing is no longer refused, so the owner
    // can pair the phone and the payment path re-arms on its own terms.
    const cleared = { ...stuck, payments_suspended: false };
    expect(agentWalletPairingBlockers(runtime(), cleared)).toEqual([]);
    // The payment gate is untouched: it still refuses everything it refused.
    expect(agentWalletPaymentBlockers(runtime(), cleared)).toEqual([
      "node_not_ready",
      "wallet_not_funded",
      "mobile_not_paired",
      "witness_not_initialized",
    ]);
  });

  it("keeps a disabled Enable locally button explaining itself in its own terms", () => {
    const control = emergencyStopControl({
      paymentsSuspended: true,
      busy: false,
      localEnableBlockers: agentWalletLocalEnableBlockers(
        runtime(),
        overview({ payments_suspended: true, unresolved_signed_operations: 1 }),
      ),
    });
    expect(control.disabled).toBe(true);
    expect(control.reason).toMatch(/recovered before agent payments can be re-enabled/);
    // Payment prose must never be the stated reason for a non-payment action.
    expect(control.reason).not.toMatch(/before a test payment/);
  });

  it("never gates engaging the stop, so fail-closed stays reachable", () => {
    expect(
      emergencyStopControl({
        paymentsSuspended: false,
        busy: false,
        localEnableBlockers: ["recovery_required"],
      }),
    ).toMatchObject({ action: "disable", disabled: false });
  });
});

describe("pairing a phone is gated only on what pairing genuinely needs", () => {
  it.each<[string, Partial<AgentWalletOverview>]>([
    ["a paired phone", { mobile_witness_ready: false }],
    ["a synchronized witness", { mobile_witness_synchronized: false }],
    ["a transaction-ready node", {
      node: { ...overview().node!, transaction_ready: false },
    }],
    ["an online node", { node_status: "offline", node: null }],
    ["a funded wallet", { confirmed_balance_units: "0" }],
    ["a network anchor", { block_one_fingerprint: null }],
  ])("does not require %s", (_label, change) => {
    expect(agentWalletPairingBlockers(runtime(), overview(change))).toEqual([]);
  });

  it("mirrors the Rust refusal while the emergency stop is engaged", () => {
    expect(
      agentWalletPairingBlockers(runtime(), overview({ payments_suspended: true })),
    ).toEqual(["payments_suspended"]);
  });

  it("mirrors the Rust refusal while recovery is required", () => {
    expect(
      agentWalletPairingBlockers(runtime(), overview({ unresolved_signed_operations: 1 })),
    ).toEqual(["recovery_required"]);
  });

  it("refuses in a non-pilot build where no companion command exists", () => {
    expect(
      agentWalletPairingBlockers(runtime({ pilot_enabled: false }), overview()),
    ).toEqual(["disabled_by_build"]);
  });
});

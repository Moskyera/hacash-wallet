import { describe, expect, it } from "vitest";
import type { AgentRuntimeStatus, AgentWalletOverview } from "./api";
import { readFileSync } from "node:fs";
import {
  APPROVE_OUTCOME_NOTICE,
  HPAY_LOCAL_PILOT,
  agentWalletLocalEnableBlockers,
  agentWalletPairingBlockers,
  agentWalletPaymentBlockers,
  agentWalletUiState,
  approvalOutcome,
  approvalResultNotice,
  emergencyStopControl,
  pairingRefusalText,
  rotationBlocksAgentWrites,
} from "./access";
import type { WitnessRotationPhase } from "./api";

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
  trusted_mainnet_fast_pay_pilot: false,
  l2_binding: null,
  hvm_channel_binding: null,
  hvm_registry_binding: null,
  l2_channel_setup: null,
  l2_channel_close: null,
  l2_channel_close_voucher: null,
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
    ["wrong-network mainnet node", { node: { ...overview().node!, mainnet: true } }],
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

  it("accepts an exact verified mainnet node only with authenticated pilot consent", () => {
    const mainnet = overview({
      network_mode: "mainnet",
      mainnet_spending_ready: true,
      trusted_mainnet_fast_pay_pilot: true,
      block_one_fingerprint:
        "001e231cb03f9938d54f04407797b8188f0375eb10f0bcb426dccae87dcadb56",
      node: {
        ...overview().node!,
        chain_id: 0,
        mainnet: true,
        current_height: 765_432,
        network_kind: "mainnet",
        node_profile_id: "hacash-mainnet",
        funding_confirmed: false,
        block_one_fingerprint:
          "001e231cb03f9938d54f04407797b8188f0375eb10f0bcb426dccae87dcadb56",
      },
    });
    expect(agentWalletPaymentBlockers(runtime(), mainnet)).toEqual([]);
    expect(
      agentWalletPaymentBlockers(runtime(), {
        ...mainnet,
        trusted_mainnet_fast_pay_pilot: false,
        mainnet_spending_ready: false,
      }),
    ).toContain("mainnet_consent_missing");
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


/**
 * The desktop offers the Approve control again, and everything printed around
 * it has to be true in the state it is printed in.
 *
 * `approve_desktop_and_broadcast` no longer refuses every desktop approval
 * under `agent-wallet-testnet-pilot`. What it does instead is build-dependent
 * in exactly one way: a pilot approval signs and stops at
 * `signed_awaiting_witness`, and the payment reaches the network only after the
 * paired phone witnesses it. Rust pins the whole path in
 * crates/agent-wallet-core/src/service/companion/tests/desktop_witness_flow.rs.
 */
describe("the desktop says what approving actually does", () => {
  it("names the pilot outcome as signing that stops for the phone", () => {
    expect(approvalOutcome(overview({ pilot_enabled: true }))).toBe(
      "signs_then_waits_for_the_phone",
    );
    expect(approvalOutcome(overview({ pilot_enabled: false }))).toBe(
      "signs_and_broadcasts",
    );
  });

  it("keys on the build and nothing else", () => {
    // Not payment readiness, not the emergency stop, not the phone, not the
    // node. Whether an individual approval succeeds is Rust's decision and
    // carries its own message; this only says what a success means.
    for (const irrelevant of [
      { payments_suspended: true },
      { mobile_witness_ready: false },
      { confirmed_balance_units: "0" },
      { node_status: "offline" as const },
    ]) {
      expect(
        approvalOutcome(overview({ pilot_enabled: true, ...irrelevant })),
      ).toBe("signs_then_waits_for_the_phone");
    }
  });

  it("never claims a pilot approval pays anyone", () => {
    const pilot = APPROVE_OUTCOME_NOTICE.signs_then_waits_for_the_phone;
    expect(pilot).toContain("signs this exact transaction and then stops");
    expect(pilot).toContain("Nothing is sent to the network");
    expect(pilot).toContain("confirm it on your paired phone");
    // It must hold in the state where no phone is paired yet, which is the one
    // state a yes is refused outright. Rust refuses before signing there.
    expect(pilot).toContain("nothing is signed");
    expect(pilot).not.toMatch(/submitted|broadcast to the network/i);
  });

  it("says the non-pilot outcome plainly and differently", () => {
    const direct = APPROVE_OUTCOME_NOTICE.signs_and_broadcasts;
    expect(direct).toContain("submits it to the network");
    expect(direct).not.toBe(
      APPROVE_OUTCOME_NOTICE.signs_then_waits_for_the_phone,
    );
  });

  it("reports the result from the status Rust returned, not from the build", () => {
    // The old code printed "was submitted" for every success. A pilot approval
    // succeeds into signed_awaiting_witness, where nothing was submitted.
    const awaiting = approvalResultNotice("signed_awaiting_witness");
    expect(awaiting).toContain("Nothing has been sent to the network yet");
    expect(awaiting).toContain("paired phone");
    expect(awaiting).not.toMatch(/was submitted/);

    expect(approvalResultNotice("submitted_awaiting_final_witness")).toBe(
      "The exact approved transaction was submitted.",
    );
    expect(approvalResultNotice("broadcast_submitted")).toBe(
      "The exact approved transaction was submitted.",
    );
    expect(approvalResultNotice("broadcast_uncertain")).toContain(
      "Do not retry automatically",
    );
    // A recorded approval whose signing did not happen must not read as a
    // payment either.
    expect(approvalResultNotice("approved")).toContain("has not been signed");
    // Anything else names the state rather than inventing an outcome.
    expect(approvalResultNotice("recovery_required")).toContain(
      "recovery required",
    );
  });

  it("renders the control and its outcome notice, out of any disclosure", () => {
    const view = readFileSync(
      new URL("./AgentAdminPages.tsx", import.meta.url),
      "utf8",
    );
    expect(view).toContain("DESKTOP_CONTROLS.approve_exact_transaction");
    expect(view).toContain("{APPROVE_OUTCOME_NOTICE[approvalOutcome(overview)]}");
    // The old build gate is gone from the view entirely, so the control cannot
    // be hidden by it again without this failing.
    expect(view).not.toContain("approvalSurface");
    expect(view).not.toContain("APPROVAL_UNAVAILABLE_NOTICE");
    // The success sentence is no longer a literal in the view: it comes from
    // the returned status.
    expect(view).toContain("approvalResultNotice(result.status)");
    expect(view).not.toContain("The exact approved transaction was submitted.");
  });

  it("keeps review and reject beside it", () => {
    const view = readFileSync(
      new URL("./AgentAdminPages.tsx", import.meta.url),
      "utf8",
    );
    expect(view).toContain("DESKTOP_CONTROLS.review_exact_transaction");
    expect(view).toContain("DESKTOP_CONTROLS.reject_payment");
  });
});


/* -------------------------------------------------------------------------- */
/* The rotation that refuses every payment and said nothing                     */
/* -------------------------------------------------------------------------- */

/**
 * Every phase the protocol enum declares, read from the Rust source rather
 * than retyped, so a phase added there and not handled here fails the build.
 */
const ROTATION_PHASES_FROM_RUST: WitnessRotationPhase[] = (() => {
  const source = readFileSync(
    new URL("../../../../crates/companion-protocol/src/rotation.rs", import.meta.url),
    "utf8",
  );
  const body = source
    .split("pub enum WitnessRotationPhase {")[1]
    .split("}")[0];
  return body
    .split("\n")
    .map((line) => line.trim().replace(/,$/, ""))
    .filter((line) => /^[A-Z][A-Za-z]*$/.test(line))
    .map(
      (variant) =>
        variant
          .replace(/([a-z0-9])([A-Z])/g, "$1_$2")
          .toLowerCase() as WitnessRotationPhase,
    );
})();

describe("a rotation in progress is reported as what blocks the payment", () => {
  it("mirrors permits_agent_writes exactly, phase by phase", () => {
    // create_payment_intent refuses every intent while the phase is not Stable
    // or Completed (crates/agent-wallet-core/src/service/payment.rs), and the
    // agent is told the wallet needs manual recovery. This desktop printed
    // "Agent payments: ready" for all of them.
    expect(ROTATION_PHASES_FROM_RUST.length).toBeGreaterThan(15);
    for (const phase of ROTATION_PHASES_FROM_RUST) {
      const writesPermitted = phase === "stable" || phase === "completed";
      expect(
        rotationBlocksAgentWrites(phase),
        `${phase} disagrees with WitnessRotationPhase::permits_agent_writes`,
      ).toBe(!writesPermitted);
      expect(
        agentWalletPaymentBlockers(
          runtime(),
          overview({ witness_rotation_phase: phase }),
        ).includes("rotation_in_progress"),
        `${phase} is reported as ready to pay`,
      ).toBe(!writesPermitted);
    }
    expect(rotationBlocksAgentWrites(null)).toBe(false);
  });

  it("leaves a healthy wallet with no blocker at all", () => {
    expect(agentWalletPaymentBlockers(runtime(), overview())).toEqual([]);
  });

  it("does not pretend a rotation blocks the stop or the pairing", () => {
    // Neither enable_agent_payments_locally nor start_companion_pairing
    // consults the rotation, so claiming otherwise would be a new refusal.
    const rotating = overview({ witness_rotation_phase: "awaiting_completion_anchor" });
    expect(agentWalletLocalEnableBlockers(runtime(), rotating)).toEqual([]);
    expect(agentWalletPairingBlockers(runtime(), rotating)).toEqual([]);
  });
});

describe("the pairing refusal never names an escape route that is closed", () => {
  it("says so when Enable locally is itself refused", () => {
    // The stop blocks pairing, and PAIRING_BLOCKER_LABELS tells the owner to
    // clear it first. With a wrong network that control is disabled, so the
    // instruction named a control that is refused.
    const suspended = overview({
      payments_suspended: true,
      network_mode: "mainnet" as AgentWalletOverview["network_mode"],
    });
    const pairing = agentWalletPairingBlockers(runtime(), suspended);
    const enable = agentWalletLocalEnableBlockers(runtime(), suspended);
    expect(pairing).toContain("payments_suspended");
    expect(enable).toContain("wrong_network");

    const text = pairingRefusalText(pairing, enable);
    expect(text).toContain("Clear the emergency stop in Payment control first");
    expect(text).toContain("Enable locally is unavailable too");
    // And it must carry the actual reason, not merely say "unavailable".
    expect(text).toContain("does not match this Agent Wallet network");
    // The control the sentence names is genuinely disabled in that state.
    expect(
      emergencyStopControl({
        paymentsSuspended: true,
        busy: false,
        localEnableBlockers: enable,
      }).disabled,
    ).toBe(true);
  });

  it("adds nothing while the route it names is open", () => {
    const suspended = overview({ payments_suspended: true });
    const pairing = agentWalletPairingBlockers(runtime(), suspended);
    const enable = agentWalletLocalEnableBlockers(runtime(), suspended);
    expect(enable).toEqual([]);
    expect(pairingRefusalText(pairing, enable)).not.toContain(
      "Enable locally is unavailable too",
    );
    expect(
      emergencyStopControl({
        paymentsSuspended: true,
        busy: false,
        localEnableBlockers: enable,
      }).disabled,
    ).toBe(false);
  });

  it("says nothing at all when pairing is not blocked", () => {
    expect(pairingRefusalText([], ["wrong_network"])).toBe("");
  });
});

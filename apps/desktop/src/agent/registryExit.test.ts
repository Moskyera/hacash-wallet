import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import {
  EXIT_BLOCK_SECONDS,
  EXIT_CHAIN_FEE_COUNT,
  registryExitView,
  type AgentHvmRegistryExitStatus,
} from "./registryExit";
import { DESKTOP_CONTROLS } from "./desktopControls";
import {
  DESKTOP_IRREVERSIBLE_ACTIONS,
  EXIT_WITHOUT_PROVIDER_WARNING,
} from "./irreversibleActions";
import type {
  AgentHvmPaymentOperation,
  AgentHvmRegistryBinding,
} from "./api";

const readRaw = (name: string) =>
  readFileSync(new URL(`./${name}`, import.meta.url), "utf8");

/** Comments are not a rendered control and must not satisfy a render check. */
const read = (name: string) =>
  readRaw(name)
    .replace(/\/\*[\s\S]*?\*\//g, " ")
    .replace(/^[ \t]*\/\/.*$/gm, " ");

const flatten = (source: string) => source.replace(/\s+/g, " ");

/** How deep inside <details> an index sits. 0 means always visible. */
function disclosureDepth(source: string, index: number): number {
  const before = source.slice(0, index);
  return before.split("<details").length - before.split("</details>").length;
}

function formatUnits(raw: string): string {
  return `${raw} HAC`;
}

function binding(
  overrides: Partial<AgentHvmRegistryBinding["recovery_bundle"]["binding"]> = {},
): AgentHvmRegistryBinding {
  return {
    schema_version: 2,
    wallet_id: "wallet-1",
    network_mode: "testnet",
    network_binding: {} as AgentHvmRegistryBinding["network_binding"],
    hub_url: "http://127.0.0.1:8790",
    hub_address: "1HubAddressAAAAAAAAAAAAAAAAAAAAAAA",
    binding_commitment: "a".repeat(64),
    recovery_bundle: {
      schema: "hpay-registry-recovery-bundle-v2",
      binding: {
        schema: "hpay-registry-binding-v2",
        settlement_profile: "hpay-hvm-shared-registry-v2",
        network_mode: "testnet",
        chain_id: 7,
        network_instance_id: "1".repeat(64),
        contract_address: "1ContractAAAAAAAAAAAAAAAAAAAAAAAAA",
        deployment_tx_hash: "2".repeat(64),
        deployment_height: 2,
        bytecode_sha3: "3".repeat(64),
        channel_id: "4".repeat(32),
        reuse_version: 0,
        left_address: "1UserAddressAAAAAAAAAAAAAAAAAAAAAA",
        right_hub_address: "1HubAddressAAAAAAAAAAAAAAAAAAAAAAA",
        left_deposit_zhu: 1_000_000,
        right_hub_deposit_zhu: 0,
        challenge_blocks: 12,
        ...overrides,
      },
      initial_recovery_bill: {
        schema: "hpay-registry-bill-v2",
        binding_commitment: "a".repeat(64),
        serial: 1,
        left_balance_zhu: 1_000_000,
        hub_balance_zhu: 0,
        left_signature_hex: "5".repeat(128),
        hub_signature_hex: "6".repeat(128),
      },
    },
    activation_snapshot_commitment: "7".repeat(64),
    minimum_required_live_blocks: 500,
    minimum_required_recover_blocks: 100,
    adopted_at: 1_700_000_000,
  };
}

function operation(
  amount_zhu: number,
  status: AgentHvmPaymentOperation["status"],
  binding_commitment = "a".repeat(64),
): AgentHvmPaymentOperation {
  return {
    amount_zhu,
    status,
    binding_commitment,
    amount_units: String(amount_zhu),
  } as AgentHvmPaymentOperation;
}

/** The view, asserted present, so each test reads as one statement. */
function viewOf(
  ...args: Parameters<typeof registryExitView>
): NonNullable<ReturnType<typeof registryExitView>> {
  const view = registryExitView(...args);
  if (!view) throw new Error("expected an exit view");
  return view;
}

const READY: AgentHvmRegistryExitStatus = {
  driver_ready: true,
  blocked_reason: "",
  lease_blocks_remaining: 9_999,
  lease_recover_blocks_remaining: 55_000,
  lease_read_error: "",
  fullnode_reachable: true,
  spendable_l1_zhu: 300_000,
  required_l1_fee_zhu: 30_000,
};

describe("what the exit section states before anything is pressed", () => {
  it("names the amount that comes back, net of what was already spent", () => {
    const view = viewOf(
      binding(),
      READY,
      [operation(250_000, "committed"), operation(50_000, "rejected")],
      formatUnits,
    );
    expect(view.depositLine).toContain("1000000 HAC");
    expect(view.yourMoneyLine).toContain("750000 HAC");
    // The exact figure is set by the newest co-signed receipt, not by this sum.
    expect(flatten(view.yourMoneyLine)).toContain(
      "newest receipt the provider co-signed",
    );
  });

  it("never claims more is coming back than was ever deposited", () => {
    const view = viewOf(
      binding(),
      READY,
      [operation(4_000_000, "committed")],
      formatUnits,
    );
    expect(view.yourMoneyLine).toContain("About 0 HAC");
    // Never a negative figure, whatever this wallet's own records say.
    expect(view.yourMoneyLine).not.toMatch(/-\d/);
  });

  it("states the objection window in blocks and in hours", () => {
    const view = viewOf(binding(), READY, [], formatUnits);
    // 12 blocks at a 300 second target is one hour.
    expect(EXIT_BLOCK_SECONDS).toBe(300);
    expect(view.windowLine).toContain("12 blocks");
    expect(view.windowLine).toContain("1 hour");
  });

  it("states that it costs chain fees, and how many, from the main balance", () => {
    const view = viewOf(binding(), READY, [], formatUnits);
    expect(EXIT_CHAIN_FEE_COUNT).toBe(3);
    expect(view.feeLine).toContain("3 network fees");
    expect(flatten(view.feeLine)).toContain(
      "spent whether or not the provider ever comes back",
    );
  });

  it("keeps the lease countdown a real number and never hides it", () => {
    const view = viewOf(binding(), READY, [], formatUnits);
    expect(view.leaseLine).toContain("9999 blocks");
    expect(view.leaseLine).toContain("34 days");
    // Both clocks, because only both together decide whether the money is
    // gone. The dormant window is stated as the reprieve it is, and the fatal
    // sentence is attached to both running out rather than to the first.
    expect(view.leaseLine).toContain("55000 blocks");
    expect(flatten(view.leaseLine)).toContain(
      "anyone at all can bring it back by paying its rent",
    );
    expect(flatten(view.leaseLine)).toContain(
      "Only if both run out is this deposit unrecoverable by everyone, including you",
    );
  });

  /**
   * The sentence that used to be here was the one line on this page that was
   * actively untrue.
   *
   * It said "If it expires, this deposit cannot be recovered by anyone,
   * including you" the moment the live lease ran out. On the reviewed contract
   * that is wrong by about six and a half times: funding buys every channel key
   * a recovery buffer, so an expired record goes dormant and any address at all
   * can restore it by paying rent. Erring toward panic is still erring, and
   * this is the screen a person reads when they already think their money is
   * gone.
   */
  it("only calls the deposit unrecoverable when the recovery window is gone too", () => {
    const doomed = viewOf(
      binding(),
      { ...READY, lease_blocks_remaining: 40, lease_recover_blocks_remaining: 0 },
      [],
      formatUnits,
    );
    expect(flatten(doomed.leaseLine)).toContain(
      "cannot be recovered by anyone, including you",
    );

    const reprieved = viewOf(
      binding(),
      { ...READY, lease_blocks_remaining: 40, lease_recover_blocks_remaining: 55_000 },
      [],
      formatUnits,
    );
    expect(flatten(reprieved.leaseLine)).not.toContain(
      "cannot be recovered by anyone, including you",
    );
  });

  it("says the lease is unknown rather than inventing a number", () => {
    const view = viewOf(
      binding(),
      {
        ...READY,
        lease_blocks_remaining: null,
        lease_recover_blocks_remaining: null,
        lease_read_error: "fullnode refused the registry snapshot",
      },
      [],
      formatUnits,
    );
    expect(view.leaseLine).toContain("could not be read");
    expect(view.leaseLine).toContain("fullnode refused the registry snapshot");
    expect(view.leaseLine).not.toMatch(/\d+ blocks/);
  });

  it("lists the four steps the exit actually runs", () => {
    const view = viewOf(binding(), READY, [], formatUnits);
    expect(view.steps).toHaveLength(4);
    expect(view.steps[0]).toContain("Asking the chain to settle");
    expect(view.steps[1]).toContain("Objection window open");
    expect(view.steps[2]).toContain("Locking the result");
    expect(view.steps[3]).toContain("Sending your money home");
  });
});

describe("the start control is offered only when it would work", () => {
  it("is offered when the driver, the fullnode and the fee balance are all there", () => {
    const view = viewOf(binding(), READY, [], formatUnits);
    expect(view.canStart).toBe(true);
    expect(view.startWithheldReason).toBe("");
  });

  it("repeats the backend's own reason rather than inventing one", () => {
    const view = viewOf(
      binding(),
      {
        ...READY,
        driver_ready: false,
        blocked_reason: "this build cannot yet build an exit signed by your key",
      },
      [],
      formatUnits,
    );
    expect(view.canStart).toBe(false);
    expect(view.startWithheldReason).toContain(
      "this build cannot yet build an exit signed by your key",
    );
  });

  it("states an unmet precondition instead of silently disabling", () => {
    const poor = viewOf(
      binding(),
      { ...READY, spendable_l1_zhu: 10 },
      [],
      formatUnits,
    );
    expect(poor.canStart).toBe(false);
    expect(poor.preconditions.map((entry) => entry.met)).toContain(false);
    expect(
      poor.preconditions.find((entry) => !entry.met)?.detail,
    ).toMatch(/fee/i);

    const offline = viewOf(
      binding(),
      { ...READY, fullnode_reachable: false },
      [],
      formatUnits,
    );
    expect(offline.canStart).toBe(false);
    expect(offline.startWithheldReason.length).toBeGreaterThan(20);
  });

  it("renders the same whether or not the provider can be reached", () => {
    // The section reads the wallet's own state and the pinned fullnode. There
    // is no Hub input to this view at all, so there is nothing a vanished Hub
    // can change about it.
    const source = readRaw("registryExit.ts");
    expect(source).not.toContain("hub_url");
    expect(source).not.toContain("hubUrl");
  });

  it("returns nothing at all when no registry channel is bound", () => {
    expect(registryExitView(null, READY, [], formatUnits)).toBeNull();
  });
});

describe("the exit control is named once and warned about before the press", () => {
  const admin = read("AgentAdminPages.tsx");

  it("has a label in the control table", () => {
    expect(DESKTOP_CONTROLS.start_exit_without_provider).toBe(
      "Take my money out without the provider",
    );
  });

  it("does not name a lease control this wallet cannot yet offer", () => {
    // The storage lease is the one clock in this system that destroys money,
    // and extending it is permissionless on chain. It is still blocked by the
    // same builder that blocks the exit, so the lease sentence states the
    // property and states the gap rather than naming a press that is not there.
    expect(Object.values(DESKTOP_CONTROLS)).not.toContain(
      "Extend my channel record",
    );
    const view = viewOf(binding(), READY, [], formatUnits);
    expect(view.leaseLine).toContain("cannot send that transaction for you yet");
  });

  it("carries an irreversible warning that names the real costs", () => {
    const entry = DESKTOP_IRREVERSIBLE_ACTIONS.find(
      (action) => action.id === "start_exit_without_provider",
    );
    expect(entry).toBeDefined();
    expect(entry?.confirmLabel).toBe("Confirm, close this channel");
    const warning = flatten(EXIT_WITHOUT_PROVIDER_WARNING);
    expect(warning).toContain("cannot be reopened without a new deposit");
    expect(warning).toContain("objection window");
    expect(warning).toContain("fees are spent whether or not");
  });

  it("renders that warning on the Security page, never behind a disclosure", () => {
    const index = admin.indexOf("{EXIT_WITHOUT_PROVIDER_WARNING}");
    expect(index).toBeGreaterThan(0);
    expect(disclosureDepth(admin, index)).toBe(0);
    // Before the first press, not after it.
    const button = admin.indexOf(
      "DESKTOP_CONTROLS.start_exit_without_provider",
    );
    expect(button).toBeGreaterThan(0);
    expect(index).toBeLessThan(button);
  });

  it("keeps the lease countdown and the amount out of a disclosure too", () => {
    for (const needle of ["{exitView.leaseLine}", "{exitView.yourMoneyLine}"]) {
      const index = admin.indexOf(needle);
      expect(index, `${needle} is never rendered`).toBeGreaterThan(0);
      expect(disclosureDepth(admin, index)).toBe(0);
    }
  });

  it("is wired to a real command, not to a local no-op", () => {
    const api = readRaw("api.ts");
    expect(api).toContain('invoke<AgentHvmRegistryExitStatus>(');
    expect(api).toContain('"agent_wallet_hvm_registry_exit_status"');
    expect(api).toContain('"agent_wallet_start_hvm_registry_exit"');
    expect(admin).toContain("agentWalletApi.hvmRegistryExitStatus");
    expect(admin).toContain("agentWalletApi.startHvmRegistryExit");
  });
});

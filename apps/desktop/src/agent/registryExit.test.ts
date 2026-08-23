import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import {
  EXIT_BLOCK_SECONDS,
  EXIT_CHAIN_FEE_COUNT,
  exitPressResultLine,
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
  // What must be held: every transaction one press can send, including the
  // lease renewals and the re-send. Deliberately larger than three times the
  // per-transaction ceiling, because that is the shape of the real numbers.
  required_l1_fee_zhu: 60_000,
  ordinary_run_ceiling_zhu: 30_000,
  chain_transaction_count: 3,
  per_transaction_ceiling_zhu: 10_000,
  per_transaction_network_fee_zhu: 1_000,
  per_transaction_gas_reserve_zhu: 9_000,
  started_steps: [],
};

/** The same wallet, on the second visit, with an exit already on chain. */
const RESUMING: AgentHvmRegistryExitStatus = {
  ...READY,
  started_steps: [
    {
      step: "challenge",
      attempt: 1,
      phase: "confirmed",
      network_fee_zhu: 1_000,
      transaction_hash: "c".repeat(64),
      confirmed_block_height: 900,
      updated_unix: 1_700_000_000,
    },
    {
      step: "finalize",
      attempt: 1,
      phase: "submitted",
      network_fee_zhu: 1_000,
      transaction_hash: "d".repeat(64),
      confirmed_block_height: null,
      updated_unix: 1_700_000_100,
    },
  ],
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

  /**
   * A settlement can start without the owner, and this screen has to say so.
   *
   * It also has to say it in the right DIRECTION, which an earlier draft did
   * not. On the shipped one-directional rail a stale receipt pays the owner
   * MORE, not less, and the wallet deliberately declines to answer one, so
   * copy promising that "the difference is gone" describes a loss that cannot
   * happen here. The assertions below pin the true exposure (the ending does
   * not happen by itself, and the protection is a setup property rather than a
   * chain guarantee) and forbid the reversal coming back.
   */
  it("says a settlement can start without the owner, in the direction the rail actually runs", () => {
    const view = viewOf(binding(), READY, [], formatUnits);
    const line = flatten(view.noWatcherLine);
    // The mechanism, in the owner's terms rather than as an identifier.
    expect(line).toContain("start a settlement without you");
    expect(line).toContain("while you are asleep");
    // The direction, which is the whole reason this line was rewritten.
    expect(line).toContain("cannot pay you less than your newest");
    expect(line).toContain("owes you more");
    expect(line).toContain("would hand money back");
    // The exposure that IS real: nothing ends it for them.
    expect(line).toContain("waits in the contract");
    expect(line).toContain("the only one who can press them is you");
    // And why the reassurance is not a guarantee.
    expect(line).toContain("not a promise from the chain");
    // The reversal must not come back. "gone for good" belongs to the lease
    // line, which is the one clock here that really does destroy money.
    expect(line).not.toMatch(/gone for good|the difference is gone/i);
    // No promise of a build nobody has scheduled. Held to the same wording as
    // the mobile test so the two cannot drift.
    expect(line).not.toMatch(/yet|soon|future release/i);
  });

  it("states the whole cost, gas included, and the amount to keep available", () => {
    const view = viewOf(binding(), READY, [], formatUnits);
    expect(EXIT_CHAIN_FEE_COUNT).toBe(3);
    const line = flatten(view.feeLine);
    expect(line).toContain("3 transactions");
    // The sentence used to say "3 network fees" and name no amount at all. On
    // a measured exit that understated the charge tenfold, because a registry
    // call is a contract call and the chain reserves its whole gas budget from
    // the main balance before running it. Every one of those numbers now has
    // to be on the screen.
    expect(line).toContain("10000 HAC");
    expect(line).toContain("1000 HAC of network fee");
    expect(line).toContain("9000 HAC");
    // The amount to keep is the whole press, not the three ordinary steps. A
    // press renews a short lease before it challenges, and quoting only the
    // three let an owner through who would have stalled at the third
    // transaction with the objection window already running. Both numbers are
    // on the screen, because "keep this" and "it will probably cost this" are
    // two different facts and folding them into one is how this went wrong.
    expect(line).toContain("Keep 60000 HAC available");
    expect(line).toContain("the usual three come to about 30000 HAC");
    expect(line).toContain(
      "it has to be there or the first transaction cannot run",
    );
    expect(line).toContain(
      "spent whether or not the provider ever comes back",
    );
  });

  it("does not describe an exit that is already running as one about to start", () => {
    const fresh = viewOf(binding(), READY, [], formatUnits);
    expect(fresh.alreadyStarted).toBe(false);
    expect(fresh.startLabelKind).toBe("start");
    expect(fresh.progressSoFarLine).toBe("");
    expect(fresh.windowLine).toContain("Once you start");

    const resumed = viewOf(binding(), RESUMING, [], formatUnits);
    expect(resumed.alreadyStarted).toBe(true);
    expect(resumed.startLabelKind).toBe("continue");
    // The screen must say which steps have run, what they cost, and that the
    // window may already be part gone. Saying "Once you start ... your
    // provider has 12 blocks to object" to someone whose window closed
    // yesterday is the failure this replaces.
    const progress = flatten(resumed.progressSoFarLine);
    expect(progress).toContain("already under way");
    expect(progress).toContain("asking the chain to settle: done, in a block");
    expect(progress).toContain(
      "locking the result: sent to your fullnode, not yet in a block",
    );
    expect(progress).toContain("1000 HAC of network fees has been confirmed");
    expect(progress).toContain("1000 HAC is on transactions this wallet signed");
    expect(progress).toContain("You do not need to keep this app open");
    expect(flatten(resumed.windowLine)).not.toContain("Once you start");
    expect(flatten(resumed.windowLine)).toContain(
      "some or all of that window may have passed already",
    );
  });

  it("reports a press in the backend's own words, never a fixed sentence", () => {
    const waiting = exitPressResultLine(
      {
        schema: "agent-hvm-registry-exit-progress/1",
        outcome: "waiting",
        step: null,
        phase: null,
        transaction_hash: null,
        waiting_reason:
          "this channel holds nothing for this wallet, so closing it would spend network fees to recover zero",
        observed_height: 900,
        channel_status: 2,
        deadline_height: 0,
        claimed_zhu: null,
        bill_serial: 4,
        network_fees_confirmed_zhu: 0,
        network_fees_at_risk_zhu: 0,
        steps: [],
      },
      formatUnits,
    );
    // The old screen printed "The exit has started" over exactly this answer.
    expect(waiting).toContain("spend network fees to recover zero");
    expect(waiting).not.toContain("The exit has started");
    expect(waiting).toContain("Nothing is stuck and nothing is lost");

    const done = exitPressResultLine(
      {
        schema: "agent-hvm-registry-exit-progress/1",
        outcome: "complete",
        step: null,
        phase: null,
        transaction_hash: null,
        waiting_reason: null,
        observed_height: 1_000,
        channel_status: 4,
        deadline_height: 900,
        claimed_zhu: 5_000,
        bill_serial: 4,
        network_fees_confirmed_zhu: 3_000,
        network_fees_at_risk_zhu: 0,
        steps: [],
      },
      formatUnits,
    );
    expect(done).toContain("closed and settled");
    expect(done).toContain("5000 HAC has been paid to your own address");
    expect(done).toContain("3000 HAC of network fees is confirmed in a block");
    expect(done).toContain("nothing is outstanding");
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
    expect(warning).toContain("spent whether or not the provider ever comes back");
    // It must not quote a fee count of its own. It did, and it was wrong: the
    // real cost is network fees plus the gas the chain reserves for a contract
    // call, which this sentence cannot check and `feeLine` can.
    expect(warning).not.toContain("three network fees");
    expect(warning).toContain("chain running costs");
    expect(warning).toContain("in the exact amount named above this");
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

  it("keeps the lease countdown, the amount and the unwatched window out of a disclosure too", () => {
    for (const needle of [
      "{exitView.leaseLine}",
      "{exitView.yourMoneyLine}",
      "{exitView.noWatcherLine}",
    ]) {
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

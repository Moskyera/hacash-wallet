/**
 * What the desktop says about getting money out of an HVM registry channel
 * when the provider has stopped answering.
 *
 * This is the screen an owner reaches on the worst day, so two rules shape
 * every line in it.
 *
 * FIRST, it must not depend on the provider. Nothing here reads a Hub
 * endpoint, and the module deliberately never mentions one: its inputs are the
 * wallet's own durable binding, this wallet's own payment records, and one
 * answer from the pinned fullnode. If this section rendered differently
 * because a Hub was unreachable, it would be broken exactly when it is needed.
 *
 * SECOND, it must not overstate. The wallet does not yet keep a durable copy
 * of the newest receipt the provider co-signed, so the amount below is this
 * wallet's own arithmetic and says so. The lease is a real number read from
 * the chain, or it is reported as unread; it is never guessed, because a
 * lapsed lease is the one state in this system where the money is destroyed
 * for everybody.
 *
 * Copy and formatting only. No control flow, no gate, no validation, no call.
 */
import type { AgentHvmPaymentOperation, AgentHvmRegistryBinding } from "./api";

/**
 * The Hacash block target, used only to turn block counts into a duration a
 * person can plan around. Every number that decides anything stays in blocks.
 */
export const EXIT_BLOCK_SECONDS = 300;

/**
 * Challenge, finalize and the Action 14 payout: three transactions, three
 * network fees, all paid from the owner's ordinary L1 balance.
 */
export const EXIT_CHAIN_FEE_COUNT = 3;

/** What the fullnode and this wallet report about an exit that has not begun. */
export type AgentHvmRegistryExitStatus = {
  /** Can this build actually put an exit transaction in the owner's hands? */
  driver_ready: boolean;
  /** The backend's own sentence for why it cannot, or "" when it can. */
  blocked_reason: string;
  /** Blocks the channel's keys stay ACTIVE, or null when unread. */
  lease_blocks_remaining: number | null;
  /**
   * Blocks the record stays dormant-but-restorable after that, or null when
   * unread.
   *
   * These are two different clocks and only the second one is fatal. When the
   * live half runs out the record does not vanish - the contract buys every
   * channel key a recovery buffer when it takes custody, and any address at
   * all can restore it by paying rent. Only when this half is also exhausted
   * are the keys destroyed and the deposit unreachable by everyone.
   */
  lease_recover_blocks_remaining: number | null;
  /** The fullnode's own words when the lease could not be read. */
  lease_read_error: string;
  /** The pinned fullnode answered the registry query. */
  fullnode_reachable: boolean;
  /** Ordinary L1 balance available to pay the exit's network fees. */
  spendable_l1_zhu: number;
  /**
   * Everything the whole exit can take from the main balance: the network fee
   * and the gas the chain reserves, for each of the transactions below.
   *
   * This used to be three network fees and nothing else, which understated a
   * measured exit by a factor of ten and understated what the owner had to
   * *hold* by considerably more. A registry call is an HVM contract call, and
   * the chain takes the whole gas budget out of the main balance before the
   * call runs, handing back what was not used.
   */
  required_l1_fee_zhu: number;
  /**
   * What the three ordinary steps cost when nothing conditional happens, which
   * is what usually happens.
   *
   * Named separately from `required_l1_fee_zhu` because they are two different
   * facts and folding them into one number is how this screen got it wrong
   * twice. This one is the likely bill; that one is what must be sitting there
   * before the press, and it covers the lease renewals and the re-send that a
   * press can also need.
   */
  ordinary_run_ceiling_zhu?: number;
  /** How many chain transactions an ordinary exit sends. */
  chain_transaction_count: number;
  /** Fee plus gas reserve for one of them. */
  per_transaction_ceiling_zhu: number;
  /** The network fee half of that. */
  per_transaction_network_fee_zhu: number;
  /** The gas half: reserved before the call runs, mostly refunded after. */
  per_transaction_gas_reserve_zhu: number;
  /**
   * Steps of an exit this wallet has already opened for this channel, from its
   * own durable record. Empty means no exit has ever been started here, and
   * that is the only case in which the screen may speak about starting one.
   */
  started_steps: readonly AgentHvmRegistryExitStepProgress[];
};

/** One step of an exit, as this wallet's durable record holds it. */
export type AgentHvmRegistryExitStepProgress = {
  step: string;
  attempt: number;
  phase: string;
  network_fee_zhu: number;
  transaction_hash: string | null;
  confirmed_block_height: number | null;
  updated_unix: number;
};

/** What one press of the exit control actually did. */
export type AgentHvmRegistryExitProgress = {
  schema: string;
  /** "stepped", "waiting" or "complete". */
  outcome: string;
  step: string | null;
  phase: string | null;
  transaction_hash: string | null;
  /** Why it stopped, naming the block it is waiting for. */
  waiting_reason: string | null;
  observed_height: number | null;
  channel_status: number | null;
  deadline_height: number | null;
  claimed_zhu: number | null;
  bill_serial: number;
  /** Fees this wallet has watched land in a block. */
  network_fees_confirmed_zhu: number;
  /** Fees on bytes that exist and have not been seen in a block. */
  network_fees_at_risk_zhu: number;
  steps: readonly AgentHvmRegistryExitStepProgress[];
};

export type ExitPrecondition = {
  label: string;
  met: boolean;
  /** Said whether or not it is met, so nothing is silently gated. */
  detail: string;
};

export type RegistryExitView = {
  heading: string;
  /** What was put into this channel when it was opened. */
  depositLine: string;
  /** What should come back, and the one authority that actually fixes it. */
  yourMoneyLine: string;
  /** How long the provider has to object, in blocks and in hours. */
  windowLine: string;
  /**
   * That a settlement can start without the owner, and what that does and does
   * not cost them.
   *
   * An earlier draft of this line said the owner loses the difference if
   * nobody answers a stale settlement. On the rail this build actually ships
   * that is backwards, and three places in the tree say so. The Hub deposits
   * nothing (`right_hub_deposit_zhu != 0` is refused outright by
   * `HvmRegistryBindingV2::validate`) and the bill ledger only ever subtracts
   * from the left balance, so every later receipt pays the owner strictly
   * LESS. An older receipt therefore owes them MORE, and answering it hands
   * money back: `decide_user_exit_action` returns `finish_whatever_is_standing`
   * instead of responding, `registry_response_watch` refuses to sign such a
   * response at all, and its own test measured a dutiful answer costing the
   * user 650,000 zhu on a 1,000,000 zhu channel.
   *
   * So what is stated here is the gap that is real: nothing presses the last
   * two steps for a sleeping owner, and the protection above is a property of
   * two checks rather than a promise from the chain. No answering window is
   * quoted, because on this rail the owner should not answer.
   *
   * Constant copy, not a measurement: the day either check changes this stops
   * being true, and it stops being a constant.
   */
  noWatcherLine: string;
  /** What it costs, and that the cost stands even if nothing is recovered. */
  feeLine: string;
  /** The storage lease, never folded away, never invented. */
  leaseLine: string;
  /** The four chain steps, in the order they run. */
  steps: string[];
  preconditions: ExitPrecondition[];
  canStart: boolean;
  /** Why the start is withheld, or "" when it is offered. */
  startWithheldReason: string;
  /** True when this wallet has already opened a step of this exit. */
  alreadyStarted: boolean;
  /**
   * What the durable record says has happened so far, or "" before anything
   * has. Never invented: every clause comes from a stored step.
   */
  progressSoFarLine: string;
  /** What the control should say: a beginning, or a continuation. */
  startLabelKind: "start" | "continue";
};

/** Payments that provably left this channel and can never be undone. */
const SPENT: ReadonlySet<AgentHvmPaymentOperation["status"]> = new Set([
  "committed",
]);

function plural(count: number, one: string): string {
  return `${count} ${one}${count === 1 ? "" : "s"}`;
}

function blocksAsHours(blocks: number): string {
  const hours = Math.max(1, Math.round((blocks * EXIT_BLOCK_SECONDS) / 3_600));
  return plural(hours, "hour");
}

function blocksAsDays(blocks: number): string {
  return plural(Math.floor((blocks * EXIT_BLOCK_SECONDS) / 86_400), "day");
}

/**
 * The exit section, or null when this wallet has no registry channel at all.
 *
 * `formatZhu` renders an exact zhu amount; the caller owns that conversion so
 * this module never carries a second copy of the unit rules.
 */
export function registryExitView(
  binding: AgentHvmRegistryBinding | null,
  status: AgentHvmRegistryExitStatus,
  operations: readonly AgentHvmPaymentOperation[],
  formatZhu: (zhu: string) => string,
): RegistryExitView | null {
  if (!binding) return null;

  const contract = binding.recovery_bundle.binding;
  const deposit = contract.left_deposit_zhu;
  const spent = operations
    .filter(
      (operation) =>
        operation.binding_commitment === binding.binding_commitment &&
        SPENT.has(operation.status),
    )
    .reduce((total, operation) => total + operation.amount_zhu, 0);
  // Never negative and never above the deposit. This is the wallet's own
  // arithmetic over its own records, so a record this wallet lost, or one it
  // holds twice, must not be able to print a number that promises the owner
  // more than the channel ever held.
  const remaining = Math.min(deposit, Math.max(0, deposit - spent));

  const windowBlocks = contract.challenge_blocks;
  const lease = status.lease_blocks_remaining;
  const recover = status.lease_recover_blocks_remaining;

  const started = status.started_steps ?? [];
  const alreadyStarted = started.length > 0;
  const feesAffordable = status.spendable_l1_zhu >= status.required_l1_fee_zhu;
  const preconditions: ExitPrecondition[] = [
    {
      label: "Network fees",
      met: feesAffordable,
      detail: feesAffordable
        ? `Your main balance holds ${formatZhu(String(status.spendable_l1_zhu))}, which covers the ${formatZhu(String(status.required_l1_fee_zhu))} this can cost.`
        : `This costs up to ${formatZhu(String(status.required_l1_fee_zhu))} in network fees and your main balance holds ${formatZhu(String(status.spendable_l1_zhu))}. Add ordinary HAC to this wallet's main balance first.`,
    },
    {
      label: "Your fullnode",
      met: status.fullnode_reachable,
      detail: status.fullnode_reachable
        ? "The fullnode this wallet is pinned to answered. Your provider is not involved in any of this."
        : "The fullnode this wallet is pinned to did not answer, and every step below is sent through it. Nothing is wrong with your channel and no money has moved.",
    },
    {
      label: "This build",
      met: status.driver_ready,
      detail: status.driver_ready
        ? "This build can sign the exit with your own key, without the provider."
        : status.blocked_reason,
    },
  ];

  const firstUnmet = preconditions.find((entry) => !entry.met);

  return {
    heading: "Getting your money out without the provider",
    depositLine: `You put ${formatZhu(String(deposit))} into this channel when it was opened.`,
    yourMoneyLine:
      `About ${formatZhu(String(remaining))} should come back to you: your deposit, less the ` +
      `${formatZhu(String(Math.min(deposit, spent)))} this wallet has recorded as already paid out of it. ` +
      "The exact figure is fixed by the newest receipt the provider co-signed, not by this sum, so treat " +
      "it as close rather than final.",
    windowLine: alreadyStarted
      ? `Your provider has ${plural(windowBlocks, "block")} (about ${blocksAsHours(windowBlocks)}) from the moment ` +
        "your first transaction was mined to object with a newer receipt. This exit is already under way, so " +
        "some or all of that window may have passed already. Continuing below carries on from where it " +
        "stopped and does not start it over."
      : `Once you start, your provider has ${plural(windowBlocks, "block")} (about ${blocksAsHours(windowBlocks)}) ` +
        "to object with a newer receipt. That is normal and it is how the chain decides which receipt is the " +
        "true one. Your money arrives after that window closes, not before.",
    noWatcherLine:
      "Your provider can start a settlement without you, including while you are asleep, and nothing " +
      "here is watching for it. On this kind of channel that cannot pay you less than your newest " +
      "receipt does: your provider puts no money in, and the running total only ever moves from you to " +
      "them, so an older receipt owes you more, not less. If one is used, this wallet will not answer " +
      "it, because answering would hand money back. What being away does cost you is the ending: the " +
      "money is not taken, it waits in the contract until the last two steps are pressed, and on this " +
      "build the only one who can press them is you, here. Nothing here can hand your receipt to " +
      "somebody else to watch it for you. And the protection above is how this channel is set up, not " +
      "a promise from the chain, so keep what is in it to what you can afford to leave sitting.",
    // The fee sentence used to say "three network fees" and name no amount at
    // all. A measured exit was charged ten times that, and what an owner has
    // to be able to HOLD is larger again: a registry call is an HVM contract
    // call, and the chain takes the whole gas budget out of the main balance
    // before the call runs, handing back what was not used. So the reserve is
    // quoted, because the reserve is what decides whether the first
    // transaction can execute at all.
    //
    // The order of the sentences is load bearing. "Keep X available" used to
    // come before the paragraph about extensions and re-sends, and X was the
    // three ordinary transactions only, so an owner who read carefully was
    // told a number that did not cover the run this screen was describing to
    // them. X is now every transaction one press can send, which is more than
    // three times the per-transaction ceiling; the conditional steps are named
    // first so the larger number reads as what it is.
    feeLine:
      `This sends ${plural(status.chain_transaction_count ?? EXIT_CHAIN_FEE_COUNT, "transaction")}, and each one can ` +
      `take up to ${formatZhu(String(status.per_transaction_ceiling_zhu ?? 0))} from your main balance: ` +
      `${formatZhu(String(status.per_transaction_network_fee_zhu ?? 0))} of network fee, plus up to ` +
      `${formatZhu(String(status.per_transaction_gas_reserve_zhu ?? 0))} that the chain holds while the contract ` +
      "runs and gives most of back afterwards. If this channel's record is close to expiring it is extended " +
      "first, and if your provider answers your first transaction before it is mined then that one is spent " +
      "for nothing and is sent again; each of those is one more transaction at the same ceiling. Keep " +
      `${formatZhu(String(status.required_l1_fee_zhu))} available, which is enough for all of them together ` +
      `even though the usual three come to about ${formatZhu(String(status.ordinary_run_ceiling_zhu ?? 0))}; ` +
      "you will not usually be charged anything like it, " +
      "and it has to be there or the first transaction cannot run. What is spent is spent whether or not the " +
      "provider ever comes back.",
    leaseLine:
      lease === null
        ? "This channel's record on chain has an expiry, and it could not be read just now. " +
          `The fullnode said: ${status.lease_read_error || "no reason given"}. ` +
          "Check again before relying on the time you have."
        : `This channel's record on chain stays active for ${plural(lease, "block")} (about ${blocksAsDays(lease)}). ` +
          (recover === null || recover === 0
            ? "After that it is gone and this deposit cannot be recovered by anyone, including you. "
            : `After that it goes dormant rather than disappearing, and anyone at all can bring it back by paying its rent for ${plural(recover, "block")} more (about ${blocksAsDays(recover)}). ` +
              "Only if both run out is this deposit unrecoverable by everyone, including you. ") +
          `${DESKTOP_EXTEND_HINT}`,
    steps: [
      "Asking the chain to settle. One transaction from your own key, with the newest receipt you hold.",
      `Objection window open. ${plural(windowBlocks, "block")}, about ${blocksAsHours(windowBlocks)}. Your provider may answer here with a newer receipt, which is normal.`,
      "Locking the result. One transaction that fixes the outcome. Anyone may send this one, including a stranger, and it cannot change who gets paid.",
      "Sending your money home. One transaction that pays the settled amount to your own address and to no other.",
    ],
    preconditions,
    canStart: !firstUnmet,
    startWithheldReason: firstUnmet ? firstUnmet.detail : "",
    alreadyStarted,
    progressSoFarLine: progressSoFarLine(started, formatZhu),
    startLabelKind: alreadyStarted ? "continue" : "start",
  };
}

/** Human names for the durable step slugs. */
const STEP_NAMES: Readonly<Record<string, string>> = {
  renew_registry_lease: "extending the shared record on chain",
  renew_channel_lease: "extending this channel's record on chain",
  challenge: "asking the chain to settle",
  respond: "answering your provider's receipt",
  finalize: "locking the result",
  claim: "sending your money home",
};

/** What each durable phase means for the owner's money. */
const PHASE_NAMES: Readonly<Record<string, string>> = {
  intent_persisted: "prepared, nothing sent and nothing spent",
  signature_may_exist: "being signed",
  signed: "signed, not yet sent",
  submitted: "sent to your fullnode, not yet in a block",
  confirmed: "done, in a block",
  settled_elsewhere: "already done by someone else, at no cost to you",
};

function stepName(slug: string): string {
  return STEP_NAMES[slug] ?? slug;
}

function phaseName(slug: string): string {
  return PHASE_NAMES[slug] ?? slug;
}

/**
 * What this wallet's own record says has happened, or "" before anything has.
 *
 * Built only from stored steps. There is no client-side "I pressed it" flag
 * anywhere in this file and there must not be: the one situation resume exists
 * for is the app having been closed, and a flag held in memory is exactly the
 * thing that does not survive that.
 */
export function progressSoFarLine(
  steps: readonly AgentHvmRegistryExitStepProgress[],
  formatZhu: (zhu: string) => string,
): string {
  if (steps.length === 0) return "";
  const spent = steps
    .filter((step) => step.phase === "confirmed")
    .reduce((total, step) => total + step.network_fee_zhu, 0);
  const atRisk = steps
    .filter(
      (step) =>
        step.phase === "signed" ||
        step.phase === "submitted" ||
        step.phase === "signature_may_exist",
    )
    .reduce((total, step) => total + step.network_fee_zhu, 0);
  const lines = steps.map((step) => `${stepName(step.step)}: ${phaseName(step.phase)}`);
  const money =
    `${formatZhu(String(spent))} of network fees has been confirmed in a block` +
    (atRisk > 0
      ? `, and ${formatZhu(String(atRisk))} is on transactions this wallet signed and has not yet seen in one.`
      : ", and nothing is outstanding.");
  return (
    `This exit is already under way on chain. So far: ${lines.join("; ")}. ${money} ` +
    "You do not need to keep this app open. Every step is picked up from where it stopped."
  );
}

/**
 * The one sentence to show after a press, built from what the press returned.
 *
 * The screen used to print a fixed "The exit has started" whatever came back,
 * including on the answer that says this channel holds nothing and closing it
 * would spend fees to recover zero. Everything below is the backend's own
 * report; nothing here decides anything.
 */
export function exitPressResultLine(
  progress: AgentHvmRegistryExitProgress,
  formatZhu: (zhu: string) => string,
): string {
  const money =
    `${formatZhu(String(progress.network_fees_confirmed_zhu))} of network fees is confirmed in a block` +
    (progress.network_fees_at_risk_zhu > 0
      ? `, and ${formatZhu(String(progress.network_fees_at_risk_zhu))} is on bytes not yet seen in one.`
      : ", and nothing is outstanding.");
  if (progress.outcome === "complete") {
    const paid =
      progress.claimed_zhu === null
        ? "Your payout has been made."
        : `${formatZhu(String(progress.claimed_zhu))} has been paid to your own address.`;
    return `This channel is closed and settled. ${paid} ${money}`;
  }
  if (progress.outcome === "waiting") {
    const reason = progress.waiting_reason ?? "the chain is not ready for the next step yet";
    return (
      `Nothing further can be sent right now: ${reason}. Nothing is stuck and nothing is lost. You can ` +
      `close this app and come back. ${money}`
    );
  }
  const step = progress.step ? stepName(progress.step) : "the next step";
  const phase = progress.phase ? phaseName(progress.phase) : "sent";
  return (
    `This exit moved forward: ${step} is ${phase}. It continues in the steps above and you can close this ` +
    `app between them. ${money}`
  );
}

/**
 * The lease is extendable by anybody, with no permission from the provider and
 * no signature but a fee. This wallet still cannot send that transaction,
 * because it is blocked by the same builder that blocks the exit itself, and
 * saying otherwise would name a control that does not exist. So the sentence
 * states the property and states the gap, and does not promise a press.
 */
const DESKTOP_EXTEND_HINT =
  "Anyone at all can extend it, including a stranger, and it needs no permission from your provider. " +
  "This wallet cannot send that transaction for you yet.";

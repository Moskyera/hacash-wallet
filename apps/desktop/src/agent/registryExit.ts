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
  /** The reviewed ceiling for all three of them together. */
  required_l1_fee_zhu: number;
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
    windowLine:
      `Once you start, your provider has ${plural(windowBlocks, "block")} (about ${blocksAsHours(windowBlocks)}) ` +
      "to object with a newer receipt. That is normal and it is how the chain decides which receipt is the " +
      "true one. Your money arrives after that window closes, not before.",
    feeLine:
      `This costs ${plural(EXIT_CHAIN_FEE_COUNT, "network fee")} from your main balance, one for each ` +
      "transaction it sends. Those fees are spent whether or not the provider ever comes back. " +
      "If this channel's record is close to expiring it is extended first, which costs one or two " +
      "more, and if your provider answers your first transaction before it is mined that one is " +
      "spent for nothing and is sent again.",
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
  };
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

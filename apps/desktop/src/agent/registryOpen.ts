/**
 * What the desktop says before an owner commits to a provider channel.
 *
 * This is the other end of `registryExit.ts`. That screen is read on the worst
 * day; this one is read on the first day, and everything the worst day depends
 * on is decided here. Four rules shape every line.
 *
 * FIRST, it names the exact amount, before the press. Funding a channel is an
 * ordinary transfer into a contract: it is not a hold, it is not reversible,
 * and no support desk can undo it.
 *
 * SECOND, it says what makes that safe, and says who checked it. The provider
 * signs a receipt returning the whole deposit BEFORE anything is funded, and
 * this wallet verifies that signature against its own record of the channel
 * rather than trusting the answer. If the receipt does not arrive, no channel
 * opens and nothing is spent.
 *
 * THIRD, it does not claim the deposit has been sent when it has not. The
 * press secures the refund and commits this wallet to this exact channel. What
 * this app can and cannot do after that is reported from the backend's own
 * answer, never from a fixed sentence.
 *
 * FOURTH, it never claims a capability the phone has. A paired phone holds an
 * approval identity, not a Hacash spending key, and cannot sign a funding
 * transaction or a refund bill in any build.
 *
 * Copy and formatting only. No control flow, no gate, no validation, no call.
 */

/** What the backend reports about opening, before anything is asked of a Hub. */
/**
 * A channel this wallet began and has not finished, as the wallet records it.
 *
 * The wallet's own answer, not this desktop's note. It survives clearing
 * browser data, it survives a restore onto another machine, and it belongs to
 * one wallet rather than to whichever wallet wrote the single note key last.
 * `null` when the wallet has no unfinished channel.
 */
export type AgentHvmRegistryChannelInProgress = {
  schema: "hpay-agent-registry-channel-in-progress/1";
  /** The countersigned full refund is saved and checked. */
  refund_held: boolean;
  /** What the channel locks up, from that countersigned bill. */
  deposit_zhu: number | null;
  /** Set once a deposit transfer exists, in a block or not. */
  funding_transaction_hash: string | null;
  /** The wallet has seen that transfer in a block. */
  funding_confirmed: boolean;
  funding_confirmed_block_height: number | null;
  /** What the network charged, once there is a transaction. */
  network_fee_zhu: number | null;
};

export type AgentHvmRegistryOpenStatus = {
  /** Can this wallet open a channel at all right now? */
  open_ready: boolean;
  /**
   * The unfinished channel this wallet holds, or `null`.
   *
   * The screen must prefer this over its own note. A deposit that has left is
   * recoverable from here with no provider and no browser storage, and losing
   * the note used to strand exactly that money.
   */
  channel_in_progress: AgentHvmRegistryChannelInProgress | null;
  /** The backend's own sentence for why it cannot, or "" when it can. */
  blocked_reason: string;
  /** The provider URL this wallet would ask. */
  hub_url: string;
  /** The provider identity that answered, or "" when it was not reached. */
  hub_address: string;
  /** The provider answered and runs the reviewed provider profile. */
  hub_reachable: boolean;
  /** The backend's own words when the provider could not be checked. */
  hub_read_error: string;
  /** The pinned fullnode answered. */
  fullnode_reachable: boolean;
  /** Ordinary L1 balance this wallet can spend right now. */
  spendable_l1_zhu: number;
  /** What this channel would lock up. */
  deposit_zhu: number;
  /** Fee plus reserved gas for the whole open, from the main balance. */
  required_l1_fee_zhu: number;
  /** How many chain transactions an open sends. */
  chain_transaction_count: number;
  /** The longest objection window a reviewed channel may carry. */
  challenge_blocks: number;
};

export type OpenPrecondition = {
  label: string;
  met: boolean;
  /** Said whether or not it is met, so nothing is silently gated. */
  detail: string;
};

export type RegistryOpenView = {
  heading: string;
  /** The exact amount the channel locks up, and that it cannot be recalled. */
  lockUpLine: string;
  /** The refund secured before anything is funded, and who verified it. */
  refundLine: string;
  /** What the press commits this wallet to, and what it does not yet do. */
  commitmentLine: string;
  /** What happens when the provider will not countersign that refund. */
  refusalLine: string;
  /** Fee and reserved gas, from the main balance, on top of the deposit. */
  feeLine: string;
  /** How the money comes back later, naming the control that does it. */
  exitLine: string;
  /** What a paired phone can and cannot do here. */
  phoneLine: string;
  preconditions: OpenPrecondition[];
  canOpen: boolean;
  /** Why the open is withheld, or "" when it is offered. */
  openWithheldReason: string;
};

/**
 * The Hacash block target, used only to turn block counts into a duration a
 * person can plan around. Every number that decides anything stays in blocks.
 */
export const OPEN_BLOCK_SECONDS = 300;

/**
 * The label of the control that gets the money back out again, quoted so this
 * screen cannot name a button that does not exist.
 *
 * Two false instructions in this codebase caused a permanent, unrecoverable
 * device revocation, and both were a sentence naming a control that was not
 * there. `registryOpen.test.ts` checks this against the control table itself.
 */
export const OPEN_EXIT_CONTROL_LABEL = "Take my money out without the provider";

/**
 * The label of the control that actually sends the deposit, quoted for the same
 * reason and checked against the control table by the same test.
 *
 * This screen's press does not move money and must never be read as if it did.
 * Saying so is only half an answer: an owner who has just been told the deposit
 * has not been sent needs to be told what does send it, on this page, by name.
 */
export const OPEN_FUND_CONTROL_LABEL = "Send the deposit into this channel";

/**
 * What the phone can and cannot do about any of this, in every build.
 *
 * A paired phone holds a witness and approval identity. It has never held a
 * Hacash spending key and there is no build in which it does, so it cannot
 * sign the funding transaction and cannot sign the refund bill. Saying it
 * "cannot yet" would be an invitation to wait for something that is not
 * coming.
 */
export const OPEN_PHONE_CANNOT =
  "Your paired phone cannot do this and never will. It holds an approval identity, not a Hacash spending key, so it can confirm a payment you have already decided on but it cannot sign the transaction that locks up this deposit, and it cannot sign the refund receipt either. Both signatures are made on this desktop.";

function plural(count: number, one: string): string {
  return `${count} ${one}${count === 1 ? "" : "s"}`;
}

function blocksAsHours(blocks: number): string {
  const hours = Math.max(1, Math.round((blocks * OPEN_BLOCK_SECONDS) / 3_600));
  return plural(hours, "hour");
}

/**
 * The open section, or null when this wallet already has a channel.
 *
 * `formatZhu` renders an exact zhu amount; the caller owns that conversion so
 * this module never carries a second copy of the unit rules.
 */
export function registryOpenView(
  hasChannelAlready: boolean,
  status: AgentHvmRegistryOpenStatus,
  formatZhu: (zhu: string) => string,
): RegistryOpenView | null {
  if (hasChannelAlready) return null;

  const total = status.deposit_zhu + status.required_l1_fee_zhu;
  const affordable = status.spendable_l1_zhu >= total;
  const preconditions: OpenPrecondition[] = [
    {
      label: "Your balance",
      met: affordable,
      detail: affordable
        ? `Your main balance holds ${formatZhu(String(status.spendable_l1_zhu))}, which covers the ${formatZhu(String(status.deposit_zhu))} deposit and the ${formatZhu(String(status.required_l1_fee_zhu))} this can cost to send.`
        : `This needs ${formatZhu(String(total))} available: ${formatZhu(String(status.deposit_zhu))} of deposit and up to ${formatZhu(String(status.required_l1_fee_zhu))} of network fee and reserved gas. Your main balance holds ${formatZhu(String(status.spendable_l1_zhu))}. Add ordinary HAC to this wallet first.`,
    },
    {
      label: "Your provider",
      met: status.hub_reachable,
      detail: status.hub_reachable
        ? `${status.hub_url} answered and runs the reviewed provider profile. It still has to sign your refund receipt before anything is funded, and it can refuse.`
        : `${status.hub_url} did not answer, or does not run the reviewed provider profile. Nothing has been asked of it and no money has moved. ${status.hub_read_error || "No reason was given."}`,
    },
    {
      label: "Your fullnode",
      met: status.fullnode_reachable,
      detail: status.fullnode_reachable
        ? "The fullnode this wallet is pinned to answered. Every transaction this channel needs is sent through it and not through your provider."
        : "The fullnode this wallet is pinned to did not answer, and the deposit is sent through it. Nothing has been sent and no money has moved.",
    },
    {
      label: "This wallet",
      met: status.open_ready,
      detail: status.open_ready
        ? "This wallet has no provider channel yet, so it can open one."
        : status.blocked_reason,
    },
  ];

  const firstUnmet = preconditions.find((entry) => !entry.met);

  return {
    heading: "Opening a channel with a provider",
    lockUpLine:
      `This channel locks ${formatZhu(String(status.deposit_zhu))} into the channel contract. That is an ` +
      "ordinary transfer on the chain: it is not a hold, it cannot be cancelled once it is in a block, and " +
      "neither this app nor your provider can reverse it. It leaves your main balance and stays in the " +
      "contract until the channel is closed.",
    refundLine:
      "Nothing is funded until your provider has signed a receipt that returns the whole " +
      `${formatZhu(String(status.deposit_zhu))} to you, and this wallet checks that signature against its own ` +
      "record of the channel rather than taking your provider's word for it. That receipt never expires, and " +
      "it is what lets you close the channel and be paid without your provider's permission.",
    commitmentLine:
      "Pressing this signs your half of that receipt, asks your provider for its half, verifies what comes " +
      "back and saves it here. It sends no money and costs no fee. It does commit this wallet to this exact " +
      "channel and this exact deposit: once the receipt is saved, this wallet will not swap it for a " +
      "different channel, because that receipt is the only thing that gets this deposit back.",
    refusalLine:
      "If your provider will not sign it, or signs something that does not check out, no channel is opened " +
      "at all. Nothing is sent to the network, nothing is reserved, no fee is charged and there is nothing " +
      "to undo. You can try again or use a different provider.",
    feeLine:
      `Funding this channel costs up to ${formatZhu(String(status.required_l1_fee_zhu))} from your main balance ` +
      `across ${plural(status.chain_transaction_count, "transaction")}: network fees, plus gas that the chain ` +
      "holds while the contract runs and gives most of back afterwards. That cost is on top of the deposit " +
      "and it is spent once those transactions are sent, whatever happens to the channel afterwards.",
    exitLine:
      `Getting the money back out later does not need your provider's permission. "${OPEN_EXIT_CONTROL_LABEL}" ` +
      "appears on this page once the channel is open and funded. It gives your provider up to " +
      `${plural(status.challenge_blocks, "block")} (about ${blocksAsHours(status.challenge_blocks)}) to object ` +
      "with a newer receipt, then pays you, and it costs further network fees of its own.",
    phoneLine: OPEN_PHONE_CANNOT,
    preconditions,
    canOpen: !firstUnmet,
    openWithheldReason: firstUnmet ? firstUnmet.detail : "",
  };
}

/** What one press of the open control actually did. */
export type AgentHvmRegistryOpenResult = {
  schema: string;
  binding_commitment: string;
  hub_url: string;
  hub_address: string;
  contract_address: string;
  /** What this channel locks up once it is funded. */
  deposit_zhu: number;
  /** What the countersigned receipt returns, read from the bill itself. */
  refunded_zhu: number;
  refund_bill_commitment: string;
  /** True when this wallet holds a receipt that would authorise funding. */
  refund_guaranteed: boolean;
};

/**
 * The one sentence to show after a press, built from what the press returned.
 *
 * It reports the guarantee, which is what happened, and then states plainly
 * that the deposit has not been sent and that this app cannot send it yet.
 * Printing "your channel is open" over a channel that holds nothing would be
 * the same class of lie as the fixed sentence the exit screen used to print
 * over an objection window: it would send an owner looking for a balance that
 * is not there, and it would hide the one thing they still have to do.
 */
export function openPressResultLine(
  result: AgentHvmRegistryOpenResult,
  formatZhu: (zhu: string) => string,
): string {
  if (!result.refund_guaranteed) {
    return (
      "Your provider did not guarantee your refund, so no channel was opened. Nothing was sent to the " +
      "network and no money has moved."
    );
  }
  return (
    `Your provider has signed a receipt returning all ${formatZhu(String(result.refunded_zhu))} of this deposit, ` +
    "and this wallet checked that signature itself and saved it. That receipt does not expire. No money has " +
    `moved yet: the ${formatZhu(String(result.deposit_zhu))} deposit has not been sent. The next step on this ` +
    `page, "${OPEN_FUND_CONTROL_LABEL}", is the one that sends it, and it goes out against the receipt you ` +
    "now hold and never before it."
  );
}

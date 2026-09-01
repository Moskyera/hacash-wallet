/**
 * Every desktop control that cannot be undone, and the sentence that must be
 * readable BEFORE it is pressed.
 *
 * Collapsing prose is safe for background. It is not safe here. A warning that
 * only appears after the press, or that hides behind a disclosure the owner
 * never opens, is the same failure as no warning at all. Nothing in this file
 * may ever be moved behind a `<details>`.
 *
 * Copy only. No control flow, no gate, no validation.
 */
import { COMPANION_REVOKE_WARNING } from "./companionPairingFeedback";
import { DESKTOP_CONTROLS, type DesktopControlId } from "./desktopControls";

export type DesktopIrreversibleAction = {
  id:
    | "revoke_phone"
    | "revoke_agent"
    | "emergency_stop"
    | "approve_exact_transaction"
    | "reject_payment"
    | "abandon_stranded_payment"
    | "open_provider_channel"
    | "fund_provider_channel"
    | "start_exit_without_provider";
  /** The control this warning belongs beside. */
  control: DesktopControlId;
  /** Rendered before the first press, never behind a disclosure. */
  warning: string;
  /**
   * The identifier the views render this warning through. The test that proves
   * the warning is not hidden inside a `<details>` looks for this token, so it
   * has to name the expression that actually appears in the JSX.
   */
  renderedAs: string;
  /**
   * The label of the confirming second press, or null when one press is enough
   * because the warning is already beside the button and names the exact
   * amount, device or wallet involved.
   */
  confirmLabel: string | null;
};

/**
 * What engaging the stop also tears down, said before the press.
 *
 * `agent_wallet_emergency_stop`
 * (crates/wallet-tauri-common/src/agent_commands.rs) calls
 * `companion.request_shutdown`, `runtime.request_shutdown`,
 * `companion.cancel_pairing`, `companion.stop` and `runtime.stop` before it
 * writes the marker. Nothing on Overview said so, and both panels kept
 * reporting that their listeners were on.
 */
export const EMERGENCY_STOP_STOPS_LISTENERS =
  "This also stops the AI agent connector and the phone connection on this desktop, and cancels any phone pairing that is part-way through. Paired phones and paired agents stay paired, and you can start both again afterwards.";

export const EMERGENCY_STOP_WARNING =
  "Disable All Agent Payments blocks new agent payment progress and invalidates active permits. It cannot reverse a transaction that has already been submitted to the network.";

export const REVOKE_AGENT_WARNING =
  "Revoking is permanent. It disconnects this agent, invalidates its sessions and cancels its unsigned pending operations. The same agent cannot be un-revoked.";

/**
 * True in every build and in every state the control can be pressed.
 *
 * It used to open "Approval signs and broadcasts only this exact commitment",
 * which is false in a Testnet Pilot build: there, approving signs and then
 * stops for the paired phone's witness, and nothing is broadcast until that
 * arrives. What is broadcast, when it is broadcast, is said beside this by
 * `APPROVE_OUTCOME_NOTICE` (access.ts), which knows the build. This sentence
 * keeps only what does not depend on it: what is signed, that a broadcast
 * cannot be taken back, and what to read before deciding.
 */
export const APPROVE_TRANSACTION_WARNING =
  "Approval signs only this exact commitment, and once a transaction has been broadcast it cannot be recalled. Verify the amount, recipient and total debit before continuing.";

export const REJECT_PAYMENT_WARNING =
  "Rejecting is final for this request. No transaction is signed and the agent has to ask again.";

/**
 * The cost of giving up a payment that is stranded waiting on the phone.
 *
 * It has to be exact about the two things an owner conflates here: the money is
 * not gone, and the payment is not coming back. The reservation is released
 * because `SignedAwaitingWitness` provably never reached the node - the only
 * route from there to a broadcast is `mark_witnessed`, which needs a real
 * receipt signed by the paired phone over that exact operation.
 *
 * `abandon_stranded_witness_operation`
 * (crates/agent-wallet-core/src/service/companion/witness.rs) is refused while
 * anything is still outstanding that could become a confirmation, so this
 * sentence can promise "never sent" without qualifying it.
 */
export const ABANDON_STRANDED_PAYMENT_WARNING =
  "Giving up this payment is final. It cannot be resumed and the agent has to ask for it again. No money moves and nothing is taken back from the network, because this payment was signed but never sent: the reserved funds return to your spendable balance.";

/**
 * What committing to a provider channel costs, said before the first press.
 *
 * The press itself sends no money. What it does is permanent in a way an owner
 * comparing providers would not guess: it signs this wallet's half of the
 * receipt that returns the deposit, and once the provider's half is saved this
 * wallet holds one channel and will not exchange it for another. A second ask
 * for a different channel is refused by
 * `AgentWalletManager::begin_hvm_registry_channel_open`
 * (crates/agent-wallet-core/src/service/hvm_registry_open.rs), because
 * replacing that record would throw away the only bill that gets the first
 * channel's deposit back.
 *
 * So the warning states four things, in this order:
 *  - what the press commits to, and that it moves no money;
 *  - that the deposit which follows cannot be reversed by anyone;
 *  - that the fee and reserved gas are on top of it and are spent either way;
 *  - that a provider which refuses costs nothing at all, because the refusal
 *    lands before any transaction is built.
 *
 * The exact amounts are named beside this by `lockUpLine` and `feeLine`
 * (registryOpen.ts), which know the channel; this sentence does not repeat a
 * number it cannot check.
 */
export const OPEN_PROVIDER_CHANNEL_WARNING =
  "This commits this wallet to one provider channel and one deposit, permanently. The press itself moves no money and costs no fee: it signs your half of a receipt returning the whole deposit, asks your provider for its half and checks it here. Once that receipt is saved this wallet will not swap it for a different channel, because it is the only thing that gets this deposit back. The deposit that follows cannot be reversed by this app, by your provider or by anyone else, and the network fee and reserved gas are charged on top of it and are spent whatever happens next. If your provider will not sign the receipt then no channel opens, nothing is sent and nothing is charged.";

/**
 * What sending the deposit actually does, said before the first press.
 *
 * This is the press that spends the money. `OPEN_PROVIDER_CHANNEL_WARNING`
 * above it covers a press that signs and asks and costs nothing; this one
 * covers a transfer on the chain, and the difference has to be unmistakable to
 * somebody who has already pressed one control on this panel today.
 *
 * Three things, in this order, because that is the order an owner needs them:
 *  - what is locked up, and that nobody can reverse it;
 *  - what it costs on top, and that the cost is spent either way;
 *  - that the full refund is already held, was checked here rather than
 *    promised by the provider, does not expire, and has been held since the
 *    moment the channel opened.
 *
 * The refund sentence is last rather than first on purpose. It is the
 * reassurance, and a warning that opens with its own reassurance is a warning
 * an owner stops reading.
 *
 * The exact deposit and the exact fee are named beside this by `lockUpLine` and
 * `feeLine` (registryFunding.ts), which know the channel; this sentence does
 * not repeat a number it cannot check.
 */
export const FUND_PROVIDER_CHANNEL_WARNING =
  "This sends your deposit. It is an ordinary transfer into the channel contract, in the exact amount named above this, and once it is in a block it cannot be cancelled or reversed by this app, by your provider or by anyone else. The network fee and the reserved gas are charged on top of the deposit, from your main balance, in the exact amount named above this, and they are spent whatever happens to the channel afterwards. What makes this safe is already done: your provider signed a receipt returning the whole deposit before any of this, this wallet checked that signature itself rather than taking your provider's word for it, and you have held that full refund from the moment the channel opened. It never expires, and it pays you without your provider's permission.";

/**
 * What starting a unilateral close actually costs, said before the first press.
 *
 * Four separate facts, and every one of them has to survive the press being
 * made by somebody who is frightened and in a hurry:
 *  - the channel is finished afterwards, and reopening means a new deposit;
 *  - the money is not immediate, because the objection window has to close and
 *    a final claim has to be sent after it;
 *  - the fees are spent even in the case the owner is most afraid of, which is
 *    the provider never coming back at all;
 *  - the cost is more than network fees. This sentence used to say "three
 *    network fees", which on a measured exit understated the charge by a
 *    factor of ten and understated what the owner had to be able to hold by
 *    considerably more, because a registry call is a contract call and the
 *    chain reserves its whole gas budget before running it. It now names the
 *    two parts and points at `feeLine`, which has the exact figures;
 *  - the exact amount is named beside this by `yourMoneyLine`, which knows the
 *    channel; this sentence does not repeat a number it cannot check.
 */
export const EXIT_WITHOUT_PROVIDER_WARNING =
  "This closes the channel for good. It cannot be reopened without a new deposit, and no further payments can be made through it. Your money does not arrive straight away: the chain holds an objection window open first, and a final claim is sent after it closes. It costs network fees and chain running costs from your main balance, in the exact amount named above this, and what is spent is spent whether or not the provider ever comes back.";

export const DESKTOP_IRREVERSIBLE_ACTIONS: readonly DesktopIrreversibleAction[] =
  [
    {
      id: "revoke_phone",
      control: "revoke_phone",
      warning: COMPANION_REVOKE_WARNING,
      renderedAs: "COMPANION_REVOKE_WARNING",
      confirmLabel: "Yes, revoke permanently",
    },
    {
      id: "revoke_agent",
      control: "revoke_agent",
      warning: REVOKE_AGENT_WARNING,
      renderedAs: "REVOKE_AGENT_WARNING",
      confirmLabel: "Confirm permanent revoke",
    },
    {
      id: "emergency_stop",
      control: "disable_all_agent_payments",
      warning: EMERGENCY_STOP_WARNING,
      renderedAs: "EMERGENCY_STOP_WARNING",
      confirmLabel: null,
    },
    {
      id: "approve_exact_transaction",
      control: "approve_exact_transaction",
      warning: APPROVE_TRANSACTION_WARNING,
      renderedAs: "APPROVE_TRANSACTION_WARNING",
      confirmLabel: null,
    },
    {
      id: "reject_payment",
      control: "reject_payment",
      warning: REJECT_PAYMENT_WARNING,
      renderedAs: "REJECT_PAYMENT_WARNING",
      confirmLabel: "Confirm reject",
    },
    {
      id: "abandon_stranded_payment",
      control: "give_up_stranded_payment",
      warning: ABANDON_STRANDED_PAYMENT_WARNING,
      renderedAs: "ABANDON_STRANDED_PAYMENT_WARNING",
      // The warning names the exact amount and recipient beside it, but this
      // one still takes two presses: the first press of a control the owner
      // reached by accident, on a payment they were only waiting for, would
      // throw the payment away.
      confirmLabel: "Confirm give up",
    },
    {
      id: "open_provider_channel",
      control: "open_provider_channel",
      warning: OPEN_PROVIDER_CHANNEL_WARNING,
      renderedAs: "OPEN_PROVIDER_CHANNEL_WARNING",
      // The exact deposit and the exact fee are on screen beside this, and the
      // press still takes a second one. An owner reading the page and comparing
      // providers must not be able to bind this wallet to one of them, for
      // good, by mis-clicking once.
      confirmLabel: "Confirm, open this channel",
    },
    {
      id: "fund_provider_channel",
      control: "fund_provider_channel",
      warning: FUND_PROVIDER_CHANNEL_WARNING,
      renderedAs: "FUND_PROVIDER_CHANNEL_WARNING",
      // The exact deposit and the exact fee are on screen beside this, and the
      // press still takes a second one. This is the only control in the app
      // that exists in order to make money irreversible, and an owner who came
      // back to this page to read where their channel had got to must not be
      // able to spend the deposit by mis-clicking once.
      confirmLabel: "Confirm, send the deposit",
    },
    {
      id: "start_exit_without_provider",
      control: "start_exit_without_provider",
      warning: EXIT_WITHOUT_PROVIDER_WARNING,
      renderedAs: "EXIT_WITHOUT_PROVIDER_WARNING",
      // The exact amount is on screen beside this, and the press still takes a
      // second one: the first press of this control by an owner who only meant
      // to read the page would end a working channel.
      confirmLabel: "Confirm, close this channel",
    },
  ];

/** The warning that belongs beside one control, or "" when it is reversible. */
export function irreversibleWarningFor(control: DesktopControlId): string {
  return (
    DESKTOP_IRREVERSIBLE_ACTIONS.find((entry) => entry.control === control)
      ?.warning ?? ""
  );
}

/** The exact label of the control an irreversible warning belongs to. */
export function irreversibleControlLabel(
  action: DesktopIrreversibleAction,
): string {
  return DESKTOP_CONTROLS[action.control];
}

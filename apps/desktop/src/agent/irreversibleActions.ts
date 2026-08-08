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
    | "abandon_stranded_payment";
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

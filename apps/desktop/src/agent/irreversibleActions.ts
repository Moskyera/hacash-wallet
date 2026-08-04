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
    | "reject_payment";
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

export const EMERGENCY_STOP_WARNING =
  "Disable All Agent Payments blocks new agent payment progress and invalidates active permits. It cannot reverse a transaction that has already been submitted to the network.";

export const REVOKE_AGENT_WARNING =
  "Revoking is permanent. It disconnects this agent, invalidates its sessions and cancels its unsigned pending operations. The same agent cannot be un-revoked.";

export const APPROVE_TRANSACTION_WARNING =
  "Approval signs and broadcasts only this exact commitment. Once it is broadcast it cannot be recalled. Verify the amount, recipient and total debit before continuing.";

export const REJECT_PAYMENT_WARNING =
  "Rejecting is final for this request. No transaction is signed and the agent has to ask again.";

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

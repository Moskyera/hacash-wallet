/**
 * Every control the desktop Agent Wallet UI renders, named once.
 *
 * Two false instructions in this codebase caused a permanent, unrecoverable
 * device revocation. Both had the same shape: a sentence naming a control that
 * either did not exist or did not do what the sentence said. This table exists
 * so that shape can be tested for.
 *
 * Rules this file encodes:
 *  - An instruction may only name a label that appears here.
 *  - Every label here must actually be rendered by the desktop agent UI.
 *  - A label that has been retired must never appear in the sources again,
 *    because every sentence that named it is now a lie.
 *
 * Copy and identifiers only. No control flow, no gate, no validation.
 */
import {
  COMPANION_PAIR_ACTION,
  COMPANION_REVOKE_ACTION,
  COMPANION_START_LINK_ACTION,
  COMPANION_STOP_LINK_ACTION,
} from "./companionPairingFeedback";

export const DESKTOP_CONTROLS = {
  /** Re-reads the wallet, the node and the balance. */
  refresh: "Refresh",
  /** Puts the Agent Wallet address on the clipboard so it can be funded. */
  copy_address: "Copy address",
  /** The only control that clears an emergency stop from this desktop. */
  enable_payments_locally: "Enable locally",
  /** Engages the emergency stop. Never gated: fail-closed stays reachable. */
  disable_all_agent_payments: "Disable All Agent Payments",
  start_connector: "Start the AI agent connector",
  stop_connector: "Stop the AI agent connector",
  /**
   * Replaces "Restart the AI agent connector", which called stop and never
   * started anything. The label now says exactly what the click does.
   */
  clear_failed_connector: "Clear the failed connector",
  pair_local_agent: "Pair local AI agent",
  /**
   * Clears the one-time local-agent pairing code from this desktop. There is no
   * backend cancel for it, so the label promises only what it can deliver.
   */
  forget_local_agent_code: "Forget this pairing code",
  pair_a_phone: COMPANION_PAIR_ACTION,
  turn_on_phone_connection: COMPANION_START_LINK_ACTION,
  turn_off_phone_connection: COMPANION_STOP_LINK_ACTION,
  revoke_phone: COMPANION_REVOKE_ACTION,
  revoke_agent: "Revoke agent",
  cancel_phone_pairing: "Cancel pairing",
  retry_automatic_setup: "Try automatic setup again",
  /**
   * The unlocked UI has no Agent Wallet picker. Locking returns to the unlock
   * screen, which does have one, so this is the honest name for that route.
   */
  lock_and_switch_wallet: "Lock and choose another Agent Wallet",
  open_security: "Open Security",
  open_overview_to_pair_agent: "Go to Overview to pair an agent",
  /**
   * Gives up a signed payment that no phone can confirm any more. It releases
   * the reservation and sends nothing: the core accepts it only for a payment
   * that provably never reached the node.
   */
  give_up_stranded_payment: "Give up this payment",
  /**
   * Drops a confirmation window that ran out unanswered. It moves no money and
   * leaves the payment exactly as it is - same amount, same recipient, same
   * transaction id - and is the step that frees the wallet to offer
   * `replace_the_paired_phone`. It is not a give-up and is never named as one.
   */
  clear_expired_confirmation_window: "Clear the expired confirmation window",
  /**
   * The disclosure that holds the witness rotation wizard on the Security page.
   * It is named by the stranded-payment copy, which has to point somewhere real.
   */
  replace_the_paired_phone: "Replace the paired phone",
  review_exact_transaction: "Review exact transaction",
  approve_exact_transaction: "Approve exact transaction",
  reject_payment: "Reject",
  try_again: "Try again",
  back_to_wallet_selection: "Back to Wallet Selection",
} as const;

export type DesktopControlId = keyof typeof DESKTOP_CONTROLS;
export type DesktopControlLabel = (typeof DESKTOP_CONTROLS)[DesktopControlId];

export const DESKTOP_CONTROL_IDS = Object.keys(
  DESKTOP_CONTROLS,
) as DesktopControlId[];

export function desktopControlLabels(): string[] {
  return DESKTOP_CONTROL_IDS.map((id) => DESKTOP_CONTROLS[id]);
}

export function isDesktopControlLabel(label: string): boolean {
  return desktopControlLabels().includes(label);
}

/**
 * Controls whose label is rendered through a shared constant instead of a
 * literal, because a refusal in Rust or on the phone quotes the same string.
 */
export const DESKTOP_CONTROL_LABEL_TOKENS: Partial<
  Record<DesktopControlId, string>
> = {
  pair_a_phone: "COMPANION_PAIR_ACTION",
  turn_on_phone_connection: "COMPANION_START_LINK_ACTION",
  turn_off_phone_connection: "COMPANION_STOP_LINK_ACTION",
  revoke_phone: "COMPANION_REVOKE_ACTION",
};

/**
 * Strings that named a control which no longer exists, or which named an action
 * the control never performed. None of them may come back.
 */
export const RETIRED_DESKTOP_INSTRUCTIONS: readonly string[] = [
  // Called onStop and nothing else. It stopped; it never restarted.
  "Restart the AI agent connector",
  // Named a wallet switcher that exists nowhere in the unlocked UI.
  "Open that wallet to manage it",
  // The old short label on the one irreversible control on the panel.
  "Revoke device",
];

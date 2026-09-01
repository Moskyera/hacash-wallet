/**
 * What the desktop says and offers about a payment that is waiting on the
 * paired phone.
 *
 * The desktop is where the owner is stuck. The payment was approved here, it is
 * signed here, the reservation is held here, and it is this desktop that then
 * refuses every new agent payment and every phone replacement while the payment
 * is unresolved. So the way out has to be here too.
 *
 * FOUR statuses reach this panel and only the first of them is pre-broadcast.
 * In `submitted_awaiting_final_witness`, `broadcast_uncertain` and
 * `reconciled_awaiting_final_witness` the transaction is already on the
 * network: the money moved, and the payment is one phone signature short of
 * being accounted for. That distinction drives every sentence below, because
 * the same words are true in one case and a lie in the other.
 *
 * Three things this module must never do, and the tests pin all three:
 *  - Say or imply that an unwitnessed pre-broadcast payment was witnessed, paid
 *    or sent. Nothing reached the network in that state.
 *  - Say or imply that a SUBMITTED payment did not happen. It did. The owner is
 *    told so plainly and given the transaction id to check it with.
 *  - Offer a control the core would refuse. `retryable`, `abandonable`,
 *    `anchor_releasable` and `phone_replacement_unblocked` are the core's own
 *    enforcement predicates; nothing here re-derives them.
 *
 * Copy and formatting only. No control flow, no gate, no validation, no call.
 */
import { DESKTOP_CONTROLS } from "./desktopControls";
import type { StrandedWitness } from "./api";

/** The exact name of the phone app that shows the confirm control. */
export const STRANDED_PHONE_APP_NAME = "AI Agent Wallet";

export type StrandedWitnessView = {
  heading: string;
  /** The amount and recipient, so the owner knows what is at stake. */
  summary: string;
  /**
   * Where the owner's money actually is, in one sentence, always present. This
   * is the sentence that must never be wrong in either direction.
   */
  whereTheMoneyIs: string;
  /** The transaction id to look the payment up with, when there is one. */
  transactionId: string | null;
  /** Why this payment is sitting here, in the owner's terms. */
  explanation: string;
  /**
   * The step to try first when it is available. Free, repeatable, and it
   * usually works.
   *
   * When the core says a retry would be refused this says so instead, and says
   * why, rather than inviting a press that cannot do anything. It read "trying
   * again costs nothing and it is safe to try more than once" over a control
   * the core refused outright on mainnet.
   */
  phoneInstruction: string;
  /** Asking the phone again would work right now. Mirrors the core. */
  canRetryPhone: boolean;
  /** True once the window the phone was given has run out. */
  anchorExpired: boolean;
  /** The give-up control may be pressed. Mirrors the core's own predicate. */
  canAbandon: boolean;
  /** Why the give-up control is withheld, or "" when it is offered. */
  abandonWithheldReason: string;
  /** What the owner may still have to do afterwards, said before the press. */
  afterAbandon: string;
  /** The dead confirmation window may be cleared away. Mirrors the core. */
  canReleaseAnchor: boolean;
  /** What clearing it does, and what it does not do, said before the press. */
  releaseExplanation: string;
  /** Replacing the paired phone is available right now. Mirrors the core. */
  canReplacePhone: boolean;
  /**
   * The next step after clearing the window, or why the phone replacement is
   * not the answer here. Never empty.
   */
  replacePhoneGuidance: string;
};

/**
 * Turns the core's answer into what the Security page renders, or null when no
 * payment is waiting.
 */
export function strandedWitnessView(
  stranded: StrandedWitness | null,
  formatUnits: (units: string) => string,
): StrandedWitnessView | null {
  if (!stranded) return null;

  // An anchor exists and nothing outstanding could still confirm it: that is
  // exactly the state in which the window the phone was given has run out. The
  // core reports it directly rather than leaving this to arithmetic on a clock.
  const anchorExpired = stranded.anchor_issued && stranded.anchor_releasable;
  const submitted = stranded.submitted;

  const whereTheMoneyIs = submitted
    ? stranded.status === "broadcast_uncertain"
      ? "This payment was sent to the network. The node did not give an answer this wallet could verify, " +
        "so whether it was accepted is not yet known here. Check the transaction id below before assuming either way."
      : stranded.status === "reconciled_awaiting_final_witness"
        ? "This payment was sent to the network and confirmed on chain. The money has left your wallet. " +
          "What is missing is only your phone's final confirmation of it."
        : "This payment was sent to the network. The money has left your wallet. " +
          "What is missing is only your phone's confirmation of it."
    : "Nothing has been sent to the network and no money has moved.";

  const explanation = !stranded.anchor_issued
    ? "This payment is waiting for your paired phone to confirm it."
    : anchorExpired
      ? "Your phone was given a confirmation window for this payment and it ran out before the confirmation came back. " +
        "Opening the payment on your phone again starts a new window."
      : "Your phone has an open confirmation window for this payment right now.";

  // The phone step is offered only while the core would honour it. Where it
  // would not, the owner is told which of the two reasons applies, because they
  // are opposites: a confirmation already on its way in is the payment
  // finishing, and a wallet that cannot open a window at all is a dead end whose
  // only way out is giving the payment up.
  const phoneInstruction = stranded.retryable
    ? `Open the ${STRANDED_PHONE_APP_NAME} on your paired phone and confirm this payment. ` +
      (submitted
        ? "Confirming records what already happened; it does not repeat the payment, and it cannot move money twice."
        : "Trying again costs nothing and moves no money, and it is safe to try more than once.")
    : stranded.network_supports_witness_retry
      ? "Your phone has already sent a confirmation for this payment and this wallet is finishing it. " +
        "There is nothing to confirm again, and nothing here needs pressing."
      : "This wallet cannot ask your phone to confirm a payment on this network, so opening the " +
        `${STRANDED_PHONE_APP_NAME} again will not move this payment on. ` +
        (submitted
          ? "The payment is on the network either way; the transaction id below is how to check it."
          : "Nothing has been sent to the network and no money has moved. Giving the payment up returns the reserved funds to your spendable balance.");

  // The give-up control exists only for a payment that provably never reached
  // the node. Past that point taking it would assert the payment did not
  // happen when it did, and the core refuses it for exactly that reason - so
  // the reason the owner is shown is that one, not a timing one.
  const abandonWithheldReason = stranded.abandonable
    ? ""
    : submitted
      ? "This payment has already been sent to the network, so it cannot be given up: nothing here may say a payment " +
        "did not happen when it did. It stays until your phone confirms it."
      : "Your phone still has an open confirmation window for this payment, so it may be confirming it right now. " +
        "This becomes available once that window runs out, within about five minutes.";

  return {
    heading: submitted
      ? "A payment you already made is waiting for your phone"
      : "A payment is waiting for your phone",
    summary: `${formatUnits(stranded.amount_units)} to ${stranded.recipient}`,
    whereTheMoneyIs,
    transactionId: stranded.transaction_id,
    explanation,
    phoneInstruction,
    canRetryPhone: stranded.retryable,
    anchorExpired,
    canAbandon: stranded.abandonable,
    abandonWithheldReason,
    // The tail of this sentence used to name Replace the paired phone as "the
    // only thing that clears that". On mainnet that control answers
    // WitnessRotationNetworkUnsupported, so the sentence sent a person to a
    // button that refuses. It is only named where it can actually be used.
    afterAbandon:
      "After this, new agent payments work again. If your phone had already accepted this payment before it lost " +
      "contact, it will refuse the next one too" +
      (stranded.network_supports_witness_retry
        ? `, and the only thing that clears that is ${DESKTOP_CONTROLS.replace_the_paired_phone}, further down this page.`
        : ". Replacing the paired phone is the fix for that, and it is not available on this network yet."),
    canReleaseAnchor: stranded.anchor_releasable,
    releaseExplanation:
      "Clearing the expired confirmation window changes nothing about this payment: the same amount, the same " +
      "recipient and the same transaction id, still waiting for your phone. It only frees this wallet to " +
      `offer ${DESKTOP_CONTROLS.replace_the_paired_phone}.`,
    canReplacePhone: stranded.phone_replacement_unblocked,
    replacePhoneGuidance: stranded.phone_replacement_unblocked
      ? `${DESKTOP_CONTROLS.replace_the_paired_phone} keeps this payment: the new phone confirms it and it goes through. ` +
        "This is the way out when your phone has accepted this payment once and will not accept it again."
      : submitted
        ? "Replacing the paired phone cannot resolve this payment, because a newly paired phone will not confirm a " +
          "payment it never saw before it was sent. Your existing paired phone is the only one that can finish this."
        : stranded.anchor_releasable
          ? `Clear the expired confirmation window first, then ${DESKTOP_CONTROLS.replace_the_paired_phone} becomes available.`
          : stranded.network_supports_witness_retry
            ? "Your phone still has an open confirmation window, so replacing it is not offered yet."
            // The line above was the unconditional fallback, and on mainnet it
            // was simply false: no confirmation window was ever opened, and
            // this wallet cannot open one, because the anchor is testnet only.
            // A person read an explanation about a window that does not exist
            // and had no way to know the real reason.
            : "Replacing the paired phone is not available on this network yet, so it is not offered here.",
  };
}

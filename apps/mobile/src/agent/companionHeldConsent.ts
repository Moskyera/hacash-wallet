/**
 * What this phone is still holding for one payment, and how to stop holding it.
 *
 * A consent record - the owner's approval of a payment on this handset, or
 * their confirmation to witness one approved on the desktop - is written
 * durably before anything is fetched or signed. That is deliberate: it is the
 * record that makes the rollback witness an act rather than an automatic
 * co-signature, and the native side refuses any anchor that does not match one.
 *
 * The problem was the other end. A record that was never retired blocks the
 * pairing-only reset, blocks pairing again, and blocks every other payment this
 * phone could approve or witness - and the one control that could clear it, the
 * witness card, disappears the moment the desktop stops offering the operation.
 * The phone then holds something it cannot see, cannot use and cannot let go.
 *
 * Most of that is now retired without asking: the desktop's own authenticated
 * status snapshot says which operations are still waiting on this phone, and a
 * record naming anything else is discarded on the next sync. This module is the
 * last exit, for the case no desktop will ever answer again - a revoked phone,
 * or a desktop that is gone. It is copy only. Nothing here signs, cancels,
 * approves or witnesses anything, and discarding cannot make an unwitnessed
 * payment look witnessed: it removes the record that admits an anchor, so it
 * can only ever make witnessing harder.
 */

import { formatCompanionTime, formatHacUnits } from "./companionView";
import { MAX_COMPANION_DISCARDED_CONSENTS } from "./types";
import type {
  CompanionDiscardedConsentView,
  CompanionPendingConsentView,
} from "./types";

/** The words the native side requires, typed by the owner. */
export const COMPANION_DISCARD_CONSENT_PHRASE = "DISCARD THIS CONFIRMATION";

export const COMPANION_DISCARD_CONSENT_ACTION = "Discard this confirmation";

export const COMPANION_HELD_CONSENT_TITLE = "This phone is holding one payment";

/** One labelled fact about the payment, in the words the phone showed. */
export type CompanionConsentFact = { label: string; value: string };

function consentKindNoun(kind: CompanionPendingConsentView["kind"]): string {
  return kind === "pilot_approval"
    ? "your approval of this payment"
    : "your confirmation to witness this payment";
}

/**
 * The exact payment being held, as labelled facts.
 *
 * The amount and the recipient are the ones the phone showed when the owner
 * pressed confirm, so what is discarded is what they read.
 */
export function heldConsentFacts(
  consent: CompanionPendingConsentView,
): CompanionConsentFact[] {
  return [
    { label: "Amount", value: formatHacUnits(consent.amountUnits) },
    { label: "To", value: consent.recipient },
    { label: "Payment", value: consent.operationId },
    { label: "Held since", value: formatCompanionTime(consent.recordedAtUnix) },
  ];
}

/**
 * Why the phone is stuck, said before the owner is offered the way out.
 */
export function heldConsentExplanation(
  consent: CompanionPendingConsentView,
): string {
  return `This phone is still holding ${consentKindNoun(consent.kind)}. While it does, this phone cannot be reset, cannot be paired again, and cannot approve or witness any other payment. If the desktop is still running, connect and sync instead: the phone clears this by itself once the desktop confirms the payment is no longer waiting on you.`;
}

/**
 * What the discard does and, more importantly, what it does not do.
 *
 * Stated before the press, not after it. Every line here is a fact about the
 * native implementation, not reassurance: the discard clears one durable record
 * and nothing else.
 */
export const COMPANION_DISCARD_CONSENT_EFFECTS = [
  "It ends only this phone's intent to sign this payment.",
  "It does not cancel the payment. If the desktop already signed or sent it, that does not change.",
  "It does not un-sign anything. Anything this phone already signed stays signed, and the record of which wallet states it has witnessed is untouched.",
  "It does not mark the payment as witnessed. Afterwards this phone refuses to witness it at all, unless the desktop offers it again and you confirm again.",
  "It deletes no pairing and no secure identity.",
] as const;

/** The receipt for a record this phone stopped holding. */
export type CompanionDiscardNotice = {
  title: string;
  body: string;
  facts: CompanionConsentFact[];
};

function discardReasonSentence(reason: string): string {
  if (reason === "desktop_no_longer_awaits_this_phone") {
    return "The desktop confirmed this payment is no longer waiting on this phone, so the phone stopped holding it.";
  }
  if (reason === "aged_out_on_this_phone") {
    return "No desktop confirmed anything about this payment for a day, so the phone stopped holding it rather than stay blocked.";
  }
  if (reason === "owner_discarded") {
    return "You discarded this on this phone.";
  }
  return "This phone stopped holding this payment.";
}

/**
 * The notice shown after a record is retired, automatically or by the owner.
 *
 * A discard is never silent. This says nothing about whether the payment
 * succeeded - the phone does not know that and must not imply it - only that
 * this phone is no longer holding it, and where to go and look.
 */
export function discardedConsentNotice(
  record: CompanionDiscardedConsentView,
): CompanionDiscardNotice {
  return {
    title: "This phone stopped holding a payment",
    body: `${discardReasonSentence(record.reason)} This does not tell you whether the payment went through. Check it in AI Agent Wallet on HPAY Desktop.`,
    facts: [
      { label: "Amount", value: formatHacUnits(record.amountUnits) },
      { label: "To", value: record.recipient },
      { label: "Payment", value: record.operationId },
      {
        label: "Stopped holding",
        value: formatCompanionTime(record.discardedAtUnix),
      },
    ],
  };
}

/** The heading over the whole history, once there is more than one receipt. */
export const COMPANION_DISCARD_HISTORY_TITLE = "Payments this phone stopped holding";

/**
 * What the cap dropped, said in full rather than left for the owner to guess.
 *
 * The history is bounded, because an unbounded one on a handset is its own
 * defect. Bounded is not the same as silent: when the cap pushes the oldest
 * receipts out, the phone says how many went and that they are not coming
 * back, so the owner knows to look on the desktop instead of assuming the
 * list below is everything that ever happened.
 *
 * `null` when nothing has been dropped, which is every ordinary phone.
 */
export function discardedConsentOverflowNotice(dropped: string): string | null {
  if (!/^(0|[1-9][0-9]*)$/.test(dropped)) {
    throw new Error("The discarded payment count is not a decimal number.");
  }
  if (dropped === "0") return null;
  const receipts = dropped === "1" ? "receipt" : "receipts";
  return `This phone keeps the last ${MAX_COMPANION_DISCARDED_CONSENTS} of these and no more, so ${dropped} older ${receipts} ${dropped === "1" ? "is" : "are"} no longer shown here. Nothing about those payments was changed, and they can still be checked in AI Agent Wallet on HPAY Desktop.`;
}

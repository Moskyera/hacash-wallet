/**
 * Presentation-only view model for the gap between "the desktop signed a
 * pairing confirmation" and "the phone's acknowledgement arrived here".
 *
 * During that gap the desktop is waiting on a human action that happens on the
 * phone. Nothing renders for it historically, so the owner sees the six digit
 * code, no next step, and concludes that "Yes, the codes match" is broken.
 *
 * This module holds copy and formatting only. It performs no pairing work, has
 * no side effects, and can never approve anything: it decides what to say, not
 * what to do.
 */

/**
 * The exact label of the button the owner has to tap in the phone app.
 *
 * It must stay identical to COMPANION_SEND_CONFIRMATION_ACTION in
 * apps/mobile/src/agent/companionStatus.ts. An instruction that names a button
 * the phone does not have is worse than no instruction at all, and
 * companionWaiting.test.ts pins the two together.
 */
export const companionPhoneConfirmationAction =
  "Send this phone's confirmation to the desktop";

/** The exact name of the phone app that shows that button. */
export const companionPhoneAppName = "AI Agent Wallet";

export type CompanionPairingWaitingInput = {
  /** A pairing offer exists on this desktop. */
  hasOffer: boolean;
  /** The desktop already signed the confirmation for this pairing. */
  hasConfirmation: boolean;
  /** The phone's acknowledgement reached this desktop over the private LAN. */
  ackReceived: boolean;
  /** An acknowledgement was scanned locally through the manual fallback. */
  hasScannedAck: boolean;
  /** Seconds of offer validity left, or null when the expiry is unknown. */
  secondsRemaining: number | null;
};

export type CompanionPairingWaitingView = {
  heading: string;
  phoneApp: string;
  phoneAction: string;
  phoneInstruction: string;
  validity: string;
  expired: boolean;
  restart: string;
  restartAction: string | null;
  humanCheck: string;
};

/**
 * Returns the waiting copy while the phone's confirmation is outstanding, or
 * null when there is nothing to wait for.
 */
export function companionPairingWaitingView(
  input: CompanionPairingWaitingInput,
): CompanionPairingWaitingView | null {
  if (!input.hasOffer || !input.hasConfirmation) return null;
  // The acknowledgement is here: the finish step owns the screen instead.
  if (input.ackReceived) return null;
  // The manual fallback already produced an acknowledgement on this desktop.
  if (input.hasScannedAck) return null;

  const expired =
    input.secondsRemaining !== null && input.secondsRemaining <= 0;

  return {
    heading: "Waiting for the confirmation from your phone",
    phoneApp: companionPhoneAppName,
    phoneAction: companionPhoneConfirmationAction,
    phoneInstruction: `On the phone, open the ${companionPhoneAppName} and tap ${companionPhoneConfirmationAction}. This desktop cannot finish pairing until the phone sends that confirmation. Tapping it costs nothing and moves no money, and it is safe to tap more than once.`,
    validity: expired
      ? "This pairing request has expired. Nothing was paired and your phone was not authorized."
      : `This pairing request expires in ${formatPairingValidity(input.secondsRemaining)}.`,
    expired,
    restart: expired
      ? "Choose Start again, then scan the new QR code with your phone. The expired code can no longer be used."
      : "If the phone shows nothing, choose Cancel pairing and run Pair a phone again. Starting over is always safe.",
    restartAction: expired ? "Start again" : null,
    humanCheck:
      "Nothing is paired automatically. You still have to compare the six digits on both devices yourself and choose Yes, the codes match on this desktop.",
  };
}

/** Friendly remaining validity, for owners who do not read a mm:ss clock. */
export function formatPairingValidity(seconds: number | null): string {
  if (seconds === null || !Number.isFinite(seconds)) return "a few minutes";
  const whole = Math.max(0, Math.floor(seconds));
  if (whole < 60) return plural(whole, "second");
  const minutes = Math.floor(whole / 60);
  const remainder = whole % 60;
  return remainder === 0
    ? plural(minutes, "minute")
    : `${plural(minutes, "minute")} ${plural(remainder, "second")}`;
}

function plural(count: number, unit: string): string {
  return `${count} ${unit}${count === 1 ? "" : "s"}`;
}

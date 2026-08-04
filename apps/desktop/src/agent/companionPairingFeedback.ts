/**
 * Presentation-only view models for the two things a failed phone pairing used
 * to hide from its owner.
 *
 * 1. The reason. A refused pairing action put its message in the alert at the
 *    top of the page, above the connector and metrics panels and off screen
 *    from the pairing wizard. A failed click therefore looked like a dead
 *    button. These helpers keep the reason attached to the exact step that
 *    produced it so the panel can render it next to that button.
 * 2. The retry budget. A pairing answers a bounded number of signed phone
 *    requests and is then destroyed. Spending that budget silently is what
 *    turned the last try into a pairing that simply stopped responding.
 *
 * This module holds copy and formatting only. It performs no pairing work, has
 * no side effects, and can never approve, complete or cancel anything.
 */

/** The pairing actions an owner can press, one per button that can fail. */
export type CompanionPairingStep =
  | "start"
  | "request"
  | "acknowledgement"
  | "finish"
  | "confirm"
  | "cancel"
  | "reconnect";

/** The last refused pairing action, or null when nothing has failed. */
export type CompanionStepFailure = {
  step: CompanionPairingStep;
  message: string;
} | null;

/**
 * The exact label of the button that starts a first pairing for a phone.
 *
 * Deliberately unchanged. Eleven refusals in `AgentWalletError` send the owner
 * to "Pair a phone" by name, and the phone app quotes it too. Renaming the
 * button would silently turn every one of those instructions into a lie, which
 * is the exact failure this pass exists to remove. What was missing was never
 * the name; it was any statement of when this button is the right one.
 */
export const COMPANION_PAIR_ACTION = "Pair a phone";

/** The exact label of the button that starts the listener for a paired phone. */
export const COMPANION_START_LINK_ACTION = "Turn on the phone connection";

/** The exact label of the button that stops that listener. */
export const COMPANION_STOP_LINK_ACTION = "Turn off the phone connection";

/** The exact label of the first press of the permanent revoke control. */
export const COMPANION_REVOKE_ACTION = "Revoke this phone permanently";

/** Last-resort copy when a rejection carries nothing readable at all. */
export const COMPANION_UNKNOWN_FAILURE =
  `The phone pairing step failed and reported no reason. Nothing was paired and no money moved. Choose Cancel pairing and run ${COMPANION_PAIR_ACTION} again.`;

/**
 * Raw refusals that are the Display of an internal type rather than a sentence
 * written for an owner, and the sentence shown in their place.
 *
 * Only strings that name no cause and no next action are listed. A refusal that
 * already explains itself, which is most of `AgentWalletError`, is left exactly
 * as Rust wrote it: this table may improve wording, never replace a specific
 * reason with a vaguer one.
 *
 * Matching is on lower-cased substrings so a Display wrapped inside a longer
 * message is still recognised.
 */
const COMPANION_OPAQUE_REFUSALS: ReadonlyArray<{ match: string; text: string }> = [
  {
    // AgentWalletError::CompanionAuthorizationFailed.
    match: "companion device authorization failed",
    text: "This Agent Wallet did not accept that phone as an authorized companion, so nothing was paired and no money moved. Check Authorized mobile devices above: a phone that is not listed has never finished pairing here, and a phone listed as Revoked can never be paired again.",
  },
  {
    // LanRuntimeError::Backend, raised on either side of the private link.
    match: "companion backend rejected the operation",
    text: "The phone connection was refused before anything was exchanged, so nothing was paired and no money moved. The saved pairing on one of the two devices no longer matches the other. Choose Cancel pairing, run " +
      COMPANION_PAIR_ACTION +
      " here and pair the phone again from the start.",
  },
  {
    // A bare end of stream. On the desktop this is the phone going away.
    match: "early eof",
    text: `The phone stopped answering before the step finished, so nothing was paired and no money moved. Check that the phone is unlocked, has the AI Agent Wallet app open and is on the same Wi-Fi as this desktop, then choose Cancel pairing and run ${COMPANION_PAIR_ACTION} again.`,
  },
  {
    match: "companion lan operation timed out",
    text: `The phone did not answer in time, so nothing was paired and no money moved. Check that the phone is unlocked, has the AI Agent Wallet app open and is on the same Wi-Fi as this desktop, then choose Cancel pairing and run ${COMPANION_PAIR_ACTION} again.`,
  },
  {
    match: "companion lan connection or rate limit was reached",
    text: "Too many phone connection attempts were made in a short time, so this one was refused. Nothing was paired and no money moved. Wait a minute, then try again.",
  },
  {
    match: "not a private address",
    text: "The phone connection only runs on your own private Wi-Fi, and the address in Advanced connection settings is not a private one. Nothing was paired. Clear that field, choose Try automatic setup again, then pair the phone.",
  },
  {
    match: "plaintext or protocol downgrade",
    text: "Data arrived that was not fully encrypted, so this desktop refused it and closed the connection. Nothing was paired, accepted or spent. Move both devices onto your own private Wi-Fi and pair again.",
  },
];

/**
 * Replaces an opaque internal refusal with an owner-facing sentence, or returns
 * the message unchanged when it already names a cause and a next action.
 */
export function companionOwnerFacingRefusal(message: string): string {
  const lowered = message.toLowerCase();
  const rule = COMPANION_OPAQUE_REFUSALS.find((candidate) =>
    lowered.includes(candidate.match),
  );
  return rule ? rule.text : message;
}

/**
 * Turns whatever a rejected pairing call threw into one readable line.
 *
 * Tauri rejects with a plain string, the browser layer with an `Error`, and a
 * few paths with neither. None of them may reach the owner as "[object
 * Object]" or as an empty alert that reads as a dead button.
 */
export function companionActionErrorMessage(reason: unknown): string {
  const raw =
    reason instanceof Error
      ? reason.message
      : typeof reason === "string"
        ? reason
        : typeof reason === "object" &&
            reason !== null &&
            "message" in reason &&
            typeof (reason as { message: unknown }).message === "string"
          ? (reason as { message: string }).message
          : "";
  const trimmed = raw.trim();
  return trimmed.length > 0
    ? companionOwnerFacingRefusal(trimmed)
    : COMPANION_UNKNOWN_FAILURE;
}

/**
 * The message to render beside one specific button, or "" when that button is
 * not the one that failed.
 */
export function companionStepErrorMessage(
  failure: CompanionStepFailure,
  step: CompanionPairingStep,
): string {
  if (!failure || failure.step !== step) return "";
  return failure.message;
}

/**
 * What a revoked phone means, and the only two ways forward.
 *
 * Revocation is an epoch cut: it durably invalidates every message that phone
 * ever signed, and the phone keeps its hardware identity across a factory
 * reset, so a revoked identity must never be able to let itself back in. That
 * is deliberate and is not changed here. What was missing is that the desktop
 * never said so, and the refusal used to send the owner to "reset the companion
 * app", which cannot work for exactly the same reason.
 *
 * Copy only. Nothing here admits, revives or re-authorizes anything.
 */
export type CompanionRevokedGuidance = {
  /** Why the record can never come back. */
  permanence: string;
  /** The advice that looks obvious and cannot work. */
  ineffective: string;
  /** The routes that do work, best first. */
  options: string[];
};

export const COMPANION_REVOKED_GUIDANCE: CompanionRevokedGuidance = {
  permanence:
    "Revocation is permanent. The revoked record is kept forever and this phone can never be paired again while it presents the same identity. That is deliberate: the phone keeps its hardware identity even after a factory reset, so a revoked phone must never be able to re-admit itself.",
  ineffective:
    "Resetting the companion app on the phone does not help. That reset clears pairing state only and keeps the same Android identity on purpose, so this desktop refuses it again for the same reason.",
  options: [
    "Give this phone a new mobile identity. In the HPAY companion app on the phone, open Mobile companion identity and follow Phone revoked on the desktop. Once the phone presents a genuinely new identity it pairs here as a first-time phone, and the revoked record stays revoked.",
    "Or pair a different phone. A different handset has a different identity and pairs normally today, with no change to this Agent Wallet.",
  ],
};

/**
 * The marker the Rust refusal for a revoked device carries.
 *
 * `AgentWalletError::PairingDeviceRevoked` is the only refusal that says
 * revocation is permanent, so matching on it names that one cause without
 * inventing a parallel error channel.
 */
const REVOKED_REFUSAL_MARKER = "revocation is permanent";

/**
 * The guidance to show beside a control that was refused because the phone is
 * revoked, or null for every other failure.
 */
export function companionRevokedDeviceGuidance(
  reason: unknown,
): CompanionRevokedGuidance | null {
  const message = companionActionErrorMessage(reason).toLowerCase();
  return message.includes("revoked") && message.includes(REVOKED_REFUSAL_MARKER)
    ? COMPANION_REVOKED_GUIDANCE
    : null;
}

/** The status line for one revoked device row. Never just a date. */
export function companionRevokedDeviceLabel(revokedAt: string): string {
  return `Revoked ${revokedAt} · Permanent · Cannot be paired again`;
}

/**
 * The status line for one working device row.
 *
 * "Paired <date> - Read only" said nothing about whether the phone could
 * actually reach this desktop, which is a different question with a different
 * control, so the two were constantly confused.
 */
export function companionAuthorizedDeviceLabel(
  pairedAt: string,
  linkOn: boolean,
): string {
  return linkOn
    ? `Authorized ${pairedAt} · Read only · Phone connection is on`
    : `Authorized ${pairedAt} · Read only · Phone connection is off`;
}

/**
 * The warning shown on the second press of Revoke device.
 *
 * Revoking is the one action in this panel that cannot be undone, and the
 * previous confirmation said nothing at all.
 */
export const COMPANION_REVOKE_WARNING =
  "Revoking is permanent and cannot be undone. This phone can never be paired again with the same identity, even after a factory reset. Do this only if the phone is lost, sold or compromised. To fix a phone that simply will not connect, run Pair a phone again instead.";

/**
 * One control on this panel, and the one situation it is for.
 *
 * Five controls used to sit side by side with nothing to separate them: two of
 * them start something, two stop something, and one is permanent. An owner
 * whose phone simply would not connect had no way to tell which was theirs, and
 * the permanent one was the shortest word on screen.
 */
export type CompanionActionGuideEntry = {
  /** The exact button label, as rendered. */
  action: string;
  /** The one situation this button is the right answer to. */
  when: string;
  /** What pressing it costs or cannot be undone. */
  cost: string;
};

export const COMPANION_ACTION_GUIDE: readonly CompanionActionGuideEntry[] = [
  {
    action: COMPANION_PAIR_ACTION,
    when: "Use this the first time you connect a phone, and any time a phone will not pair and you want to start the whole setup again.",
    cost: "Costs nothing and moves no money. It shows a QR code that stops working after a few minutes.",
  },
  {
    action: COMPANION_START_LINK_ACTION,
    when: "Use this when a phone is already listed under Authorized mobile devices but says it cannot reach this desktop. It does not pair anything.",
    cost: "Costs nothing and moves no money. It opens the encrypted connection on your private Wi-Fi only.",
  },
  {
    action: COMPANION_STOP_LINK_ACTION,
    when: "Use this to close the connection to your phone for now. Paired phones stay paired.",
    cost: "Costs nothing. Your phone stops seeing this wallet until you turn the connection on again.",
  },
  {
    action: COMPANION_REVOKE_ACTION,
    when: "Use this only if a phone is lost, sold or compromised. It is not a way to fix a phone that will not connect.",
    cost: "This cannot be undone. That phone can never be paired again while it presents the same identity, even after a factory reset.",
  },
];

export type CompanionAttemptBudget = {
  /** Signed phone requests this pairing has already answered. */
  attemptsUsed: number;
  /** Tries left before the pairing is destroyed. */
  attemptsRemaining: number;
  /** Total tries this pairing will ever answer. */
  maxAttempts: number;
};

export type CompanionAttemptBudgetView = {
  /** Short badge, e.g. "Attempt 2 of 5". */
  label: string;
  /** One sentence naming what happens when the budget runs out. */
  detail: string;
  /** Exactly one try left. */
  lastTry: boolean;
  /** No tries left; the pairing is already gone. */
  exhausted: boolean;
};

/**
 * Renders the bounded retry budget, or null when the desktop did not report a
 * usable one. A missing budget must never invent an "Attempt 1 of 1".
 */
export function companionAttemptBudgetView(
  budget: Partial<CompanionAttemptBudget> | null | undefined,
): CompanionAttemptBudgetView | null {
  if (!budget) return null;
  const max = wholeCount(budget.maxAttempts);
  const used = wholeCount(budget.attemptsUsed);
  if (max === null || used === null || max < 1) return null;

  const reported = wholeCount(budget.attemptsRemaining);
  // The counters come from one bounded manager-side budget; clamp anyway so a
  // surprising payload can never render a negative or runaway count.
  const remaining = Math.max(0, Math.min(reported ?? max - used, max));
  const exhausted = remaining <= 0;
  const lastTry = remaining === 1;
  const attempt = Math.min(used + 1, max);

  return {
    label: exhausted
      ? `All ${max} tries used`
      : `Attempt ${attempt} of ${max}`,
    detail: exhausted
      ? "This pairing has no tries left. Choose Cancel pairing and run Pair a phone again."
      : lastTry
        ? "1 try left. If this one is refused, the pairing is cancelled and you start again."
        : `${remaining} tries left before this pairing is cancelled.`,
    lastTry,
    exhausted,
  };
}

function wholeCount(value: unknown): number | null {
  if (typeof value !== "number") return null;
  if (!Number.isSafeInteger(value) || value < 0) return null;
  return value;
}

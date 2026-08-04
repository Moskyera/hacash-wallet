/**
 * Owner-facing wording for the phone half of the companion flow.
 *
 * This module is copy only. It performs no pairing, opens no connection, reads
 * no key and has no side effect. It decides what the phone SAYS, never what it
 * DOES, so nothing here can weaken device admission, authentication, encryption,
 * replay protection or the fail-closed behaviour that produced the message.
 *
 * Two failures of wording, not of cryptography, defeated a real owner:
 *
 * 1. One status string meant two different things. "Paired, disconnected" was
 *    shown both for a phone the desktop had genuinely admitted and for one the
 *    desktop had never finalized and therefore refuses on every attempt. Those
 *    are opposite situations with opposite next steps.
 * 2. A refusal arrived as the Display of a Rust enum. "companion backend
 *    rejected the operation" names no cause and no next action, and several
 *    unrelated local faults are flattened into that one string.
 *
 * Every state below has a label no other state uses, and every mapped failure
 * names a cause and an action the owner can actually take.
 */

/**
 * Where this phone stands with the desktop. Distinct on purpose: no two of
 * these may ever render the same sentence.
 */
export type CompanionPairingState =
  /** No pairing exists on this phone at all. */
  | "not_paired"
  /** A pairing ceremony is open on this phone and is not finished. */
  | "pairing_in_progress"
  /** This phone finished its part; the desktop has not finalized it. */
  | "waiting_for_desktop"
  /** Both sides finished pairing. No live connection at the moment. */
  | "paired_not_connected"
  /** The desktop closed the connection during device authentication. */
  | "refused_by_desktop"
  /** Authenticated, but no fully validated snapshot has arrived yet. */
  | "connected_checking_data"
  /** Authenticated, and the latest desktop data passed every check. */
  | "connected";

export type CompanionPairingStateView = {
  state: CompanionPairingState;
  /** Header badge. Short, and unique across every state. */
  pill: string;
  /** Short status line. Unique across every state. */
  label: string;
  /** What the state actually means, in the owner's terms. */
  detail: string;
  /** The next thing to do, or "" when nothing is required. */
  nextAction: string;
};

export type CompanionPairingStateInput = {
  /** A pairing is stored on this phone. */
  configured: boolean;
  /** The desktop has not finalized this pairing, as far as this phone knows. */
  pendingPairingFinalization: boolean;
  /** A pairing ceremony is open on this screen right now. */
  pairingInProgress: boolean;
  /** An authenticated native session exists. */
  hasSession: boolean;
  /** A snapshot that passed every validation is being shown. */
  hasTrustedSnapshot: boolean;
  /** The most recent failure text, if any. */
  lastError: string;
};

/**
 * The exact label of the phone button that sends this phone's confirmation to
 * the desktop. The desktop quotes this string, so both places stay in step.
 */
export const COMPANION_SEND_CONFIRMATION_ACTION =
  "Send this phone's confirmation to the desktop";

/** The exact label of the phone button that opens the desktop connection. */
export const COMPANION_CONNECT_ACTION = "Connect to the desktop";

/**
 * The exact label of the phone button pressed after the desktop side is done.
 * It only re-checks and connects: it cannot approve anything on the desktop.
 */
export const COMPANION_RETRY_AFTER_APPROVAL_ACTION =
  "I approved it on the desktop. Connect now";

/** The exact label of the phone button that clears this phone's pairing. */
export const COMPANION_RESET_PAIRING_ACTION = "Reset this phone's pairing only";

/**
 * The remaining exact button labels, kept here with the others so that any copy
 * naming a control quotes the control instead of describing it. A test walks
 * every label in this file and requires a button carrying it in the sources.
 */

/** The button that mints this phone's secure identity, on the Security tab. */
export const COMPANION_CREATE_IDENTITY_ACTION = "Create mobile identity";

/** The onboarding button that opens the Security tab to make that identity. */
export const COMPANION_OPEN_SECURITY_SETUP_ACTION =
  "Open Security to set up this phone";

/** The camera button that reads the pairing QR code shown by the desktop. */
export const COMPANION_SCAN_QR_ACTION = "Scan desktop QR";

/** The button that reloads the desktop's status into this phone. */
export const COMPANION_REFRESH_ACTION = "Refresh the status now";

/** The button that opens one waiting payment request in full. */
export const COMPANION_REVIEW_APPROVAL_ACTION = "Review exact request";

/** The button that re-reads this phone's own security status. */
export const COMPANION_RECHECK_IDENTITY_ACTION =
  "Check this phone's security status again";

/**
 * The exact label of the button offered after a failed connection attempt.
 *
 * Its own state was the missing affordance: a refused attempt commits nothing,
 * so pressing again is always safe, and for a self-clearing refusal it is the
 * only thing that fixes it. Before this, the sole retry in the whole surface
 * belonged to the pending-pairing panel, which is not rendered once pairing is
 * finalized - so the one state where pressing again would have worked was the
 * one state with no button offering it.
 */
export const COMPANION_TRY_AGAIN_ACTION = "Try connecting again";

/** Why pressing it costs nothing, so an owner does not reach for a reset. */
export const COMPANION_TRY_AGAIN_IS_SAFE =
  "Trying again is safe. A refused attempt changes nothing on this phone or on HPAY Desktop, pays nothing, signs nothing and does not repeat or undo any pairing. You do not need to reset anything for this.";

/**
 * The marker of the transport refusal that genuinely means "the desktop closed
 * the connection during device authentication". It is the one refusal that
 * proves the desktop, not this phone, ended the attempt.
 */
const DESKTOP_REFUSAL_MARKER = "refused this device";

/**
 * The same refusal once companionFailureText has rewritten it for the owner.
 *
 * This was the hole. Everything the phone stores in its error state has already
 * been through that rewrite, and the owner-facing sentence says "refused this
 * phone" while the marker above says "device", so companionDesktopRefusedDevice
 * matched the raw string in tests and nothing at all in the running app. The
 * "Desktop refused" status - the one that sends an owner to look for a revoked
 * record instead of retrying forever - could therefore never appear on screen.
 * Just as narrow as the first marker: no timeout, local fault or unreachable
 * desktop produces this sentence.
 */
const DESKTOP_REFUSAL_OWNER_MARKER = "which means it refused this phone";

/** The permanent refusal: the desktop holds a revoked record for this phone. */
const DEVICE_REVOKED_MARKER = "no longer authorizes this phone";

/**
 * True when the last failure is the desktop refusing this device outright.
 *
 * Deliberately narrow. A timeout, a local fault or an unreachable desktop must
 * never be reported as a refusal, because the next step is different.
 */
export function companionDesktopRefusedDevice(lastError: string): boolean {
  const lowered = lastError.toLowerCase();
  return (
    lowered.includes(DESKTOP_REFUSAL_MARKER) ||
    lowered.includes(DESKTOP_REFUSAL_OWNER_MARKER)
  );
}

/**
 * True when revocation is one of the live explanations for the last failure.
 *
 * Used only to decide whether the revocation reference on the Security tab
 * opens by itself. It never claims the phone was revoked: a silent close means
 * either a pairing the desktop never finished or a revoked record, and the
 * phone cannot tell those apart. A named revocation is certain; a refusal is
 * not, and the text it opens says so.
 */
export function companionRevocationSuspected(lastError: string): boolean {
  return (
    lastError.toLowerCase().includes(DEVICE_REVOKED_MARKER) ||
    companionDesktopRefusedDevice(lastError)
  );
}

/**
 * The single status shown for the phone-to-desktop link.
 *
 * Order matters: a pairing the desktop never finalized is decided before the
 * plain "not connected" branch, because the desktop holds no admission record
 * for it and refuses every attempt. Calling that "paired" is the exact lie that
 * cost an owner two days.
 */
export function companionPairingStateView(
  input: CompanionPairingStateInput,
): CompanionPairingStateView {
  if (!input.configured) {
    return {
      state: input.pairingInProgress ? "pairing_in_progress" : "not_paired",
      pill: input.pairingInProgress ? "Pairing" : "Not paired",
      label: input.pairingInProgress
        ? "Pairing in progress on this phone"
        : "Not paired with a desktop",
      detail: input.pairingInProgress
        ? "Pairing has started on this phone and is not finished. Nothing is linked yet."
        : "This phone is not linked to an Agent Wallet on any desktop. It holds no wallet key and can see nothing.",
      nextAction: input.pairingInProgress
        ? "Follow the steps on this screen. Nothing is linked until the same six digits are confirmed on both devices."
        : `Open the Security tab, use ${COMPANION_CREATE_IDENTITY_ACTION} once, then use ${COMPANION_SCAN_QR_ACTION} to read the code shown by HPAY Desktop.`,
    };
  }
  if (input.pendingPairingFinalization) {
    return {
      state: "waiting_for_desktop",
      pill: "Waiting for desktop",
      label: "Waiting for the desktop to approve this phone",
      detail:
        "This phone finished its part. HPAY Desktop has not approved this phone yet, so the desktop does not recognise it and refuses every connection it attempts.",
      nextAction:
        "On HPAY Desktop open AI Agent Wallet, find Pair your phone, check that the six digits match and choose Yes, the codes match.",
    };
  }
  if (input.hasSession) {
    return input.hasTrustedSnapshot
      ? {
          state: "connected",
          pill: "Connected",
          label: "Connected and verified",
          detail:
            "The encrypted connection to HPAY Desktop is open and the latest desktop data passed every check.",
          nextAction: "",
        }
      : {
          state: "connected_checking_data",
          pill: "Connected, checking",
          label: "Connected. Checking the desktop's data",
          detail:
            "The encrypted connection is open. No wallet figure is shown until a fresh snapshot passes every check.",
          nextAction: "",
        };
  }
  if (companionDesktopRefusedDevice(input.lastError)) {
    return {
      state: "refused_by_desktop",
      pill: "Desktop refused",
      label: "Paired on this phone, but the desktop refused it",
      detail:
        "HPAY Desktop closed the connection without answering, which means it refused this phone. From the phone alone HPAY cannot tell whether pairing was never finished on the desktop or this phone was revoked there.",
      nextAction:
        "On HPAY Desktop open AI Agent Wallet and read Authorized mobile devices. If this phone is not listed, finish pairing there. If it is listed as Revoked, open Phone revoked on the desktop in the Security tab of this app.",
    };
  }
  return {
    state: "paired_not_connected",
    pill: "Paired, not connected",
    label: "Paired. Not connected right now",
    detail:
      "This phone and HPAY Desktop have both finished pairing. There is no live connection at the moment, so no wallet figure is shown.",
    // Deliberately does not quote a button label. This state covers both a cold
    // phone, where the control reads "Connect to the desktop", and a phone that
    // has just been refused, where the same single control reads "Try
    // connecting again" because every failure sentence tells the owner to tap
    // that. Naming one of the two would be wrong half the time.
    nextAction:
      "Make sure HPAY Desktop is open and unlocked on the same Wi-Fi, then use the connect button on this screen.",
  };
}

/**
 * One raw failure string and the sentence shown in its place.
 *
 * `match` is compared in lower case against the raw text, so a message that
 * wraps a Rust Display inside a longer sentence is still recognised.
 */
type CompanionFailureRule = {
  match: string;
  text: string;
};

/**
 * The always-true closing sentence for a failure we cannot classify.
 *
 * It must hold for every unknown message, so it names a place to look rather
 * than an action that might not apply.
 */
export const COMPANION_UNCLASSIFIED_NEXT_STEP =
  "If this keeps happening, open AI Agent Wallet on HPAY Desktop and read Authorized mobile devices to see whether this phone is listed, pending or revoked.";

/** Shown when a rejection carries no readable text at all. */
export const COMPANION_EMPTY_FAILURE = `The phone could not finish that step and reported no reason. Nothing was paid, signed or changed. ${COMPANION_UNCLASSIFIED_NEXT_STEP}`;

/**
 * Raw text that must never reach an owner, and the sentence that replaces it.
 *
 * Order is significant: the first rule whose marker appears wins, so the more
 * specific markers are listed first.
 */
const COMPANION_FAILURE_RULES: readonly CompanionFailureRule[] = [
  {
    // LanRuntimeError::StaleDesktopChallengeSequence. The phone's replay guard
    // is doing its job: the desktop's challenge counter had not cleared the mark
    // the last accepted challenge left. Nothing is wrong with the pairing, the
    // block expires with that challenge, and a reset would destroy a working
    // pairing to work around a five-minute timer. This used to arrive as
    // "companion backend rejected the operation", which said none of that.
    match: "already accepted a newer session challenge",
    text: `This phone had already accepted a newer connection request from HPAY Desktop, so it refused this one as a repeat. Nothing was paid, signed or changed, and the pairing is fine. Tap ${COMPANION_TRY_AGAIN_ACTION}. If it still refuses, wait five minutes and tap it once more. Do not reset the pairing for this.`,
  },
  {
    // LanRuntimeError::ReusedDesktopChallengeNonce. Same shape, different half
    // of the same guard.
    match: "reused a session challenge",
    text: `HPAY Desktop repeated a connection request this phone had already answered, so this phone refused it. Nothing was paid, signed or changed, and the pairing is fine. Tap ${COMPANION_TRY_AGAIN_ACTION} to ask for a fresh one.`,
  },
  {
    // LanRuntimeError::DesktopChallengeClockOffsetTooLarge. Split out of
    // DesktopChallengeExpired, which was the sink for both CompanionError::Expired
    // and CompanionError::InvalidIssuedAt while naming only a clock cause. Listed
    // first because it is the narrower of the two.
    match: "clock is more than a minute ahead",
    text: `HPAY Desktop's clock is more than a minute away from this phone's, so this phone could not confirm the connection request was still fresh and refused it. Nothing was paid, signed or changed, and the pairing is fine. Set the date and time automatically on both devices, then tap ${COMPANION_TRY_AGAIN_ACTION}.`,
  },
  {
    // LanRuntimeError::DesktopChallengeExpired. Expiry only, now that the clock
    // cause above has its own error. A new request is issued on every connect,
    // so trying again is the whole remedy and no clock needs auditing.
    match: "had already expired by the time this phone read it",
    text: `The connection request from HPAY Desktop had already run out before this phone read it, so this phone refused it. Nothing was paid, signed or changed, and the pairing is fine. Tap ${COMPANION_TRY_AGAIN_ACTION} to ask for a fresh one.`,
  },
  {
    // LanRuntimeError::DeviceNoLongerAuthorized. This one really is permanent.
    match: "no longer authorizes this phone",
    text: "HPAY Desktop no longer authorizes this phone: its record there was revoked, replaced or moved to another Agent Wallet. Nothing was paid, signed or changed, and no retry can fix this. Open the Security tab and read Phone revoked on the desktop.",
  },
  {
    // LanRuntimeError::DesktopChallengeSignatureRejected.
    match: "was not signed by the desktop this phone is paired with",
    text: "The desktop that answered did not prove it is the one this phone is paired with, so this phone refused it and nothing was exchanged. Make sure both devices are on your own private Wi-Fi and that HPAY Desktop is the one holding this Agent Wallet, then try again.",
  },
  {
    // LanRuntimeError::ChallengeAddressedToAnotherDevice.
    match: "addressed to a different phone",
    text: "HPAY Desktop answered with a request meant for a different phone, so this phone refused it. Nothing was paid, signed or changed. On HPAY Desktop open AI Agent Wallet and check that this phone is the one listed under Authorized mobile devices.",
  },
  {
    // LanRuntimeError::CompanionIdentityUnavailable.
    match: "hardware companion identity is unavailable",
    text: "This phone could not open its own secure identity, so it stopped before sending anything. Nothing was paid, signed or changed. Unlock the phone, confirm the fingerprint or face prompt, reopen this screen and try again.",
  },
  {
    // LanRuntimeError::CompanionStatePersistFailed. The refusal is deliberate:
    // the phone will not use a session it could not first record.
    match: "could not durably record the companion session",
    text: `This phone could not save the connection before using it, so it refused to continue rather than leave it unrecorded. Nothing was paid, signed or changed. Free up some storage on the phone, then tap ${COMPANION_TRY_AGAIN_ACTION}.`,
  },
  {
    // LanRuntimeError::CompanionScopeMismatch.
    match: "is not the desktop this phone is paired with",
    text: "The desktop that answered is not the one this phone is paired with, so this phone refused it and nothing was exchanged. Open HPAY Desktop on the computer that holds this Agent Wallet, on the same private Wi-Fi, and try again.",
  },
  {
    // LanRuntimeError::CompanionStateUnavailable / CompanionNotPaired.
    match: "stored companion state could not be read",
    text: `This phone could not read its own saved pairing, so it stopped before sending anything. Nothing was paid, signed or changed. Close and reopen the agent space and tap ${COMPANION_TRY_AGAIN_ACTION}. If it keeps failing, run ${COMPANION_RESET_PAIRING_ACTION} and pair again from HPAY Desktop.`,
  },
  {
    // Raised by the phone itself, from local state, before anything is sent.
    // It is the one refusal whose next step is a button on the desktop, so the
    // sentence names that button and the phone button pressed afterwards.
    match: "pairing is not complete on hpay desktop",
    text: `HPAY Desktop has not approved this phone yet, so it refuses every connection this phone attempts. Nothing was sent, paid or changed. On HPAY Desktop open AI Agent Wallet, find Pair your phone, check that the six digits match and choose Yes, the codes match. Then come back here and tap ${COMPANION_RETRY_AFTER_APPROVAL_ACTION}.`,
  },
  {
    // The phone has no stored pairing at all, so there is nothing to connect.
    match: "pair this phone before connecting",
    text: "This phone is not paired with any desktop yet, so there is nothing to connect to. On HPAY Desktop open AI Agent Wallet and run Pair a phone, then scan the QR code with this phone.",
  },
  {
    // LanRuntimeError::EofDuringDeviceAuthentication already names the cause.
    // What it cannot say is where the owner looks to find out which refusal it
    // was, so that is added rather than replacing a correct sentence.
    match: DESKTOP_REFUSAL_MARKER,
    text: "HPAY Desktop closed the connection without answering, which means it refused this phone. Nothing was paid, signed or changed. On HPAY Desktop open AI Agent Wallet and read Authorized mobile devices: if this phone is not listed, pairing was never finished there; if it is listed as Revoked, open Phone revoked on the desktop in the Security tab of this app.",
  },
  {
    // LanRuntimeError::Backend. This used to be the single Display that every
    // local refusal on the connect path was flattened into: no stored pairing,
    // a stored pairing that no longer validates, a scope mismatch, a secure
    // identity that will not open, and a replay or sequence state the phone
    // refused. Each of those now returns its own named error and is matched by
    // a rule above, so reaching this rule means a cause that is genuinely not
    // one of them. It is kept as a floor, never as the expected path.
    match: "companion backend rejected the operation",
    text: `This phone could not complete its own part of the connection, so nothing was sent, paid or changed. The usual causes are a phone identity that is not unlocked and ready, or a saved pairing that no longer matches HPAY Desktop. Open the Security tab: if Identity reads Created and Ready reads Yes, run ${COMPANION_RESET_PAIRING_ACTION} and then pair again from HPAY Desktop.`,
  },
  {
    match: "companion device authorization failed",
    text: "HPAY Desktop did not accept this phone as an authorized companion. Nothing was paid, signed or changed. On HPAY Desktop open AI Agent Wallet and read Authorized mobile devices to see whether this phone is listed, pending or revoked.",
  },
  {
    match: "closed the connection while confirming the session key",
    text: "HPAY Desktop and this phone could not agree on the encryption for this session, so the connection was closed and nothing was exchanged. Both applications have to come from the same HPAY release. Update the one that is older and try again.",
  },
  {
    match: "closed the authenticated companion session",
    text: "HPAY Desktop ended the connection. Nothing was paid, signed or changed. This is normal after the desktop is locked, put to sleep or closed. Unlock HPAY Desktop and connect again.",
  },
  {
    match: "early eof",
    text: "The connection to HPAY Desktop stopped before it finished. Nothing was paid, signed or changed. Check that HPAY Desktop is open and unlocked on the same Wi-Fi as this phone, then try again.",
  },
  {
    match: "timed out",
    text: "HPAY Desktop did not answer in time, so nothing was sent, paid or changed. Check that HPAY Desktop is open and unlocked on the same Wi-Fi as this phone, then try again.",
  },
  {
    match: "not a private address",
    text: "This phone only connects over your own private Wi-Fi, and the saved desktop address is not a private one. Nothing was sent. Put both devices on your home Wi-Fi, then pair again from HPAY Desktop.",
  },
  {
    match: "connection or rate limit was reached",
    text: "Too many connection attempts were made in a short time, so this one was refused. Nothing was paid, signed or changed. Wait a minute and try again.",
  },
  {
    match: "downgrade received after authentication",
    text: "Data arrived that was not fully encrypted, so this phone refused it and closed the connection. Nothing was accepted, paid or changed. Leave this network, reconnect both devices to your own private Wi-Fi, and try again.",
  },
  {
    match: "no private-lan endpoint was available",
    text: "This phone has no saved Wi-Fi address for HPAY Desktop to try, so nothing was sent. On HPAY Desktop open AI Agent Wallet and run Pair a phone, then scan the QR code with this phone.",
  },
];

/**
 * Turns whatever a rejected companion call produced into one owner-facing
 * sentence that names a cause and a next action.
 *
 * A message that is already written for the owner is returned unchanged apart
 * from trimming, so this can never overwrite better wording with worse.
 */
export function companionFailureText(reason: unknown): string {
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
  if (trimmed.length === 0) return COMPANION_EMPTY_FAILURE;
  const lowered = trimmed.toLowerCase();
  const rule = COMPANION_FAILURE_RULES.find((candidate) =>
    lowered.includes(candidate.match),
  );
  if (rule) return rule.text;
  return `${trimmed} ${COMPANION_UNCLASSIFIED_NEXT_STEP}`;
}

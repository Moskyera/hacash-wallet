/**
 * What the phone puts on screen, and which single control is the point of it.
 *
 * Presentation only. Nothing here pairs, connects, signs, approves or reads a
 * key. It decides ordering, emphasis and disclosure, so no gate, validation or
 * refusal can be weakened by anything in this file.
 *
 * Two complaints produced it:
 *
 * 1. Every tab opened with the same notice, the same health card and the same
 *    connection card, roughly a screen of chrome, so the tab the owner chose
 *    started below the fold. `companionPageLeadsWithOwnContent` decides when
 *    the chosen tab goes first.
 * 2. Several screens carried two or three buttons of equal weight with nothing
 *    saying which one the state needed. `companionPrimaryAction` names exactly
 *    one for every reachable state, and the label it returns is the label of a
 *    control that is really on screen in that state - never a description of
 *    one. `COMPANION_PRIMARY_ACTION_LABELS` is the list the tests check against
 *    the sources, so a renamed button cannot silently leave the copy pointing
 *    at a control that no longer exists.
 */

import {
  COMPANION_CONNECT_ACTION,
  COMPANION_CREATE_IDENTITY_ACTION,
  COMPANION_OPEN_SECURITY_SETUP_ACTION,
  COMPANION_REVIEW_APPROVAL_ACTION,
  COMPANION_SCAN_QR_ACTION,
  COMPANION_SEND_CONFIRMATION_ACTION,
  COMPANION_TRY_AGAIN_ACTION,
} from "./companionStatus";

export {
  COMPANION_CREATE_IDENTITY_ACTION,
  COMPANION_OPEN_SECURITY_SETUP_ACTION,
  COMPANION_RECHECK_IDENTITY_ACTION,
  COMPANION_REFRESH_ACTION,
  COMPANION_REVIEW_APPROVAL_ACTION,
  COMPANION_SCAN_QR_ACTION,
} from "./companionStatus";

export type AgentCompanionPage =
  | "overview"
  | "agents"
  | "rules"
  | "activity"
  | "security";

/** The summary line of the collapsed connection block, named by other copy. */
export const COMPANION_CONNECTION_SECTION_TITLE = "Connection to HPAY Desktop";

/**
 * The one thing the owner is meant to do next, per reachable phone state.
 *
 * "none" is a real answer, not a fallback: a connected phone with nothing
 * pending has no outstanding work, and a handset that cannot host the secure
 * identity has no action that would help. Inventing one for either would be the
 * same class of defect as naming a button that does not exist.
 */
export type CompanionPrimaryActionId =
  | "none"
  | "open_security_setup"
  | "create_identity"
  | "scan_desktop_qr"
  | "send_confirmation"
  | "connect"
  | "try_again"
  | "review_approval";

export type CompanionPrimaryAction = {
  id: CompanionPrimaryActionId;
  /** The exact on-screen label of that control, or "" for "none". */
  label: string;
};

/** Every label this module can name, for the "the control exists" check. */
export const COMPANION_PRIMARY_ACTION_LABELS: Readonly<
  Record<Exclude<CompanionPrimaryActionId, "none">, string>
> = {
  open_security_setup: COMPANION_OPEN_SECURITY_SETUP_ACTION,
  create_identity: COMPANION_CREATE_IDENTITY_ACTION,
  scan_desktop_qr: COMPANION_SCAN_QR_ACTION,
  send_confirmation: COMPANION_SEND_CONFIRMATION_ACTION,
  connect: COMPANION_CONNECT_ACTION,
  try_again: COMPANION_TRY_AGAIN_ACTION,
  review_approval: COMPANION_REVIEW_APPROVAL_ACTION,
};

export type CompanionPrimaryActionInput = {
  /** The selected tab. */
  page: AgentCompanionPage;
  /** Android can hold a hardware-backed companion identity on this handset. */
  platformSupported: boolean;
  /** This phone's secure identity exists. */
  identityConfigured: boolean;
  /** A pairing is stored on this phone. */
  configured: boolean;
  /** A pairing ceremony is open on this screen right now. */
  pairingInProgress: boolean;
  /** The desktop has not finalized this pairing, as far as this phone knows. */
  pendingPairingFinalization: boolean;
  /** An authenticated native session exists. */
  hasSession: boolean;
  /** A connect attempt has failed and the retry is being offered. */
  connectRetryAvailable: boolean;
  /** Payment requests waiting for this owner's decision. */
  pendingApprovals: number;
};

/**
 * The single primary action for a state, in the order the states block on each
 * other. Order is the whole content of this function: pairing cannot start
 * before the identity exists, the desktop cannot be connected before it has
 * finalized the pairing, and no approval can be reviewed without a connection.
 */
export function companionPrimaryAction(
  input: CompanionPrimaryActionInput,
): CompanionPrimaryAction {
  const none: CompanionPrimaryAction = { id: "none", label: "" };
  // Nothing on this handset can create the identity every later step needs, so
  // there is no action to promote. The Security tab says so in words.
  if (!input.platformSupported) return none;
  if (!input.configured) {
    if (!input.identityConfigured) {
      return input.page === "security"
        ? { id: "create_identity", label: COMPANION_CREATE_IDENTITY_ACTION }
        : {
            id: "open_security_setup",
            label: COMPANION_OPEN_SECURITY_SETUP_ACTION,
          };
    }
    // A ceremony in progress is owned step by step by the pairing panel, and
    // each of its steps carries exactly one primary of its own.
    if (input.pairingInProgress) return none;
    return { id: "scan_desktop_qr", label: COMPANION_SCAN_QR_ACTION };
  }
  if (input.pendingPairingFinalization) {
    return {
      id: "send_confirmation",
      label: COMPANION_SEND_CONFIRMATION_ACTION,
    };
  }
  if (!input.hasSession) {
    // One button, two correct names. After a refused attempt the failure text
    // tells the owner to tap "Try connecting again", so that has to be what the
    // button says; otherwise it says what it does from cold.
    return input.connectRetryAvailable
      ? { id: "try_again", label: COMPANION_TRY_AGAIN_ACTION }
      : { id: "connect", label: COMPANION_CONNECT_ACTION };
  }
  if (input.pendingApprovals > 0) {
    return { id: "review_approval", label: COMPANION_REVIEW_APPROVAL_ACTION };
  }
  return none;
}

export type CompanionPageLeadInput = {
  page: AgentCompanionPage;
  /** A pairing is stored on this phone. */
  configured: boolean;
  /** A snapshot that passed every validation is available. */
  hasTrustedSnapshot: boolean;
};

/**
 * Whether the selected tab renders before the shared connection block.
 *
 * A tab leads whenever it has content of its own to show. Security always does:
 * it reads this phone's identity, which needs no desktop. The other four are
 * drawn entirely from the authenticated snapshot, so without one they have
 * nothing to lead with, and the connection block - the only thing that produces
 * a snapshot - goes first instead. The unpaired onboarding order is untouched.
 */
export function companionPageLeadsWithOwnContent(
  input: CompanionPageLeadInput,
): boolean {
  if (!input.configured) return false;
  if (input.page === "security") return true;
  return input.hasTrustedSnapshot;
}

/**
 * What the phone says when Android cannot hold the companion identity at all.
 *
 * This is the one state in the app where nothing can proceed, and until now it
 * rendered a two-column list reading "Platform support: Unavailable" and not
 * one other word. No control is offered because none exists: a handset without
 * hardware-backed, per-use-authenticated key storage cannot host this identity,
 * and pretending a button could change that is exactly the kind of instruction
 * that has already cost an owner a device.
 */
export const COMPANION_PLATFORM_UNSUPPORTED_TITLE =
  "This phone cannot hold the secure identity";

export const COMPANION_PLATFORM_UNSUPPORTED_BODY =
  "Pairing needs a key that Android keeps in secure hardware and unlocks only with your fingerprint or face for each use. This phone does not offer that, so it cannot be paired with an Agent Wallet. Nothing is wrong with your wallet and nothing here was changed.";

export const COMPANION_PLATFORM_UNSUPPORTED_ROUTE =
  "There is no setting on this phone that changes it. Use a different Android phone that has a fingerprint or face unlock and a hardware keystore, and pair that one from HPAY Desktop instead. Your Agent Wallet, its agents and its limits stay exactly as they are.";

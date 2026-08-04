/**
 * What to do on the phone when the desktop says this phone was revoked.
 *
 * Revoking a phone on the desktop is an epoch cut: it durably invalidates every
 * message that phone ever signed, and it is permanent on purpose. The Android
 * companion identity is a hardware Keystore key that deliberately survives a
 * phone-side reset, so a revoked phone keeps presenting the same identity and
 * the desktop keeps refusing it. None of that is changed here, and nothing in
 * this module admits, revives or re-authorizes anything.
 *
 * What was missing is that the phone never said any of it. "Reset pairing only"
 * is the only reset the app offers, it keeps the identity by design, and the
 * screen that mentions revocation said the opposite of the truth. This module
 * is copy only: it names the permanence, says plainly that a reset cannot fix
 * it, and describes the one route that returns this handset to service - a
 * genuinely new companion identity, which the app already mints through
 * "Create mobile identity" whenever the current key is not usable.
 */

import { COMPANION_RESET_PAIRING_ACTION } from "./companionStatus";

/** One step of the identity replacement, in the order it must be done. */
export type CompanionRevokedRecoveryStep = {
  /** Where the owner does it. */
  where: "Desktop" | "Phone";
  /** The action itself. */
  action: string;
  /** Why this step exists, so a skipped step is an informed choice. */
  detail: string;
};

export const COMPANION_REVOKED_TITLE = "Phone revoked on the desktop?";

export const COMPANION_REVOKED_PERMANENCE =
  "Revoking is permanent. The desktop keeps the revoked record forever and refuses this phone for as long as it presents the same identity. That is deliberate: this identity is a hardware key that survives a factory reset, so a revoked phone must never be able to let itself back in.";

export const COMPANION_REVOKED_RESET_DOES_NOT_HELP =
  `${COMPANION_RESET_PAIRING_ACTION} will not fix it. That reset clears pairing, replay and session state and keeps the same Android identity on purpose, so the desktop refuses the phone again for exactly the same reason.`;

export const COMPANION_REVOKED_ROUTE =
  "The way back is a new mobile identity. A new identity is a new key, so the desktop sees a genuinely different phone and pairs it as a first-time phone. The revoked record stays revoked.";

/**
 * The one route that returns this handset to service.
 *
 * Step 3 is the honest part: the app never replaces a healthy companion key on
 * demand, so Create mobile identity only appears once the current key is no
 * longer usable. Enrolling a new fingerprint or face invalidates it by the key
 * policy the identity was created with.
 */
export const COMPANION_REVOKED_RECOVERY_STEPS: readonly CompanionRevokedRecoveryStep[] =
  [
    {
      where: "Desktop",
      action: "Clear the emergency stop in Payment control, if one is engaged.",
      detail:
        "A local payment suspension also blocks the phone connection, so pairing cannot even start while it is on.",
    },
    {
      where: "Phone",
      action: `Run ${COMPANION_RESET_PAIRING_ACTION}, in the reset section below.`,
      detail:
        "This clears the stale pairing this phone still holds. On its own it fixes nothing; it only leaves a clean slate for the new identity.",
    },
    {
      where: "Phone",
      action:
        "In Android Settings, enrol a new fingerprint or face for this phone.",
      detail:
        "The companion key was created to become invalid as soon as a new biometric is enrolled, and that is what makes replacing it possible. This is a real change to the phone: other apps that also bind keys to your biometrics may ask you to set them up again. Read that cost before you do it.",
    },
    {
      where: "Phone",
      action:
        "Reopen this screen. Identity now reads Not created, so tap Create mobile identity and confirm.",
      detail:
        "The old key is deleted and a brand new one is generated in hardware. This identity is still not a Hacash private key and still cannot access My Wallet.",
    },
    {
      where: "Desktop",
      action:
        "Run Pair a phone on the desktop and finish every step there.",
      detail:
        "The desktop sees a new device and admits it through the ordinary first-pairing flow. Nothing about the revoked record changes.",
    },
  ];

export const COMPANION_REVOKED_ALTERNATIVE =
  "If you would rather not change your biometrics, pair a different Android phone instead. A different handset has a different identity and pairs normally. Creating a new Agent Wallet is not a fix: it abandons the wallet id, its journal history, its agents and its limits.";

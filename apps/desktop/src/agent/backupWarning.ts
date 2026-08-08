import type {
  AgentBackupAcknowledgement,
  AgentBackupWarning,
} from "./api";

/// The four facts, in a fixed order, each tied to the exact acknowledgement flag
/// the core checks.
///
/// The list is derived from the warning object the core sends rather than
/// written out here, so a screen cannot show three of four and a reworded
/// warning cannot drift away from the thing it warns about. If the core ever
/// adds a fifth fact, `ACKNOWLEDGEMENT_KEYS` is the one place that has to grow,
/// and `warningPoints` fails loudly until it does.
export const ACKNOWLEDGEMENT_KEYS = [
  "restore_rewinds_spending",
  "revoked_agents_return",
  "old_phone_must_be_replaced",
  "the_file_is_a_working_wallet",
] as const;

export type AcknowledgementKey = (typeof ACKNOWLEDGEMENT_KEYS)[number];

export type WarningPoint = {
  key: AcknowledgementKey;
  text: string;
};

export const EMPTY_ACKNOWLEDGEMENT: AgentBackupAcknowledgement = {
  restore_rewinds_spending: false,
  revoked_agents_return: false,
  old_phone_must_be_replaced: false,
  the_file_is_a_working_wallet: false,
};

/// Every point the owner has to read and tick, in order.
///
/// It throws rather than skipping a point whose text is missing or blank,
/// because a silently empty checkbox is exactly how one of these four stops
/// being shown.
export function warningPoints(warning: AgentBackupWarning): WarningPoint[] {
  return ACKNOWLEDGEMENT_KEYS.map((key) => {
    const text = warning[key];
    if (typeof text !== "string" || text.trim().length === 0) {
      throw new Error(`the backup warning is missing its "${key}" point`);
    }
    return { key, text };
  });
}

export function toggleAcknowledgement(
  current: AgentBackupAcknowledgement,
  key: AcknowledgementKey,
  value: boolean,
): AgentBackupAcknowledgement {
  return { ...current, [key]: value };
}

/// True only when all four are ticked. This is the same rule the core enforces;
/// asking it here is what keeps the button from being pressable before the
/// reading is done, and the core is what keeps a caller from lying about it.
export function acknowledgementComplete(
  acknowledgement: AgentBackupAcknowledgement,
): boolean {
  return ACKNOWLEDGEMENT_KEYS.every((key) => acknowledgement[key] === true);
}

declare const sealedAcknowledgement: unique symbol;

/// An acknowledgement that has been checked, point by point, against the warning
/// the owner was actually shown.
///
/// THIS IS WHY IT IS A SEPARATE TYPE. Both entry points into the core take one of
/// these and nothing else, so there is no way to reach a backup or a restore
/// without having gone through [`sealAcknowledgement`] - not by forgetting the
/// check, not by refactoring the panel, not by adding a second caller. A plain
/// `AgentBackupAcknowledgement` does not type-check there, so `tsc --noEmit` is
/// part of the enforcement and not only the tests are.
export type SealedAcknowledgement = AgentBackupAcknowledgement & {
  readonly [sealedAcknowledgement]: "every point of this warning was ticked";
};

/// Turns four ticks into something the API will accept, or throws.
///
/// It checks against the WARNING rather than against a fixed list of keys, so a
/// warning whose fourth point never rendered - blank, missing, or dropped by a
/// reword - cannot be acknowledged at all: `warningPoints` throws on it first.
export function sealAcknowledgement(
  warning: AgentBackupWarning,
  acknowledgement: AgentBackupAcknowledgement,
): SealedAcknowledgement {
  const outstanding = outstandingPoints(warning, acknowledgement);
  if (outstanding.length > 0) {
    throw new Error(
      `the backup warning has not been read in full: ${outstanding
        .map((point) => point.key)
        .join(", ")}`,
    );
  }
  return acknowledgement as SealedAcknowledgement;
}

/// Whether a control that runs one of the two flows may be pressed.
///
/// It is [`sealAcknowledgement`] asked as a question, deliberately, so that the
/// state of the button and the state of the call can never disagree: one of them
/// greying out while the other would have gone through is exactly how a warning
/// becomes decoration.
export function warningGatePasses(
  warning: AgentBackupWarning,
  acknowledgement: AgentBackupAcknowledgement,
): boolean {
  try {
    sealAcknowledgement(warning, acknowledgement);
    return true;
  } catch {
    return false;
  }
}

/// The runtime half of the same rule, asked immediately before the call leaves
/// the app.
///
/// The type is the first gate and this is the second, because a cast, an `any`,
/// or a value that arrived as JSON defeats a type and defeats nothing here. The
/// core asks the same question a third time, and that is the only one an attacker
/// cannot reach at all.
export function requireSealedAcknowledgement(
  acknowledgement: SealedAcknowledgement,
): AgentBackupAcknowledgement {
  const missing = ACKNOWLEDGEMENT_KEYS.filter(
    (key) => (acknowledgement as AgentBackupAcknowledgement)[key] !== true,
  );
  if (missing.length > 0) {
    throw new Error(
      `the backup warning has not been read in full: ${missing.join(", ")}`,
    );
  }
  return {
    restore_rewinds_spending: true,
    revoked_agents_return: true,
    old_phone_must_be_replaced: true,
    the_file_is_a_working_wallet: true,
  };
}

/// Which points are still unread, so the screen can name them instead of just
/// greying a button out.
export function outstandingPoints(
  warning: AgentBackupWarning,
  acknowledgement: AgentBackupAcknowledgement,
): WarningPoint[] {
  return warningPoints(warning).filter(
    (point) => acknowledgement[point.key] !== true,
  );
}

/// What the owner is told after a restore succeeds - the part that is about what
/// they still have to go and do.
export function restoreFollowUp(outcome: {
  witness_phone_must_be_replaced: boolean;
  restored_active_agents: number;
  journal_sequence: number;
}): string[] {
  const lines: string[] = [
    `This wallet's record is now back at journal position ${outcome.journal_sequence}. ` +
      "Anything it spent after that point is no longer recorded here, and it may pay for those things again.",
  ];
  if (outcome.witness_phone_must_be_replaced) {
    lines.push(
      "Your witness phone will refuse to approve anything for this wallet from now on. " +
        "Run a lost-phone witness rotation onto a different handset before you let any agent spend.",
    );
  }
  if (outcome.restored_active_agents > 0) {
    lines.push(
      `${outcome.restored_active_agents} agent${outcome.restored_active_agents === 1 ? " is" : "s are"} ` +
        "allowed to spend again, with allowances reset. Check the agent list and revoke anything you had already revoked.",
    );
  }
  lines.push(
    "The backup file you just used is still a working wallet. Delete spare copies, and never keep it beside its passphrase.",
  );
  return lines;
}

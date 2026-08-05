import { describe, expect, it } from "vitest";
import type { AgentBackupWarning } from "./api";
import {
  ACKNOWLEDGEMENT_KEYS,
  EMPTY_ACKNOWLEDGEMENT,
  acknowledgementComplete,
  outstandingPoints,
  restoreFollowUp,
  toggleAcknowledgement,
  warningPoints,
} from "./backupWarning";

const warning: AgentBackupWarning = {
  headline: "You are about to rewind this wallet's spending record.",
  restore_rewinds_spending:
    "Restoring rewinds the record of what has been spent and this wallet may pay again for something it has already paid for.",
  revoked_agents_return:
    "Every agent that could spend when the backup was made comes back live, including one you have revoked since.",
  old_phone_must_be_replaced:
    "Your witness phone will refuse to approve anything after this and must be replaced by a lost-phone rotation.",
  the_file_is_a_working_wallet:
    "The backup file plus its passphrase is a working wallet that can spend, at the same time as this one.",
};

describe("the four warning points", () => {
  it("renders all four, in order, each tied to the flag the core checks", () => {
    const points = warningPoints(warning);
    expect(points.map((point) => point.key)).toEqual([...ACKNOWLEDGEMENT_KEYS]);
    expect(points).toHaveLength(4);
    for (const point of points) {
      expect(point.text.length).toBeGreaterThan(40);
    }
  });

  it("refuses to render a warning that is missing one of the four", () => {
    for (const key of ACKNOWLEDGEMENT_KEYS) {
      const broken = { ...warning, [key]: "" };
      expect(() => warningPoints(broken)).toThrow(key);
    }
    // A silently absent field is the same failure as a blank one.
    for (const key of ACKNOWLEDGEMENT_KEYS) {
      const broken = { ...warning } as Record<string, unknown>;
      delete broken[key];
      expect(() => warningPoints(broken as AgentBackupWarning)).toThrow(key);
    }
  });
});

describe("the acknowledgement gate", () => {
  it("is incomplete until every one of the four is ticked", () => {
    let acknowledgement = EMPTY_ACKNOWLEDGEMENT;
    expect(acknowledgementComplete(acknowledgement)).toBe(false);
    expect(outstandingPoints(warning, acknowledgement)).toHaveLength(4);
    for (const [index, key] of ACKNOWLEDGEMENT_KEYS.entries()) {
      acknowledgement = toggleAcknowledgement(acknowledgement, key, true);
      const remaining = ACKNOWLEDGEMENT_KEYS.length - index - 1;
      expect(outstandingPoints(warning, acknowledgement)).toHaveLength(remaining);
      expect(acknowledgementComplete(acknowledgement)).toBe(remaining === 0);
    }
  });

  it("names exactly which points are still unread, rather than only greying a button", () => {
    const acknowledgement = toggleAcknowledgement(
      EMPTY_ACKNOWLEDGEMENT,
      "restore_rewinds_spending",
      true,
    );
    const outstanding = outstandingPoints(warning, acknowledgement);
    expect(outstanding.map((point) => point.key)).toEqual([
      "revoked_agents_return",
      "old_phone_must_be_replaced",
      "the_file_is_a_working_wallet",
    ]);
    expect(outstanding[0].text).toBe(warning.revoked_agents_return);
  });

  it("un-ticking a point re-arms the gate", () => {
    let acknowledgement = EMPTY_ACKNOWLEDGEMENT;
    for (const key of ACKNOWLEDGEMENT_KEYS) {
      acknowledgement = toggleAcknowledgement(acknowledgement, key, true);
    }
    expect(acknowledgementComplete(acknowledgement)).toBe(true);
    acknowledgement = toggleAcknowledgement(
      acknowledgement,
      "the_file_is_a_working_wallet",
      false,
    );
    expect(acknowledgementComplete(acknowledgement)).toBe(false);
  });
});

describe("what the owner is told after a restore", () => {
  it("names the rewind, the dead phone, the revived agents and the live file", () => {
    const lines = restoreFollowUp({
      witness_phone_must_be_replaced: true,
      restored_active_agents: 2,
      journal_sequence: 22,
    }).join("\n");
    expect(lines).toContain("journal position 22");
    expect(lines).toContain("pay for those things again");
    expect(lines).toContain("lost-phone witness rotation");
    expect(lines).toContain("2 agents are");
    expect(lines).toContain("working wallet");
  });

  it("never says a restore was a repair, and never omits the rewind", () => {
    const lines = restoreFollowUp({
      witness_phone_must_be_replaced: false,
      restored_active_agents: 0,
      journal_sequence: 5,
    }).join("\n");
    expect(lines).toContain("no longer recorded here");
    expect(lines.toLowerCase()).not.toContain("repair");
    expect(lines.toLowerCase()).not.toContain("safely");
  });
});

/// THE SCREEN'S OWN BEHAVIOUR IS ASSERTED IN `backupGate.test.tsx`, BY RENDERING
/// IT AND BY WATCHING `invoke`.
///
/// What used to be here read `AgentBackupPanel.tsx` as text and asserted that it
/// CONTAINED "warningPoints(", "acknowledgementComplete(" and two `disabled=`
/// attributes. That is precisely the test that let a bypass through: every one of
/// those strings can be present while nothing is enforced, and a grep cannot tell
/// the difference. It has been replaced rather than added to, because leaving it
/// would leave the impression that the strings are the guarantee.

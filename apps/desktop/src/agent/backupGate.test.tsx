/// THE WARNING IS LOAD-BEARING, PROVED BY BYPASSING IT.
///
/// The tests this file replaces asserted that `AgentBackupPanel.tsx` CONTAINED
/// certain strings. That is what let a bypass through: a mutation can keep every
/// string and stop enforcing anything, and a grep cannot tell. So nothing here
/// reads a source file. Every test tries to skip a fact and then asks the one
/// question that matters - DID THE CALL REACH THE CORE - by watching `invoke`.
///
/// If any of the three gates is deleted, `invoke` is called and these fail.

import { renderToStaticMarkup } from "react-dom/server";
import { beforeEach, describe, expect, it, vi } from "vitest";

const invoke = vi.fn();
vi.mock("@tauri-apps/api/core", () => ({
  invoke: (...args: unknown[]) => invoke(...args),
}));

const { agentWalletApi } = await import("./api");
const {
  ACKNOWLEDGEMENT_KEYS,
  EMPTY_ACKNOWLEDGEMENT,
  sealAcknowledgement,
  toggleAcknowledgement,
  warningGatePasses,
} = await import("./backupWarning");
const { AgentBackupPanel, WarningBlock } = await import("./AgentBackupPanel");

type Warning = Parameters<typeof sealAcknowledgement>[0];
type Acknowledgement = Parameters<typeof sealAcknowledgement>[1];
type Sealed = ReturnType<typeof sealAcknowledgement>;

const warning: Warning = {
  headline: "You are about to rewind the spending record of this wallet.",
  restore_rewinds_spending:
    "Restoring rewinds the record of what has been spent and this wallet may pay again for something it has already paid for.",
  revoked_agents_return:
    "Every agent that could spend when the backup was made comes back live, including one you have revoked since.",
  old_phone_must_be_replaced:
    "Your witness phone will refuse to approve anything after this and must be replaced by a lost-phone rotation.",
  the_file_is_a_working_wallet:
    "The backup file plus its passphrase is a working wallet that can spend, at the same time as this one.",
};

const allFour: Acknowledgement = {
  restore_rewinds_spending: true,
  revoked_agents_return: true,
  old_phone_must_be_replaced: true,
  the_file_is_a_working_wallet: true,
};

/// The bypass an attacker or a careless refactor actually has: cast whatever you
/// like into the sealed type. The runtime gate in `api.ts` is what stops it.
function forge(acknowledgement: Acknowledgement): Sealed {
  return acknowledgement as unknown as Sealed;
}

/// Runs a call that must be refused and returns why.
///
/// It accepts a synchronous throw and a rejected promise alike, because which one
/// the API does is an implementation detail and neither may reach `invoke`.
async function refused(call: () => unknown): Promise<string> {
  try {
    await call();
  } catch (reason) {
    return String(reason);
  }
  throw new Error("the call was not refused at all");
}

beforeEach(() => {
  invoke.mockReset();
  invoke.mockResolvedValue({ document: "{}" });
});

describe("no fact can be skipped on the way to a backup", () => {
  it("is not vacuous: all four ticked really does reach the core", async () => {
    await agentWalletApi.backupCreate(
      "aw_one",
      "pass",
      sealAcknowledgement(warning, allFour),
    );
    expect(invoke).toHaveBeenCalledTimes(1);
    expect(invoke.mock.calls[0][1]).toMatchObject({
      acknowledgement: allFour,
    });

    invoke.mockReset();
    invoke.mockResolvedValue({ wallet_id: "aw_one" });
    await agentWalletApi.backupRestore(
      "{}",
      "pass",
      sealAcknowledgement(warning, allFour),
    );
    expect(invoke).toHaveBeenCalledTimes(1);
  });

  for (const key of ACKNOWLEDGEMENT_KEYS) {
    it(`refuses a backup with "${key}" unread, and never calls the core`, async () => {
      const withheld = toggleAcknowledgement(allFour, key, false);
      // 1. THE SEAL. The panel cannot produce an acknowledgement at all.
      expect(() => sealAcknowledgement(warning, withheld)).toThrow(key);
      expect(warningGatePasses(warning, withheld)).toBe(false);

      // 2. THE RUNTIME GATE, reached by casting past the type system - which is
      //    the only way a caller gets here, and the one a mutation takes.
      expect(
        await refused(() =>
          agentWalletApi.backupCreate("aw_one", "pass", forge(withheld)),
        ),
      ).toContain(key);
      expect(invoke).not.toHaveBeenCalled();
    });

    it(`refuses a restore with "${key}" unread, and never calls the core`, async () => {
      const withheld = toggleAcknowledgement(allFour, key, false);
      expect(() => sealAcknowledgement(warning, withheld)).toThrow(key);
      expect(
        await refused(() =>
          agentWalletApi.backupRestore("{}", "pass", forge(withheld)),
        ),
      ).toContain(key);
      expect(invoke).not.toHaveBeenCalled();
    });
  }

  it("refuses every incomplete combination of the four, all fifteen of them", async () => {
    let refusals = 0;
    for (let mask = 0; mask < 1 << ACKNOWLEDGEMENT_KEYS.length; mask += 1) {
      let acknowledgement = EMPTY_ACKNOWLEDGEMENT;
      ACKNOWLEDGEMENT_KEYS.forEach((key, index) => {
        if (mask & (1 << index)) {
          acknowledgement = toggleAcknowledgement(acknowledgement, key, true);
        }
      });
      const complete = mask === (1 << ACKNOWLEDGEMENT_KEYS.length) - 1;
      expect(warningGatePasses(warning, acknowledgement)).toBe(complete);
      if (complete) continue;
      refusals += 1;
      invoke.mockReset();
      await refused(() =>
        agentWalletApi.backupCreate("aw_one", "pass", forge(acknowledgement)),
      );
      expect(invoke).not.toHaveBeenCalled();
    }
    expect(refusals).toBe(15);
  });

  it("refuses when the warning itself lost a point, even with all four ticked", async () => {
    // A reword, a blank string or a dropped field is the same failure: the fact
    // was never on screen, so it was never read, so nothing may run.
    for (const key of ACKNOWLEDGEMENT_KEYS) {
      const damaged = { ...warning, [key]: "   " };
      expect(() => sealAcknowledgement(damaged, allFour)).toThrow(key);
      expect(warningGatePasses(damaged, allFour)).toBe(false);

      const dropped = { ...warning } as Record<string, unknown>;
      delete dropped[key];
      expect(() =>
        sealAcknowledgement(dropped as Warning, allFour),
      ).toThrow(key);
    }
    expect(invoke).not.toHaveBeenCalled();
  });
});

describe("what the owner actually sees", () => {
  it("renders all four facts, one checkbox each, and says how many are left", () => {
    const html = renderToStaticMarkup(
      <WarningBlock
        warning={warning}
        acknowledgement={EMPTY_ACKNOWLEDGEMENT}
        onToggle={() => {}}
        idPrefix="agent-backup"
      />,
    );
    for (const key of ACKNOWLEDGEMENT_KEYS) {
      expect(html).toContain(warning[key]);
      expect(html).toContain(`id="agent-backup-${key}"`);
    }
    expect(html).toContain(warning.headline);
    expect((html.match(/type="checkbox"/g) ?? []).length).toBe(
      ACKNOWLEDGEMENT_KEYS.length,
    );
    expect(html).toContain("Still to read and accept: 4 of 4");
  });

  it("shows the remaining count going down, and stops naming any when it is done", () => {
    let acknowledgement = EMPTY_ACKNOWLEDGEMENT;
    ACKNOWLEDGEMENT_KEYS.forEach((key, index) => {
      acknowledgement = toggleAcknowledgement(acknowledgement, key, true);
      const html = renderToStaticMarkup(
        <WarningBlock
          warning={warning}
          acknowledgement={acknowledgement}
          onToggle={() => {}}
          idPrefix="agent-restore"
        />,
      );
      const remaining = ACKNOWLEDGEMENT_KEYS.length - index - 1;
      if (remaining === 0) {
        expect(html).not.toContain("Still to read and accept");
      } else {
        expect(html).toContain(`Still to read and accept: ${remaining} of 4`);
      }
      // Every fact stays on screen throughout; ticking one never hides another.
      for (const point of ACKNOWLEDGEMENT_KEYS) {
        expect(html).toContain(warning[point]);
      }
    });
  });

  it("offers no control at all until the warning has arrived", () => {
    // The panel loads the warning in an effect, so this is the very first paint.
    // There must be nothing pressable and nothing tickable on it: an owner cannot
    // reach a backup or a restore before the four facts exist to be read.
    invoke.mockImplementation(() => new Promise(() => {}));
    const html = renderToStaticMarkup(
      <AgentBackupPanel
        walletId="aw_one"
        busy={false}
        run={async (work) => {
          await work();
        }}
        onInfo={() => {}}
      />,
    );
    expect(html).not.toContain("<button");
    expect(html).not.toContain("<input");
    expect(html).not.toContain("<textarea");
    expect(html).toContain("Nothing can be backed up or restored");
  });
});

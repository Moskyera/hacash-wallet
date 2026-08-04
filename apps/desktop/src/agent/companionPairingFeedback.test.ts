import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import {
  COMPANION_ACTION_GUIDE,
  COMPANION_PAIR_ACTION,
  COMPANION_REVOKED_GUIDANCE,
  COMPANION_REVOKE_ACTION,
  COMPANION_REVOKE_WARNING,
  COMPANION_START_LINK_ACTION,
  COMPANION_STOP_LINK_ACTION,
  COMPANION_UNKNOWN_FAILURE,
  companionActionErrorMessage,
  companionAttemptBudgetView,
  companionAuthorizedDeviceLabel,
  companionOwnerFacingRefusal,
  companionRevokedDeviceGuidance,
  companionRevokedDeviceLabel,
  companionStepErrorMessage,
} from "./companionPairingFeedback";

/** Source with every comment removed, so a "gone" check sees only the UI. */
function withoutComments(source: string): string {
  return source
    .replace(/\/\*[\s\S]*?\*\//g, " ")
    .replace(/\{\s*\/\*[\s\S]*?\*\/\s*\}/g, " ")
    .replace(/(^|[^:])\/\/[^\n]*/g, "$1");
}

/** JSX wraps prose across lines, so compare on collapsed whitespace. */
function flatten(source: string): string {
  return source.replace(/\s+/g, " ");
}

const panelSource = readFileSync(
  new URL("./MobileCompanionPanel.tsx", import.meta.url),
  "utf8",
);

/**
 * The Overview page.
 *
 * It used to render the connector panel above the phone panel. It no longer
 * does: the phone panel is hoisted whenever the phone connection is not on,
 * because it owns the one control the whole connection depends on, and that
 * control was measured 2.8 screens below the fold. `overviewBlockOrder` in
 * overviewLayout.ts decides the order and overviewLayout.test.ts pins it.
 */
const appSource = readFileSync(
  new URL("./AgentWalletApp.tsx", import.meta.url),
  "utf8",
);

/** The single table every rendered control label now comes from. */
const controlsSource = readFileSync(
  new URL("./desktopControls.ts", import.meta.url),
  "utf8",
);

/** The Rust refusals this panel renders verbatim. */
const errorSource = readFileSync(
  new URL("../../../../crates/agent-wallet-core/src/error.rs", import.meta.url),
  "utf8",
);

/** The `#[error("...")]` copy for one `AgentWalletError` variant. */
function refusalCopy(variant: string): string {
  const at = errorSource.indexOf(`\n    ${variant},`);
  expect(at, `missing variant ${variant}`).toBeGreaterThan(-1);
  const attribute = errorSource.lastIndexOf('#[error(', at);
  const quoted = errorSource.slice(attribute, at).match(/"((?:[^"\\]|\\.)*)"/);
  expect(quoted, `missing #[error] copy for ${variant}`).not.toBeNull();
  return (quoted as RegExpMatchArray)[1].replace(/\\"/g, '"');
}

/** The chunk of the panel that renders one wizard step, by its heading. */
function stepSource(startHeading: string, endHeading: string): string {
  const from = panelSource.indexOf(startHeading);
  const to = panelSource.indexOf(endHeading, from + startHeading.length);
  expect(from, `missing step: ${startHeading}`).toBeGreaterThan(-1);
  expect(to, `missing step: ${endHeading}`).toBeGreaterThan(from);
  return panelSource.slice(from, to);
}

describe("panel-local pairing failures", () => {
  it("keeps a failure attached to the button that produced it", () => {
    const failure = { step: "finish", message: "Nothing was paired." } as const;
    expect(companionStepErrorMessage(failure, "finish")).toBe(
      "Nothing was paired.",
    );
    // Never bleed one button's failure onto another button.
    expect(companionStepErrorMessage(failure, "start")).toBe("");
    expect(companionStepErrorMessage(failure, "confirm")).toBe("");
    expect(companionStepErrorMessage(null, "finish")).toBe("");
  });

  it("turns every rejection shape into one readable line", () => {
    expect(
      companionActionErrorMessage(
        new Error("The Agent Wallet changed since this pairing started."),
      ),
    ).toBe("The Agent Wallet changed since this pairing started.");
    expect(companionActionErrorMessage("  That code does not match.  ")).toBe(
      "That code does not match.",
    );
    expect(companionActionErrorMessage({ message: "no tries left" })).toBe(
      "no tries left",
    );
  });

  it("never renders an empty or unreadable alert, which reads as a dead button", () => {
    for (const reason of [undefined, null, "", "   ", 42, {}, { message: 7 }]) {
      const message = companionActionErrorMessage(reason);
      expect(message).toBe(COMPANION_UNKNOWN_FAILURE);
      expect(message.trim().length).toBeGreaterThan(0);
    }
  });

  it("renders the failure inside the finish step, next to the button", () => {
    const finish = stepSource(
      "3. Finish on this desktop",
      "5. Confirm locally on this desktop",
    );
    // The exact button the owner presses after the phone says Done.
    expect(finish).toContain("Yes, the codes match");
    expect(finish).toContain('stepError("finish")');
    // Under the button, not somewhere above it.
    expect(finish.indexOf('stepError("finish")')).toBeGreaterThan(
      finish.indexOf("Yes, the codes match"),
    );
    // The completion that fails is the one this step reports on.
    expect(finish).toContain('runPairingStep("finish"');
    expect(finish).toContain("completeAutomaticCompanionPairing");
  });

  it("reports every pairing action beside its own control", () => {
    for (const step of [
      "start",
      "request",
      "acknowledgement",
      "finish",
      "confirm",
      "cancel",
      "reconnect",
    ]) {
      expect(panelSource, `no panel-local report for ${step}`).toContain(
        `stepError("${step}")`,
      );
    }
    // Pairing actions no longer report only into the page-level alert: every
    // pairing call is reached through the wrapper that keeps the reason here.
    expect(panelSource).toContain("const runPairingStep = useCallback(");
    for (const call of [
      "startCompanionPairing",
      "acceptCompanionPairingRequest",
      "completeAutomaticCompanionPairing",
      "completeCompanionPairing",
    ]) {
      const at = panelSource.indexOf(`agentWalletApi.${call}(`);
      expect(at, `missing pairing call ${call}`).toBeGreaterThan(0);
      const before = panelSource.slice(0, at);
      expect(
        before.lastIndexOf("void runPairingStep("),
        `${call} still reports only into the page-level alert`,
      ).toBeGreaterThan(before.lastIndexOf("void run("));
    }
    // Cancel is a pairing action too, and it can fail.
    expect(panelSource).toContain('runPairingStep("cancel", cancelPairing)');
    expect(panelSource).not.toContain("void run(cancelPairing)");
  });
});

describe("the bounded retry budget", () => {
  it("names the attempt about to be spent", () => {
    expect(
      companionAttemptBudgetView({
        attemptsUsed: 0,
        attemptsRemaining: 5,
        maxAttempts: 5,
      }),
    ).toMatchObject({
      label: "Attempt 1 of 5",
      lastTry: false,
      exhausted: false,
    });
    expect(
      companionAttemptBudgetView({
        attemptsUsed: 1,
        attemptsRemaining: 4,
        maxAttempts: 5,
      })?.label,
    ).toBe("Attempt 2 of 5");
    expect(
      companionAttemptBudgetView({
        attemptsUsed: 3,
        attemptsRemaining: 2,
        maxAttempts: 5,
      })?.detail,
    ).toContain("2 tries left");
  });

  it("warns before the last try instead of after it", () => {
    const last = companionAttemptBudgetView({
      attemptsUsed: 4,
      attemptsRemaining: 1,
      maxAttempts: 5,
    });
    expect(last?.label).toBe("Attempt 5 of 5");
    expect(last?.lastTry).toBe(true);
    expect(last?.exhausted).toBe(false);
    expect(last?.detail).toContain("1 try left");
    expect(last?.detail).toMatch(/cancelled/i);
  });

  it("says the pairing is gone once the budget is spent", () => {
    const spent = companionAttemptBudgetView({
      attemptsUsed: 5,
      attemptsRemaining: 0,
      maxAttempts: 5,
    });
    expect(spent?.exhausted).toBe(true);
    expect(spent?.label).toBe("All 5 tries used");
    expect(spent?.detail).toMatch(/Pair a phone again/);
    // The attempt counter never runs past the bound.
    expect(
      companionAttemptBudgetView({
        attemptsUsed: 9,
        attemptsRemaining: 0,
        maxAttempts: 5,
      })?.label,
    ).toBe("All 5 tries used");
  });

  it("invents no budget when the desktop reports none", () => {
    expect(companionAttemptBudgetView(null)).toBeNull();
    expect(companionAttemptBudgetView(undefined)).toBeNull();
    expect(companionAttemptBudgetView({})).toBeNull();
    expect(
      companionAttemptBudgetView({ attemptsUsed: 0, maxAttempts: 0 }),
    ).toBeNull();
    expect(
      companionAttemptBudgetView({
        attemptsUsed: -1,
        attemptsRemaining: 5,
        maxAttempts: 5,
      }),
    ).toBeNull();
    // A surprising payload is clamped, never rendered as a runaway count.
    expect(
      companionAttemptBudgetView({
        attemptsUsed: 0,
        attemptsRemaining: 99,
        maxAttempts: 5,
      })?.detail,
    ).toContain("5 tries left");
  });

  it("is shown in the wizard while a pairing is on screen", () => {
    expect(panelSource).toContain(
      "companionAttemptBudgetView(attemptBudget)",
    );
    expect(panelSource).toContain("{offer && attempts && (");
    expect(panelSource).toContain("{attempts.label}");
    expect(panelSource).toContain("{attempts.detail}");
    // The counters come from the status the desktop already polls.
    expect(panelSource).toContain("pairingStatus.attemptsUsed");
    expect(panelSource).toContain("pairingStatus.attemptsRemaining");
    expect(panelSource).toContain("pairingStatus.maxAttempts");
  });
});

/**
 * The five controls that sat side by side with nothing to tell them apart.
 *
 * Two of them start something, two stop something, and one is permanent. The
 * permanent one had the shortest label on the screen.
 */
describe("which button do I need", () => {
  it("covers every control that can be confused for another", () => {
    const actions = COMPANION_ACTION_GUIDE.map((entry) => entry.action);
    expect(actions).toEqual([
      COMPANION_PAIR_ACTION,
      COMPANION_START_LINK_ACTION,
      COMPANION_STOP_LINK_ACTION,
      COMPANION_REVOKE_ACTION,
    ]);
    for (const entry of COMPANION_ACTION_GUIDE) {
      expect(entry.when.trim().length, `${entry.action} has no "when"`)
        .toBeGreaterThan(0);
      expect(entry.cost.trim().length, `${entry.action} has no cost`)
        .toBeGreaterThan(0);
    }
    // The panel renders the guide, next to the controls it describes.
    expect(panelSource).toContain("COMPANION_ACTION_GUIDE.map");
    expect(panelSource).toContain("Which button do I need?");
  });

  it("says the free ones are free and the permanent one is permanent", () => {
    const guide = new Map(
      COMPANION_ACTION_GUIDE.map((entry) => [entry.action, entry]),
    );
    for (const free of [
      COMPANION_PAIR_ACTION,
      COMPANION_START_LINK_ACTION,
      COMPANION_STOP_LINK_ACTION,
    ]) {
      expect(guide.get(free)?.cost, `${free} does not say it is free`)
        .toMatch(/costs nothing/i);
    }
    const revoke = guide.get(COMPANION_REVOKE_ACTION);
    expect(revoke?.cost).toMatch(/cannot be undone/i);
    expect(revoke?.cost).toMatch(/never be paired again/i);
    // And it says outright that it is not the fix for a phone that will not
    // connect, which is how a working phone became permanently unusable.
    expect(revoke?.when).toMatch(/not a way to fix a phone that will not connect/i);
  });

  it("separates pairing a phone from turning its connection on", () => {
    const guide = new Map(
      COMPANION_ACTION_GUIDE.map((entry) => [entry.action, entry]),
    );
    // These two are the pair an owner cannot tell apart from the labels alone.
    expect(guide.get(COMPANION_PAIR_ACTION)?.when).toMatch(/first time/i);
    expect(guide.get(COMPANION_START_LINK_ACTION)?.when).toMatch(
      /already listed under Authorized mobile devices/i,
    );
    expect(guide.get(COMPANION_START_LINK_ACTION)?.when).toMatch(
      /does not pair anything/i,
    );
    // The old labels named the wrong thing. "Reconnect phone" read as "fix my
    // unpaired phone", and "Stop mobile companion" read as "unpair my phone".
    // Both are pinned by value, because the panel renders them from constants
    // and a rename would otherwise slip past a source-only check.
    expect(COMPANION_START_LINK_ACTION).toBe("Turn on the phone connection");
    expect(COMPANION_STOP_LINK_ACTION).toBe("Turn off the phone connection");
    for (const label of [COMPANION_START_LINK_ACTION, COMPANION_STOP_LINK_ACTION]) {
      expect(label).not.toBe("Reconnect phone");
      expect(label).not.toBe("Stop mobile companion");
      // It has to name what it acts on: the connection, not the phone itself.
      expect(label).toMatch(/phone connection/i);
    }
    expect(withoutComments(panelSource)).not.toContain("Reconnect phone");
    expect(withoutComments(panelSource)).not.toContain("Stop mobile companion");
    expect(panelSource).toContain("{COMPANION_START_LINK_ACTION}");
    expect(panelSource).toContain("{COMPANION_STOP_LINK_ACTION}");
  });

  it("keeps the pairing button named exactly what every refusal calls it", () => {
    // Eleven AgentWalletError refusals and the phone app all send the owner to
    // this button by name. Renaming it would make every one of them false.
    expect(COMPANION_PAIR_ACTION).toBe("Pair a phone");
    expect(refusalCopy("PairingAlreadyUsed")).toContain(COMPANION_PAIR_ACTION);
    expect(refusalCopy("PairingUnknownToSession")).toContain(COMPANION_PAIR_ACTION);
    expect(panelSource).toContain("{COMPANION_PAIR_ACTION}");
  });
});

describe("the AI agent connector is not the phone connection", () => {
  it("says which device each set of buttons is for", () => {
    const flat = flatten(appSource);
    // The connector panel renders directly above the phone panel, so an owner
    // fixing a phone pressed Start connector and nothing about the phone moved.
    expect(flat).toMatch(/This is for AI agent software running on this computer/);
    expect(flat).toMatch(/It is not the phone connection/);
    // "below" was dropped: the connector panel is hoisted above the phone panel
    // when it has failed, so "below" was true only some of the time.
    expect(flat).toMatch(/use Pair your phone instead/);
    expect(flat).toMatch(/costs nothing and moves no money/);
    // The separation is still stated at rest, one line, beside the buttons.
    expect(flat).toMatch(
      /For AI agent software on this computer\. Not the phone connection\./,
    );
  });

  it("names the connector buttons after the thing they start and stop", () => {
    expect(controlsSource).toContain('start_connector: "Start the AI agent connector"');
    expect(controlsSource).toContain('stop_connector: "Stop the AI agent connector"');
    expect(appSource).toContain("DESKTOP_CONTROLS.start_connector");
    expect(appSource).toContain("DESKTOP_CONTROLS.stop_connector");
    // "Restart the AI agent connector" called onStop and never started
    // anything. The label now says exactly what the click does.
    expect(withoutComments(appSource)).not.toContain("Restart the AI agent connector");
    expect(withoutComments(controlsSource)).toContain(
      'clear_failed_connector: "Clear the failed connector"',
    );
    expect(appSource).toContain("DESKTOP_CONTROLS.clear_failed_connector");
    const visible = withoutComments(appSource);
    expect(visible).not.toContain('"Start connector"');
    expect(visible).not.toContain('"Stop connector"');
    expect(visible).not.toContain('"Recover connector"');
    // And the disabled state says why, instead of reading as a dead button.
    expect(flatten(appSource)).toMatch(
      /\{DESKTOP_CONTROLS\.start_connector\} is unavailable while it is\{" "\} \{connector\.phase\}/,
    );
  });

  it("replaces the internal phase name with something an owner can read", () => {
    // "Connector stopped" read as a fault; "Connector running" read as "my
    // phone is fine". Neither is what this badge reports.
    expect(withoutComments(appSource)).not.toContain("`Connector ${connector.phase}`");
    expect(appSource).toContain("connectorStatusText(connector.phase)");
    for (const label of [
      "AI agent connector is on",
      "AI agent connector is off",
      "AI agent connector is starting",
      "AI agent connector is stopping",
      "AI agent connector failed to start",
    ]) {
      expect(appSource).toContain(label);
    }
  });
});

describe("the desktop badge reports the desktop, not the phone", () => {
  it("never claims a phone is ready when only the listener is", () => {
    // "Phone ready" was shown whenever this desktop was accepting connections,
    // including while every phone on the wallet was refused.
    expect(withoutComments(panelSource)).not.toContain('"Phone ready"');
    for (const label of [
      "Phone connection is on",
      "Phone connection is off",
      "Phone connection is stopping",
      "Phone connection failed to start",
    ]) {
      expect(panelSource).toContain(label);
    }
    // "Not connected" and "Disconnecting" said nothing about what was not
    // connected, and read as a statement about the phone.
    expect(withoutComments(panelSource)).not.toContain('return "Not connected";');
    expect(withoutComments(panelSource)).not.toContain('return "Disconnecting";');
  });
});

describe("a disabled control that explains itself", () => {
  it("says why pairing and the phone link are unavailable, beside them", () => {
    const flat = flatten(panelSource);
    // No authorized phone: there is nothing for the link to connect to, so the
    // control is now hidden rather than shown disabled, and the sentence that
    // replaces it says so and names the control that does work.
    expect(flat).toContain("{COMPANION_START_LINK_ACTION} is not shown because no phone is");
    expect(flat).toMatch(/nothing for it to connect to/i);
    expect(flat).toContain("Use {COMPANION_PAIR_ACTION} below first.");
    // No private address: both controls need one, and both say so.
    expect(flat).toContain("{COMPANION_PAIR_ACTION} is unavailable because this desktop has");
    expect(flat).toContain("{COMPANION_START_LINK_ACTION} is unavailable because this desktop");
    expect(flat).toMatch(/Try automatic setup again/);
    // The bare "Authorize a mobile device before starting the companion
    // listener." named no control and no next step.
    expect(withoutComments(panelSource)).not.toContain(
      "Authorize a mobile device before starting the companion listener.",
    );
  });
});

describe("opaque internal refusals", () => {
  it("never shows a Rust Display that names no cause and no next action", () => {
    for (const raw of [
      "companion device authorization failed",
      "companion backend rejected the operation",
      "companion LAN I/O failed: early eof",
      "companion LAN operation timed out",
    ]) {
      const text = companionActionErrorMessage(raw);
      expect(text, `${raw} reached the owner verbatim`).not.toBe(raw);
      expect(text.toLowerCase()).not.toContain("early eof");
      expect(text).toMatch(/nothing was paired|Wait a minute/);
    }
  });

  it("leaves a refusal that already explains itself exactly as Rust wrote it", () => {
    // These are written for the owner and are more specific than any table
    // entry could be. Overwriting them would lose the real reason.
    for (const variant of [
      "PairingDeviceRevoked",
      "PairingVerificationCodeMismatch",
      "PairingAttemptsExhausted",
      "PairingStateChangedSinceStart",
    ]) {
      const refusal = refusalCopy(variant);
      expect(companionOwnerFacingRefusal(refusal), `${variant} was overwritten`)
        .toBe(refusal);
      expect(companionActionErrorMessage(refusal)).toBe(refusal);
    }
  });

  it("does not turn the authorization refusal into a revoked verdict", () => {
    // "companion device authorization failed" covers more than revocation, and
    // revocation is permanent. Naming it as the cause would send an owner to an
    // irreversible control for a recoverable problem.
    const text = companionActionErrorMessage("companion device authorization failed");
    expect(companionRevokedDeviceGuidance(text)).toBeNull();
    expect(text).toMatch(/listed|Authorized mobile devices/);
  });
});

describe("an authorized device row", () => {
  it("distinguishes being paired from being reachable", () => {
    const on = companionAuthorizedDeviceLabel("3/08/2026, 02:35:30", true);
    const off = companionAuthorizedDeviceLabel("3/08/2026, 02:35:30", false);
    expect(on).not.toBe(off);
    expect(on).toContain("Phone connection is on");
    expect(off).toContain("Phone connection is off");
    for (const label of [on, off]) {
      expect(label).toContain("3/08/2026, 02:35:30");
      expect(label).toContain("Read only");
      // Never the same words a revoked row uses.
      expect(label).not.toContain("Revoked");
      expect(label).not.toContain("Cannot be paired again");
    }
    expect(panelSource).toContain("companionAuthorizedDeviceLabel(");
    // The old row was a bare date and said nothing about reachability.
    expect(withoutComments(panelSource)).not.toContain(
      "`Paired ${formatUnix(device.paired_at)} · Read only`",
    );
  });

  it("warns that revoking is permanent before the first press, not after", () => {
    expect(COMPANION_REVOKE_ACTION).toMatch(/permanently/i);
    const flat = flatten(panelSource);
    expect(flat).toContain(
      "{revokeConfirmId !== device.device_id && ( <p className=\"agent-muted\"> Permanent. Use only for a lost, sold or compromised phone.",
    );
    // The unconfirmed state comes first, so the warning is on screen before the
    // owner has pressed anything.
    expect(panelSource.indexOf("revokeConfirmId !== device.device_id &&")).toBeLessThan(
      panelSource.indexOf("revokeConfirmId === device.device_id && ("),
    );
    expect(withoutComments(panelSource)).not.toContain('"Revoke device"');
  });
});

describe("a revoked phone, said out loud", () => {
  it("names revocation as the cause beside the control that was refused", () => {
    // The exact sentence Rust returns when the durable registry refuses the
    // last step of a pairing because the phone is revoked.
    const refusal = refusalCopy("PairingDeviceRevoked");
    const guidance = companionRevokedDeviceGuidance(refusal);
    expect(guidance, "the revoked refusal is not recognised").not.toBeNull();
    expect(guidance).toBe(COMPANION_REVOKED_GUIDANCE);
    expect(guidance?.permanence).toMatch(/permanent/i);
    expect(guidance?.options).toHaveLength(2);
    expect(guidance?.options[0]).toMatch(/new mobile identity/i);
    expect(guidance?.options[1]).toMatch(/different phone/i);
  });

  it("claims no other pairing failure, so the cause stays specific", () => {
    for (const other of [
      "PairingDeviceAlreadyRegistered",
      "PairingDeviceRecordRejected",
      "PairingVerificationCodeMismatch",
      "PairingIdentityMismatch",
      "PairingAlreadyUsed",
    ]) {
      expect(
        companionRevokedDeviceGuidance(refusalCopy(other)),
        `${other} was mistaken for a revoked device`,
      ).toBeNull();
    }
    expect(companionRevokedDeviceGuidance(null)).toBeNull();
    expect(companionRevokedDeviceGuidance("companion device authorization failed")).toBeNull();
  });

  it("never sends the owner on an errand that cannot work", () => {
    // Resetting the companion app keeps the hardware identity by design, so a
    // reset can never clear a revocation. The old copy said to do exactly that.
    const refusal = refusalCopy("PairingDeviceRevoked");
    expect(refusal).not.toMatch(/Reset the companion app on the phone, then pair it again/);
    expect(refusal).toMatch(/Revocation is permanent/);
    expect(COMPANION_REVOKED_GUIDANCE.ineffective).toMatch(/reset/i);
    // And "already authorized" must never point at Revoke, which is how a
    // working phone becomes a permanently unpairable one.
    const already = refusalCopy("PairingDeviceAlreadyRegistered");
    expect(already).not.toMatch(/Revoke it under Authorized mobile devices/);
    expect(already).toMatch(/never revoke a working phone/);
  });

  it("says a revoked row is permanent rather than showing only a date", () => {
    const label = companionRevokedDeviceLabel("3/08/2026, 21:44:25");
    expect(label).toContain("3/08/2026, 21:44:25");
    expect(label).toMatch(/Permanent/);
    expect(label).toMatch(/Cannot be paired again/);
    // The list renders that label, and can explain itself in place.
    expect(panelSource).toContain(
      "companionRevokedDeviceLabel(formatUnix(device.revoked_at))",
    );
    expect(panelSource).toContain("<RevokedDeviceExplanation />");
    expect(panelSource).toContain("Why this phone cannot be paired again");
    // The stuck state itself is named, not left as an empty-looking list.
    expect(panelSource).toContain("devices.length > 0 && !hasAuthorizedDevice");
  });

  it("expands the reason under every pairing button, not only one", () => {
    for (const step of [
      "start",
      "request",
      "acknowledgement",
      "finish",
      "confirm",
      "cancel",
      "reconnect",
    ]) {
      expect(
        panelSource,
        `${step} still renders a bare line with no revoked guidance`,
      ).toContain(`<PairingFailure message={stepError("${step}")} />`);
    }
    expect(panelSource).toContain("companionRevokedDeviceGuidance(message)");
  });

  it("warns that revoking cannot be undone before it is confirmed", () => {
    expect(COMPANION_REVOKE_WARNING).toMatch(/permanent/i);
    expect(COMPANION_REVOKE_WARNING).toMatch(/cannot be undone/i);
    expect(COMPANION_REVOKE_WARNING).toMatch(/never be paired again/i);
    expect(panelSource).toContain("{COMPANION_REVOKE_WARNING}");
    // The confirmation itself has to say what it does.
    expect(panelSource).toContain('"Yes, revoke permanently"');
    const warningAt = panelSource.indexOf("{COMPANION_REVOKE_WARNING}");
    const confirmAt = panelSource.indexOf('"Yes, revoke permanently"');
    expect(warningAt).toBeGreaterThan(-1);
    expect(confirmAt).toBeGreaterThan(warningAt);
  });
});

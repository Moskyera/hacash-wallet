import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import {
  DESKTOP_CONTROLS,
  isDesktopControlLabel,
} from "./desktopControls";
import {
  companionPairingWaitingView,
  companionPhoneAppName,
  companionPhoneConfirmationAction,
  formatPairingValidity,
  type CompanionPairingWaitingInput,
} from "./companionWaitingView";

const panelSource = readFileSync(
  new URL("./MobileCompanionPanel.tsx", import.meta.url),
  "utf8",
);

/** Desktop confirmed, phone acknowledgement still outstanding, 4:12 left. */
function waitingInput(
  overrides: Partial<CompanionPairingWaitingInput> = {},
): CompanionPairingWaitingInput {
  return {
    hasOffer: true,
    hasConfirmation: true,
    ackReceived: false,
    hasScannedAck: false,
    secondsRemaining: 252,
    ...overrides,
  };
}

function allText(
  view: NonNullable<ReturnType<typeof companionPairingWaitingView>>,
): string {
  return [
    view.heading,
    view.phoneInstruction,
    view.validity,
    view.restart,
    view.restartAction ?? "",
    view.humanCheck,
  ].join(" ");
}

/** Reports which snippets are absent, so a failure names them all at once. */
function missingFrom(source: string, snippets: string[]): string[] {
  return snippets.filter((snippet) => !source.includes(snippet));
}

/** Body of every useEffect in the panel, matched by brace balance. */
function effectBodies(source: string): string[] {
  const bodies: string[] = [];
  let from = 0;
  for (;;) {
    const start = source.indexOf("useEffect(", from);
    if (start < 0) return bodies;
    let depth = 0;
    let index = start + "useEffect".length;
    for (; index < source.length; index += 1) {
      const character = source[index];
      if (character === "(") depth += 1;
      else if (character === ")") {
        depth -= 1;
        if (depth === 0) break;
      }
    }
    bodies.push(source.slice(start, index + 1));
    from = index + 1;
  }
}

describe("desktop pairing waiting state", () => {
  it("exists while the phone confirmation has not arrived", () => {
    const view = companionPairingWaitingView(waitingInput());
    expect(view).not.toBeNull();
    expect(view?.heading).toMatch(/waiting for the confirmation from your phone/i);
  });

  it("is shown when ackReceived is false and withdrawn once it is true", () => {
    expect(companionPairingWaitingView(waitingInput({ ackReceived: false }))).not.toBeNull();
    // The finish step renders on ackReceived, so the waiting copy must retire.
    expect(companionPairingWaitingView(waitingInput({ ackReceived: true }))).toBeNull();
  });

  it("names the phone app and the exact phone action to tap", () => {
    const view = companionPairingWaitingView(waitingInput());
    expect(view).not.toBeNull();
    expect(view?.phoneApp).toBe(companionPhoneAppName);
    expect(view?.phoneAction).toBe(companionPhoneConfirmationAction);
    expect(view?.phoneInstruction).toContain("AI Agent Wallet");
    expect(view?.phoneInstruction).toContain(
      "Send this phone's confirmation to the desktop",
    );
    // An owner who has never sent anything before needs to know that tapping it
    // is free and repeatable, or the fear of double-spending stops them.
    expect(view?.phoneInstruction).toMatch(/costs nothing and moves no money/i);
    expect(view?.phoneInstruction).toMatch(/safe to tap more than once/i);
  });

  it("matches the label the phone actually renders", () => {
    // The phone declares the label once, in companionStatus.ts, and renders it
    // from that constant in both places it appears. An instruction that names a
    // button the phone does not have is worse than no instruction at all.
    const mobileStatus = readFileSync(
      new URL("../../../mobile/src/agent/companionStatus.ts", import.meta.url),
      "utf8",
    );
    const mobileApp = readFileSync(
      new URL(
        "../../../mobile/src/agent/AgentCompanionApp.tsx",
        import.meta.url,
      ),
      "utf8",
    );
    const mobilePanel = readFileSync(
      new URL(
        "../../../mobile/src/agent/CompanionPairingPanel.tsx",
        import.meta.url,
      ),
      "utf8",
    );
    expect(mobileStatus).toContain(
      `COMPANION_SEND_CONFIRMATION_ACTION =\n  "${companionPhoneConfirmationAction}"`,
    );
    // Both phone screens that can send the confirmation use that one constant,
    // so the desktop instruction is true wherever the owner happens to be.
    expect(mobileApp).toContain("{COMPANION_SEND_CONFIRMATION_ACTION}");
    expect(mobilePanel).toContain("{COMPANION_SEND_CONFIRMATION_ACTION}");
  });

  it("shows the remaining validity of the pairing request", () => {
    const view = companionPairingWaitingView(waitingInput({ secondsRemaining: 252 }));
    expect(view?.expired).toBe(false);
    expect(view?.validity).toMatch(/expires in .*4 minutes/);
    expect(formatPairingValidity(300)).toBe("5 minutes");
    expect(formatPairingValidity(252)).toBe("4 minutes 12 seconds");
    expect(formatPairingValidity(61)).toBe("1 minute 1 second");
    expect(formatPairingValidity(45)).toBe("45 seconds");
    expect(formatPairingValidity(null)).toBe("a few minutes");
  });

  it("makes expiry obvious and names the control the press really is", () => {
    const expired = companionPairingWaitingView(waitingInput({ secondsRemaining: 0 }));
    expect(expired?.expired).toBe(true);
    expect(expired?.validity).toMatch(/expired/i);
    expect(expired?.validity).toMatch(/nothing was paired/i);

    // The button is wired to agent_wallet_companion_pairing_cancel and to
    // nothing else: it cancels, clears the wizard and produces no offer and no
    // QR. It used to be labelled "Start again" beside a sentence promising a
    // new QR code, so the label named an action the press does not perform and
    // the owner had to find Pair a phone unaided. The label must be a
    // registered control, must be the cancel control, and the sentence must
    // name the second press that does produce the new code.
    expect(expired?.restartAction).toBe(DESKTOP_CONTROLS.cancel_phone_pairing);
    expect(isDesktopControlLabel(expired!.restartAction!)).toBe(true);
    expect(expired?.restart).toContain(DESKTOP_CONTROLS.cancel_phone_pairing);
    expect(expired?.restart).toContain(DESKTOP_CONTROLS.pair_a_phone);
    // The retired label may never come back anywhere in the desktop surface.
    expect(allText(expired!)).not.toContain("Start again");
    expect(panelSource).not.toContain("Start again");

    const live = companionPairingWaitingView(waitingInput());
    expect(live?.restartAction).toBeNull();
    expect(live?.restart).toMatch(/cancel pairing/i);
  });

  it("never renders two buttons for the same cancel press", () => {
    // The panel's own trailing Cancel pairing is withheld exactly when the
    // waiting card renders the same handler under the same label.
    expect(panelSource).toContain("{offer && !waiting?.restartAction && (");
  });

  it("keeps the human code comparison and never promises auto-approval", () => {
    const view = companionPairingWaitingView(waitingInput());
    expect(view).not.toBeNull();
    expect(view?.humanCheck).toMatch(/nothing is paired automatically/i);
    expect(view?.humanCheck).toMatch(/compare the six digits/i);
    expect(view?.humanCheck).toMatch(/yes, the codes match/i);
    expect(allText(view!)).not.toMatch(
      /automatically (approv|pair|confirm|complet)/i,
    );
  });

  it("stays hidden when there is nothing to wait for", () => {
    expect(companionPairingWaitingView(waitingInput({ hasOffer: false }))).toBeNull();
    expect(companionPairingWaitingView(waitingInput({ hasConfirmation: false }))).toBeNull();
    // A manually scanned acknowledgement is already here, so it is not waiting.
    expect(companionPairingWaitingView(waitingInput({ hasScannedAck: true }))).toBeNull();
  });
});

describe("desktop pairing panel wiring", () => {
  it("renders the waiting state where the finish step is still missing", () => {
    expect(
      missingFrom(panelSource, [
        "const waiting = companionPairingWaitingView({",
        "ackReceived,",
        "{waiting && (",
        "{waiting.heading}",
        "{waiting.phoneInstruction}",
        "{waiting.validity}",
        "{waiting.humanCheck}",
        "{waiting.restart}",
      ]),
    ).toEqual([]);
    // The waiting card must sit before the finish step, where the owner is
    // looking for it.
    expect(panelSource.indexOf("{waiting && (")).toBeLessThan(
      panelSource.indexOf("3. Finish on this desktop"),
    );
  });

  it("leaves the pairing gates and the human comparison untouched", () => {
    expect(
      missingFrom(panelSource, [
        "offer && confirmation && ackReceived && !ack",
        "Yes, the codes match",
        "Finish only if the phone shows the same six digits",
        "Stop if the phone shows a different code",
      ]),
    ).toEqual([]);
  });

  it("introduces no auto-approval path", () => {
    const completions = panelSource.match(/agentWalletApi\.complete[A-Za-z]*\(/g) ?? [];
    expect(completions).toHaveLength(2);
    for (const call of ["completeAutomaticCompanionPairing", "completeCompanionPairing"]) {
      const at = panelSource.indexOf(`agentWalletApi.${call}(`);
      expect(at).toBeGreaterThan(0);
      const before = panelSource.slice(Math.max(0, at - 400), at);
      // Every completion is still reached only through a click by the owner.
      expect(before).toContain("onClick={");
    }
    for (const body of effectBodies(panelSource)) {
      expect(body).not.toContain("complete");
      expect(body).not.toContain("startCompanion");
      expect(body).not.toContain("acceptCompanionPairingRequest");
    }
    // No timer may push pairing forward on the owner's behalf.
    expect(panelSource).not.toMatch(/set(?:Timeout|Interval)\([^;]{0,200}complete/);
  });
});

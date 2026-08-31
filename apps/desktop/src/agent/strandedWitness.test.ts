import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import type { StrandedWitness } from "./api";
import { DESKTOP_CONTROLS, desktopControlLabels } from "./desktopControls";
import { ABANDON_STRANDED_PAYMENT_WARNING } from "./irreversibleActions";
import { strandedWitnessView } from "./strandedWitness";

const units = (value: string) => `${value} HAC`;

const waiting: StrandedWitness = {
  operation_id: "op_one",
  agent_id: "agent_one",
  asset: "HAC",
  amount_units: "10000",
  total_debit_units: "10100",
  recipient: "hacd1qexamplerecipient",
  status: "signed_awaiting_witness",
  submitted: false,
  transaction_id: "ebb3db27ba861c79c08805c4529172a43a7d438b5725888a800c05c742311f53",
  anchor_issued: false,
  anchor_expires_at: null,
  retryable: true,
  network_supports_witness_retry: true,
  abandonable: true,
  anchor_releasable: false,
  phone_replacement_unblocked: true,
};

/** The phone has an open confirmation window right now. */
const live: StrandedWitness = {
  ...waiting,
  anchor_issued: true,
  anchor_expires_at: 1_700_000_300,
  abandonable: false,
  phone_replacement_unblocked: false,
};

/** The window ran out before the confirmation came back. */
const expired: StrandedWitness = {
  ...waiting,
  anchor_issued: true,
  anchor_expires_at: 1_700_000_300,
  abandonable: true,
  anchor_releasable: true,
  phone_replacement_unblocked: false,
};

/**
 * THE OTHER HALF OF THIS PANEL. The transaction is already on the network in
 * all three of these, so every sentence that is true above is a lie here.
 */
const submittedLive: StrandedWitness = {
  ...waiting,
  status: "submitted_awaiting_final_witness",
  submitted: true,
  anchor_issued: true,
  anchor_expires_at: 1_700_000_300,
  abandonable: false,
  anchor_releasable: false,
  phone_replacement_unblocked: false,
};

const submittedExpired: StrandedWitness = {
  ...submittedLive,
  anchor_releasable: true,
};

const uncertain: StrandedWitness = {
  ...submittedExpired,
  status: "broadcast_uncertain",
};

const reconciled: StrandedWitness = {
  ...submittedExpired,
  status: "reconciled_awaiting_final_witness",
};

const everySubmitted = [submittedLive, submittedExpired, uncertain, reconciled];

/**
 * THE SAME STRANDED PAYMENT, ON A NETWORK THIS WALLET WILL NOT OPEN A
 * CONFIRMATION WINDOW ON.
 *
 * The core refuses the retry here, so the panel must not invite one. This is
 * the exact shape a mainnet owner sees, and it is the shape that used to print
 * "it is safe to try more than once" over a control that answered "configured
 * node does not match the Agent Wallet network".
 */
const retryUnavailable: StrandedWitness = {
  ...waiting,
  retryable: false,
  network_supports_witness_retry: false,
};

/** A confirmation is already in hand; the lifecycle owns it from here. */
const confirmationAlreadyIn: StrandedWitness = {
  ...waiting,
  anchor_issued: true,
  anchor_expires_at: 1_700_000_300,
  retryable: false,
  abandonable: false,
};

const everySentence = (input: StrandedWitness): string[] => {
  const view = strandedWitnessView(input, units);
  if (!view) throw new Error("expected a view");
  return [
    view.heading,
    view.summary,
    view.whereTheMoneyIs,
    view.explanation,
    view.phoneInstruction,
    view.abandonWithheldReason,
    view.afterAbandon,
    view.releaseExplanation,
    view.replacePhoneGuidance,
  ].filter((text) => text.length > 0);
};

describe("nothing is reported when nothing is waiting", () => {
  it("returns null rather than an empty panel", () => {
    expect(strandedWitnessView(null, units)).toBeNull();
  });
});

describe("an unwitnessed payment is never described as a paid one", () => {
  // This is the whole risk of a recovery screen. The owner is looking at a
  // payment that reached `signed_awaiting_witness` and stopped, and every word
  // here has to keep saying so - including on the screen that offers to throw
  // it away.
  it.each([
    ["never asked", waiting],
    ["window open", live],
    ["window expired", expired],
  ])("claims no payment, send or confirmation (%s)", (_name, input) => {
    for (const sentence of everySentence(input)) {
      expect(sentence).not.toMatch(/\b(paid|witnessed|submitted|broadcast)\b/i);
      // "sent" may only ever appear as a denial.
      const claimsSent = /\bsent\b/i.test(sentence);
      if (claimsSent) {
        expect(sentence).toMatch(/never sent|nothing has been sent/i);
      }
    }
  });

  it("says outright that nothing reached the network in every anchor state", () => {
    for (const input of [waiting, live, expired]) {
      const view = strandedWitnessView(input, units);
      expect(view?.whereTheMoneyIs).toContain(
        "Nothing has been sent to the network and no money has moved",
      );
    }
  });

  it("names the exact amount and recipient being given up", () => {
    const view = strandedWitnessView(expired, units);
    expect(view?.summary).toContain("10000 HAC");
    expect(view?.summary).toContain(expired.recipient);
  });
});

describe("the phone is always offered first", () => {
  it.each([
    ["never asked", waiting],
    ["window open", live],
    ["window expired", expired],
  ])("points at the phone app and says retrying is free (%s)", (_name, input) => {
    const view = strandedWitnessView(input, units);
    expect(view?.phoneInstruction).toContain("AI Agent Wallet");
    expect(view?.phoneInstruction).toContain("costs nothing and moves no money");
  });

  it("still points at the phone once the payment is on the network", () => {
    for (const input of everySubmitted) {
      const view = strandedWitnessView(input, units);
      expect(view?.phoneInstruction).toContain("AI Agent Wallet");
      // And is careful not to suggest confirming pays a second time.
      expect(view?.phoneInstruction).toContain("cannot move money twice");
    }
  });

  it("does not offer a retry the core would refuse, and says which reason it is", () => {
    // A wallet that cannot open a window at all: the phone is not the answer,
    // and the owner is pointed at the one thing that does work.
    const blocked = strandedWitnessView(retryUnavailable, units);
    expect(blocked?.canRetryPhone).toBe(false);
    expect(blocked?.phoneInstruction).toContain("cannot ask your phone");
    expect(blocked?.phoneInstruction).not.toContain("safe to try more than once");
    expect(blocked?.phoneInstruction).toContain(
      "Nothing has been sent to the network and no money has moved",
    );
    expect(blocked?.canAbandon).toBe(true);

    // A confirmation already on its way in is the opposite situation and gets
    // the opposite sentence: nothing is wrong and nothing needs pressing.
    const settled = strandedWitnessView(confirmationAlreadyIn, units);
    expect(settled?.canRetryPhone).toBe(false);
    expect(settled?.phoneInstruction).toContain("already sent a confirmation");
    expect(settled?.phoneInstruction).not.toContain("cannot ask your phone");
  });

  it("says a dead window is restarted by opening the payment again", () => {
    const view = strandedWitnessView(expired, units);
    expect(view?.anchorExpired).toBe(true);
    expect(view?.explanation).toContain("ran out");
    expect(view?.explanation).toContain("starts a new window");
  });
});

describe("the give-up control mirrors the core, and never guesses", () => {
  it("is withheld while the phone still has an open window", () => {
    const view = strandedWitnessView(live, units);
    expect(view?.canAbandon).toBe(false);
    expect(view?.anchorExpired).toBe(false);
    // A withheld control must say why and when, not just vanish.
    expect(view?.abandonWithheldReason).toContain("open confirmation window");
    expect(view?.abandonWithheldReason).toContain("five minutes");
  });

  it("is offered once nothing outstanding could still confirm", () => {
    for (const input of [waiting, expired]) {
      const view = strandedWitnessView(input, units);
      expect(view?.canAbandon).toBe(true);
      expect(view?.abandonWithheldReason).toBe("");
    }
  });

  it("follows `abandonable` and never re-derives it from the anchor", () => {
    // A core that refuses must be obeyed even when the anchor looks dead, and a
    // core that allows must be obeyed even when no anchor was ever issued.
    expect(
      strandedWitnessView({ ...expired, abandonable: false }, units)?.canAbandon,
    ).toBe(false);
    expect(
      strandedWitnessView({ ...waiting, abandonable: true }, units)?.canAbandon,
    ).toBe(true);
  });
});

describe("what it costs is said before the press", () => {
  it("promises the money back and the payment gone, in that order of clarity", () => {
    expect(ABANDON_STRANDED_PAYMENT_WARNING).toContain("final");
    expect(ABANDON_STRANDED_PAYMENT_WARNING).toContain("No money moves");
    expect(ABANDON_STRANDED_PAYMENT_WARNING).toContain("signed but never sent");
    expect(ABANDON_STRANDED_PAYMENT_WARNING).toContain(
      "reserved funds return to your spendable balance",
    );
    expect(ABANDON_STRANDED_PAYMENT_WARNING).toContain("ask for it again");
  });

  it("names the follow-up an owner may still need, and it is a real control", () => {
    const view = strandedWitnessView(expired, units);
    expect(view?.afterAbandon).toContain(
      DESKTOP_CONTROLS.replace_the_paired_phone,
    );
    expect(desktopControlLabels()).toContain(
      DESKTOP_CONTROLS.replace_the_paired_phone,
    );
    // The residue is stated rather than hidden: a phone that already accepted
    // the payment will refuse the next one until it is replaced.
    expect(view?.afterAbandon).toContain("refuse the next one");
  });
});

describe("a payment that already went to the network is never described as one that did not", () => {
  // The mirror image of the block above, and the more dangerous half. The money
  // has moved. Nothing here may deny it, soften it, or offer a control that
  // would record it as never having happened.
  it.each([
    ["submitted, window open", submittedLive],
    ["submitted, window expired", submittedExpired],
    ["uncertain acknowledgement", uncertain],
    ["confirmed on chain", reconciled],
  ])("never claims nothing was sent (%s)", (_name, input) => {
    for (const sentence of everySentence(input)) {
      expect(sentence).not.toMatch(/nothing has been sent/i);
      expect(sentence).not.toMatch(/no money has moved/i);
      expect(sentence).not.toMatch(/never sent/i);
    }
  });

  it("says plainly that the payment was sent, in every submitted status", () => {
    for (const input of everySubmitted) {
      expect(strandedWitnessView(input, units)?.whereTheMoneyIs).toContain(
        "was sent to the network",
      );
    }
  });

  it("hands over the transaction id so the owner can check the chain", () => {
    for (const input of everySubmitted) {
      expect(strandedWitnessView(input, units)?.transactionId).toBe(
        input.transaction_id,
      );
    }
  });

  it("does not claim an unverifiable acknowledgement is a confirmation", () => {
    const view = strandedWitnessView(uncertain, units);
    expect(view?.whereTheMoneyIs).toContain("not yet known");
    expect(view?.whereTheMoneyIs).not.toContain("confirmed on chain");
  });

  it("says a confirmed payment is confirmed, and still unwitnessed", () => {
    const view = strandedWitnessView(reconciled, units);
    expect(view?.whereTheMoneyIs).toContain("confirmed on chain");
    expect(view?.whereTheMoneyIs).toContain("final confirmation");
  });

  it("never offers to give up a payment that already happened", () => {
    for (const input of everySubmitted) {
      const view = strandedWitnessView(input, units);
      expect(view?.canAbandon).toBe(false);
      // And says the real reason, which is not a timing one.
      expect(view?.abandonWithheldReason).toContain("already been sent");
      expect(view?.abandonWithheldReason).not.toContain("five minutes");
    }
  });
});

describe("the two escapes past the phone mirror the core, and never guess", () => {
  it("offers clearing the dead window exactly when the core would allow it", () => {
    expect(strandedWitnessView(expired, units)?.canReleaseAnchor).toBe(true);
    expect(strandedWitnessView(live, units)?.canReleaseAnchor).toBe(false);
    expect(strandedWitnessView(waiting, units)?.canReleaseAnchor).toBe(false);
    expect(strandedWitnessView(submittedExpired, units)?.canReleaseAnchor).toBe(
      true,
    );
  });

  it("promises that clearing the window changes nothing about the payment", () => {
    const view = strandedWitnessView(submittedExpired, units);
    expect(view?.releaseExplanation).toContain("changes nothing about this payment");
    expect(view?.releaseExplanation).toContain("same transaction id");
  });

  it("offers the phone replacement exactly when the core would allow it", () => {
    expect(strandedWitnessView(waiting, units)?.canReplacePhone).toBe(true);
    expect(strandedWitnessView(expired, units)?.canReplacePhone).toBe(false);
    for (const input of everySubmitted) {
      expect(strandedWitnessView(input, units)?.canReplacePhone).toBe(false);
    }
  });

  it("says the replacement keeps the payment when it is on offer", () => {
    const view = strandedWitnessView(waiting, units);
    expect(view?.replacePhoneGuidance).toContain("keeps this payment");
  });

  it("names the next step, or says why the replacement is not the answer", () => {
    expect(strandedWitnessView(expired, units)?.replacePhoneGuidance).toContain(
      "Clear the expired confirmation window first",
    );
    // Post-submit it is not a matter of order: it cannot help at all, and
    // sending the owner down it would cost them their working phone.
    for (const input of everySubmitted) {
      const guidance = strandedWitnessView(input, units)?.replacePhoneGuidance;
      expect(guidance).toContain("cannot resolve this payment");
      expect(guidance).toContain("never saw");
    }
  });
});

describe("the recovery panel is reachable where the owner is stuck", () => {
  /**
   * The page with its comments removed. A comment that mentions `<details>`
   * must not count as a disclosure, and a token that appears only in a comment
   * must not count as rendered.
   */
  const security = readFileSync(
    new URL("./AgentAdminPages.tsx", import.meta.url),
    "utf8",
  )
    .replace(/\/\*[\s\S]*?\*\//g, " ")
    .replace(/^[ 	]*\/\/.*$/gm, " ");

  it("renders on the desktop Security page, not on the phone", () => {
    expect(security).toContain("strandedWitnessView(stranded, formatUnits)");
    expect(security).toContain("DESKTOP_CONTROLS.give_up_stranded_payment");
    expect(security).toContain("agentWalletApi.abandonStrandedWitness");
  });

  it("re-reads the waiting payment on the same load as the approvals", () => {
    // Otherwise the panel keeps offering a control for a payment that was
    // finished on the phone a moment ago.
    // Anchored on the stranded read, because another page on this file loads
    // the pending approvals too and its `load` comes first.
    const start = security.lastIndexOf(
      "const load = useCallback(",
      security.indexOf("agentWalletApi.strandedWitness"),
    );
    const body = security.slice(
      start,
      security.indexOf("useEffect(() => { void load(); }, [load]);", start),
    );
    expect(body).toContain("agentWalletApi.listPendingApprovals");
    expect(body).toContain("agentWalletApi.strandedWitness");
  });

  it("takes two presses, and the first one shows the cost", () => {
    expect(security).toContain("{ABANDON_STRANDED_PAYMENT_WARNING}");
    expect(security).toContain("Confirm give up");
    // The warning and the confirming press sit outside every disclosure.
    const index = security.indexOf("{ABANDON_STRANDED_PAYMENT_WARNING}");
    const before = security.slice(0, index);
    expect(before.split("<details").length).toBe(
      before.split("</details>").length,
    );
  });

  it("never offers the control on a failed read", () => {
    // A read that throws sets null, and a null renders nothing at all rather
    // than a panel with an enabled danger button.
    expect(security).toContain("catch { setStranded(null); }");
    expect(strandedWitnessView(null, units)).toBeNull();
  });
});

describe("what a mainnet owner reads when the witness rail is not on their network", () => {
  // Both of these sentences were live and false on the exact path the mainnet
  // exit opens. Neither the builder nor its skeptic found them; they were
  // caught by reading what the panel actually renders, which is unconditional.
  const strandedOnMainnet = {
    operation_id: "op-1",
    transaction_id: "tx-1",
    amount_units: 1_000,
    recipient: "1Recipient",
    submitted: false,
    anchor_issued: false,
    anchor_releasable: false,
    retryable: false,
    abandonable: true,
    phone_replacement_unblocked: false,
    network_supports_witness_retry: false,
  };

  it("never says a confirmation window is open when none can exist", () => {
    // The old fallback said "Your phone still has an open confirmation window,
    // so replacing it is not offered yet." On mainnet no window was ever
    // opened and none can be: the anchor is testnet only.
    const view = strandedWitnessView(strandedOnMainnet as never, units);
    if (!view) throw new Error("expected a view");
    expect(view.replacePhoneGuidance).not.toMatch(/still has an open confirmation window/i);
    expect(view.replacePhoneGuidance).toMatch(/not available on this network/i);
  });

  it("does not send the owner to a control that refuses on their network", () => {
    // afterAbandon named Replace the paired phone as "the only thing that
    // clears that". On mainnet that control answers
    // WitnessRotationNetworkUnsupported.
    const view = strandedWitnessView(strandedOnMainnet as never, units);
    if (!view) throw new Error("expected a view");
    expect(view.afterAbandon).not.toMatch(/the only thing that clears that is/i);
    expect(view.afterAbandon).toMatch(/not available on this network/i);
  });

  it("still names the control where it does work", () => {
    // The fix must not remove the guidance from the rail that has it.
    const view = strandedWitnessView(
      { ...strandedOnMainnet, network_supports_witness_retry: true } as never,
      units,
    );
    if (!view) throw new Error("expected a view");
    expect(view.afterAbandon).toMatch(/the only thing that clears that is/i);
  });
});

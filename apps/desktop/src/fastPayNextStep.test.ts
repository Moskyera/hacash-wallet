/**
 * "WHAT IS THE NEXT THING I DO, AND CAN I DO IT RIGHT NOW?"
 *
 * The Fast Pay screen could answer every question except that one. It showed a
 * state pill, a route hint, a consent block, a hub finder, a preflight report
 * and a refusal list, and left a person to read all six and work out which one
 * was their turn. The owner sat on this screen with a healthy Hub and could not
 * tell whether they were waiting on the wallet, on their Hub, on their node, or
 * on themselves.
 *
 * `fastPayNextStep` picks the single next action and says whether it can be
 * taken right now. It decides nothing - it reads the refusal list that
 * `fastPayEnableRefusals` already produces, plus the measured state - and every
 * gate still runs for real in the core.
 */
import { describe, expect, it } from "vitest";
import {
  fastPayNextStep,
  type FastPayEnableRefusal,
} from "@hacash/wallet-ui";

const noRefusals: FastPayEnableRefusal[] = [];

const consentRefusal: FastPayEnableRefusal = {
  id: "mainnet_consent_withheld",
  title: "The bounded mainnet pilot has not been accepted",
  detail: "Tick the consent box near the top of this screen.",
};

const addressRefusal: FastPayEnableRefusal = {
  id: "no_provider_address",
  title: "No provider address is saved",
  detail: 'Use "Check this hub" then "Use this hub".',
};

describe("the Fast Pay screen names one next step", () => {
  it("says there is nothing to do when Fast Pay is already on", () => {
    const step = fastPayNextStep({ state: "ready", refusals: noRefusals, nodeReachable: true });
    expect(step.canActNow).toBe(true);
    expect(step.action).toMatch(/Send/i);
    expect(step.blockedBy).toBeNull();
  });

  it("names Enable as the next step when nothing is stopping it", () => {
    const step = fastPayNextStep({
      state: "needs_channel",
      refusals: noRefusals,
      nodeReachable: true,
    });
    expect(step.canActNow).toBe(true);
    expect(step.action).toMatch(/Enable Fast Pay/i);
  });

  it("hands back the first refusal as the next step, in words", () => {
    const step = fastPayNextStep({
      state: "needs_channel",
      refusals: [consentRefusal, addressRefusal],
      nodeReachable: true,
    });
    expect(step.canActNow).toBe(false);
    // The words, not the identifier. `mainnet_consent_withheld` is not an
    // instruction to a person.
    expect(step.action).toContain("consent box");
    expect(step.headline).toContain("bounded mainnet pilot");
    expect(step.blockedBy).toBe("mainnet_consent_withheld");
  });

  it("counts the rest so a person knows this is not the only one", () => {
    const step = fastPayNextStep({
      state: "needs_channel",
      refusals: [consentRefusal, addressRefusal],
      nodeReachable: true,
    });
    expect(step.remaining).toBe(1);
  });

  it("puts the provider address ahead of the consent box, because it comes first in practice", () => {
    // Saving a provider is what un-blocks the deposit and the caps, so it is
    // the step that unlocks the most of the screen.
    const step = fastPayNextStep({
      state: "needs_channel",
      refusals: [consentRefusal, addressRefusal],
      nodeReachable: true,
      preferOrder: ["no_provider_address", "mainnet_consent_withheld"],
    });
    expect(step.blockedBy).toBe("no_provider_address");
  });

  it("says the node is unreachable before it says anything else", () => {
    // A node that cannot be reached makes every other step pointless, and the
    // preflight already knows. It was the one fact the screen never promoted.
    const step = fastPayNextStep({
      state: "needs_channel",
      refusals: [consentRefusal],
      nodeReachable: false,
    });
    expect(step.canActNow).toBe(false);
    expect(step.blockedBy).toBe("node_unreachable");
    expect(step.action.toLowerCase()).toContain("node");
  });

  it("does not claim the node is unreachable when nobody has checked", () => {
    // `null` is "not measured". Reporting unknown as broken sends a person to
    // fix something that may be fine, and this repository's own comment says
    // telling a user a wrong cause is worse than a vague one.
    const step = fastPayNextStep({
      state: "needs_channel",
      refusals: [consentRefusal],
      nodeReachable: null,
    });
    expect(step.blockedBy).toBe("mainnet_consent_withheld");
  });

  it("never returns an empty action", () => {
    for (const state of ["ready", "needs_channel", "no_provider", "checking", "hub_unreachable"]) {
      for (const refusals of [noRefusals, [consentRefusal]]) {
        const step = fastPayNextStep({ state, refusals, nodeReachable: true });
        expect(step.action.trim().length).toBeGreaterThan(0);
        expect(step.headline.trim().length).toBeGreaterThan(0);
      }
    }
  });

  it("tells somebody with no provider to go and find one", () => {
    const step = fastPayNextStep({
      state: "no_provider",
      refusals: [addressRefusal],
      nodeReachable: true,
    });
    expect(step.canActNow).toBe(false);
    expect(step.action).toMatch(/hub/i);
  });
});

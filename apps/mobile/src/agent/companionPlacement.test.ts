/**
 * Where the phone puts the control a state depends on, not merely that it has
 * one.
 *
 * The desktop was measured at a 760px viewport and one control was found three
 * blocks below the fold. The phone had the same shape of fault at 960px and no
 * test could have caught it, because every test it had asserted that a control
 * existed somewhere in the tree. Existence is not placement, so everything
 * below is about position.
 *
 * Found by this sweep, and fixed:
 *  - Create the secure identity, the control that every later step waits on,
 *    rendered on the Security tab underneath the unpaired onboarding hero, the
 *    pairing panel, an identity table and a revocation reference.
 *  - Send my confirmation, the only control a phone waiting on desktop
 *    finalization has, rendered underneath a full Security tab.
 */
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
  COMPANION_ABOVE_THE_FOLD_PANELS,
  COMPANION_PRIMARY_ACTION_BLOCK,
  COMPANION_PRIMARY_ACTION_LABELS,
  companionAboveTheFold,
  companionBlockIsRendered,
  companionBlockOrder,
  companionPageLeadsWithOwnContent,
  companionPrimaryAction,
  companionPrimaryActionBlock,
  type AgentCompanionPage,
  type CompanionBlockId,
  type CompanionBlockOrderInput,
} from "./companionLayout";

const AGENT_DIR = dirname(fileURLToPath(import.meta.url));
const read = (name: string) => readFileSync(join(AGENT_DIR, name), "utf8");
/** Comments removed: a guard quoted in a comment is not a guard. */
const withoutComments = (source: string) =>
  source
    .replace(/\{\s*\/\*[\s\S]*?\*\/\s*\}/g, " ")
    .replace(/\/\*[\s\S]*?\*\//g, " ")
    .replace(/^[ \t]*\/\/.*$/gm, " ");

const APP = withoutComments(read("AgentCompanionApp.tsx"));
const SECURITY = withoutComments(read("CompanionSecurity.tsx"));

const TABS: AgentCompanionPage[] = [
  "overview",
  "agents",
  "rules",
  "activity",
  "security",
];

const ALL_BLOCKS: CompanionBlockId[] = [
  "status_strip",
  "onboarding",
  "pairing",
  "pending_pairing_step",
  "connection",
  "page_content",
];

/**
 * Every state the phone can actually be in.
 *
 * The impossible combinations are excluded on purpose: a completed ceremony
 * implies a ceremony, a trusted snapshot implies a session, a session implies
 * a pairing, a pairing implies an identity, and an identity implies a handset
 * that can hold one. Asserting placement for a state the app cannot reach
 * would prove nothing.
 */
function everyState(): CompanionBlockOrderInput[] {
  const states: CompanionBlockOrderInput[] = [];
  for (const page of TABS) {
    for (const platformSupported of [false, true]) {
      for (const identityConfigured of [false, true]) {
        for (const configured of [false, true]) {
          for (const pairingInProgress of [false, true]) {
            for (const pairingCompleted of [false, true]) {
              for (const pendingPairingFinalization of [false, true]) {
                for (const hasSession of [false, true]) {
                  for (const hasTrustedSnapshot of [false, true]) {
                    for (const connectRetryAvailable of [false, true]) {
                      for (const pendingApprovals of [0, 2]) {
                        if (!platformSupported && identityConfigured) continue;
                        if (configured && !identityConfigured) continue;
                        if (pairingCompleted && !pairingInProgress) continue;
                        if (hasSession && !configured) continue;
                        if (hasTrustedSnapshot && !hasSession) continue;
                        if (pendingApprovals > 0 && !hasTrustedSnapshot) continue;
                        states.push({
                          page,
                          platformSupported,
                          identityConfigured,
                          configured,
                          pairingInProgress,
                          pairingCompleted,
                          pendingPairingFinalization,
                          hasSession,
                          hasTrustedSnapshot,
                          connectRetryAvailable,
                          pendingApprovals,
                        });
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
  }
  return states;
}

function describeState(state: CompanionBlockOrderInput): string {
  return `page=${state.page} configured=${state.configured} identity=${state.identityConfigured} ceremony=${state.pairingInProgress}/${state.pairingCompleted} pending=${state.pendingPairingFinalization} session=${state.hasSession}`;
}

describe("the control a state depends on is on the first screen", () => {
  it("renders the block that owns the primary action above the fold", () => {
    for (const state of everyState()) {
      const primary = companionPrimaryAction(state);
      if (primary.id === "none") continue;
      const owner = companionPrimaryActionBlock(state);
      expect(owner).not.toBeNull();
      const order = companionBlockOrder(state);
      expect(
        companionAboveTheFold(order),
        `${primary.label} is the one control ${describeState(state)} has, and its block "${owner}" is at position ${order.indexOf(
          owner as CompanionBlockId,
        )} of ${order.length}. It cannot be reached without scrolling.`,
      ).toContain(owner);
    }
  });

  it("never names a primary action whose block is not on screen at all", () => {
    for (const state of everyState()) {
      const owner = companionPrimaryActionBlock(state);
      if (!owner) continue;
      expect(
        companionBlockIsRendered(owner, state),
        `${describeState(state)} promotes a control in "${owner}", which this state does not render`,
      ).toBe(true);
    }
  });

  it("keeps the one-line status strip first, and lets nothing else above", () => {
    for (const state of everyState()) {
      const order = companionBlockOrder(state);
      expect(order[0]).toBe("status_strip");
      // Strip plus one panel: that is the whole first screen at 960px.
      expect(companionAboveTheFold(order)).toHaveLength(
        Math.min(order.length, 1 + COMPANION_ABOVE_THE_FOLD_PANELS),
      );
    }
  });

  it("renders every block that belongs in a state, exactly once", () => {
    for (const state of everyState()) {
      const order = companionBlockOrder(state);
      expect(new Set(order).size).toBe(order.length);
      for (const block of ALL_BLOCKS) {
        expect(
          order.includes(block),
          `${block} disagrees with its own render guard in ${describeState(state)}`,
        ).toBe(companionBlockIsRendered(block, state));
      }
    }
  });

  it("still leads with the selected tab once the phone is connected and quiet", () => {
    // The earlier fix, unchanged: a paired, connected phone with nothing
    // outstanding opens the tab the owner chose, not the connection card.
    for (const page of TABS) {
      const state: CompanionBlockOrderInput = {
        page,
        platformSupported: true,
        identityConfigured: true,
        configured: true,
        pairingInProgress: false,
        pairingCompleted: false,
        pendingPairingFinalization: false,
        hasSession: true,
        hasTrustedSnapshot: true,
        connectRetryAvailable: false,
        pendingApprovals: 0,
      };
      expect(companionPrimaryAction(state).id).toBe("none");
      expect(companionPageLeadsWithOwnContent(state)).toBe(true);
      expect(companionBlockOrder(state)[1]).toBe("page_content");
    }
  });

  it("leads with the ceremony while a pairing is running", () => {
    const order = companionBlockOrder({
      page: "overview",
      platformSupported: true,
      identityConfigured: true,
      configured: false,
      pairingInProgress: true,
      pairingCompleted: false,
      pendingPairingFinalization: false,
      hasSession: false,
      hasTrustedSnapshot: false,
      connectRetryAvailable: false,
      pendingApprovals: 0,
    });
    // No single label can be named for a wizard, but the wizard still owns
    // every control the owner needs, so the onboarding prose goes under it.
    expect(order[1]).toBe("pairing");
    expect(order.indexOf("onboarding")).toBeGreaterThan(1);
  });

  it("hoists the one-last-step block a phone waiting on the desktop depends on", () => {
    for (const page of TABS) {
      const order = companionBlockOrder({
        page,
        platformSupported: true,
        identityConfigured: true,
        configured: true,
        pairingInProgress: false,
        pairingCompleted: false,
        pendingPairingFinalization: true,
        hasSession: false,
        hasTrustedSnapshot: false,
        connectRetryAvailable: false,
        pendingApprovals: 0,
      });
      expect(order[1]).toBe("pending_pairing_step");
    }
  });

  it("hoists the Security tab when it owns the identity the phone has not got", () => {
    const order = companionBlockOrder({
      page: "security",
      platformSupported: true,
      identityConfigured: false,
      configured: false,
      pairingInProgress: false,
      pairingCompleted: false,
      pendingPairingFinalization: false,
      hasSession: false,
      hasTrustedSnapshot: false,
      connectRetryAvailable: false,
      pendingApprovals: 0,
    });
    expect(order[1]).toBe("page_content");
    expect(order.indexOf("onboarding")).toBeGreaterThan(1);
  });
});

describe("the sources put those blocks where the model says they are", () => {
  it("renders every block once, in the order the model returns", () => {
    expect(APP).toContain("const blockOrder = companionBlockOrder(layout);");
    expect(APP).toContain("{blockOrder.map((id) => renderBlock(id))}");
    const cases: Array<[CompanionBlockId, string]> = [
      ["status_strip", "statusStripBlock"],
      ["onboarding", "onboardingBlock"],
      ["pairing", "pairingBlock"],
      ["pending_pairing_step", "pendingPairingStepBlock"],
      ["connection", "connectionBlock"],
      ["page_content", "pageContent"],
    ];
    for (const [id, variable] of cases) {
      const marker = `case "${id}":`;
      const index = APP.indexOf(marker);
      expect(index, `${id} has no case in renderBlock`).toBeGreaterThan(0);
      expect(
        APP.slice(index, index + 160),
        `${id} does not render ${variable}`,
      ).toContain(`{${variable}}`);
      // One position in the tree. A block with two positions is how a control
      // ends up above the fold in one state and below it in another.
      expect(APP.match(new RegExp(`\\{${variable}\\}`, "g"))).toHaveLength(1);
    }
  });

  it("keeps the render guards and the model's guards the same", () => {
    for (const guard of [
      "const onboardingBlock = !companion.stored?.configured ?",
      "!companion.stored?.configured || pairing?.completion ?",
      "companion.stored?.pendingPairingFinalization && !pairing?.completion ?",
      "const connectionBlock = companion.stored?.configured ?",
    ]) {
      expect(APP, `${guard} no longer matches companionBlockIsRendered`).toContain(
        guard,
      );
    }
  });

  it("puts the identity control above everything that describes it", () => {
    // "Create the secure identity" was the fourth section of the Security tab.
    //
    // Measured on the RENDER position, not on where the section happens to be
    // declared. Reading the declaration is exactly the mistake that lets a
    // control be declared at the top of a component and rendered at the bottom.
    const rendered = SECURITY.slice(SECURITY.indexOf("  return ("));
    const create = rendered.indexOf("{createIdentity}");
    const confirm = rendered.indexOf("{confirmIdentity}");
    const identityTable = rendered.indexOf("<h2>Mobile companion identity</h2>");
    const revocation = rendered.indexOf("{COMPANION_REVOKED_TITLE}");
    const boundary = rendered.indexOf("<summary>Security boundary</summary>");
    expect(create).toBeGreaterThan(0);
    expect(confirm).toBeGreaterThan(0);
    for (const reference of [identityTable, revocation, boundary]) {
      expect(reference).toBeGreaterThan(0);
      expect(
        create,
        "the identity control renders below reference material again",
      ).toBeLessThan(reference);
      expect(confirm).toBeLessThan(reference);
    }
    // Not folded away, which is the same fault as being below the fold.
    const before = rendered.slice(0, create);
    expect(
      before.split("<details").length - before.split("</details>").length,
    ).toBe(0);
    // And the block really is the button, not a sentence quoting it.
    const block = SECURITY.slice(
      SECURITY.indexOf("const createIdentity ="),
      SECURITY.indexOf("const confirmIdentity ="),
    );
    const label = block.indexOf("{COMPANION_CREATE_IDENTITY_ACTION}");
    const button = block.lastIndexOf("<button", label);
    expect(label).toBeGreaterThan(0);
    expect(button).toBeGreaterThanOrEqual(0);
    expect(block.slice(button, label)).not.toContain("</button>");
  });

  it("stops the hero pointing at the screen the owner is already on", () => {
    // "Start here. The next screen creates this phone's secure identity" is
    // false on the Security tab, and on that tab the real control is already
    // above this block.
    expect(APP).toContain('{companion.identity?.ready || page === "security" ? null : (');
    expect(APP).toContain("{COMPANION_OPEN_SECURITY_SETUP_ACTION}");
  });

  it("names only labels that a control on this phone really carries", () => {
    // The block table and the label table must describe the same controls.
    for (const id of Object.keys(COMPANION_PRIMARY_ACTION_LABELS)) {
      expect(
        COMPANION_PRIMARY_ACTION_BLOCK[
          id as keyof typeof COMPANION_PRIMARY_ACTION_BLOCK
        ],
        `${id} has a label but no block`,
      ).toBeTruthy();
    }
    for (const block of Object.values(COMPANION_PRIMARY_ACTION_BLOCK)) {
      expect(ALL_BLOCKS).toContain(block);
    }
  });
});

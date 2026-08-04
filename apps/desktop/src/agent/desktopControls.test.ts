import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import {
  DESKTOP_CONTROLS,
  DESKTOP_CONTROL_IDS,
  DESKTOP_CONTROL_LABEL_TOKENS,
  RETIRED_DESKTOP_INSTRUCTIONS,
  desktopControlLabels,
} from "./desktopControls";
import {
  DESKTOP_IRREVERSIBLE_ACTIONS,
  irreversibleControlLabel,
  irreversibleWarningFor,
} from "./irreversibleActions";

const readRaw = (name: string) =>
  readFileSync(new URL(`./${name}`, import.meta.url), "utf8");

/**
 * The source with its comments removed.
 *
 * A comment explaining that a false instruction was removed must not itself
 * count as that instruction coming back, and a label that appears only in a
 * comment must not count as rendered.
 */
const read = (name: string) =>
  readRaw(name)
    .replace(/\/\*[\s\S]*?\*\//g, " ")
    .replace(/^[ \t]*\/\/.*$/gm, " ");

/** JSX wraps prose across lines, so compare on collapsed whitespace. */
const flatten = (source: string) => source.replace(/\s+/g, " ");

const VIEWS = [
  "AgentWalletApp.tsx",
  "MobileCompanionPanel.tsx",
  "AgentAdminPages.tsx",
] as const;

const COPY = [
  "access.ts",
  "companionPairingFeedback.ts",
  "companionWaitingView.ts",
  "desktopControls.ts",
  "irreversibleActions.ts",
  "overviewLayout.ts",
] as const;

const viewSource = VIEWS.map(read).join("\n");
const allSource = [...VIEWS, ...COPY].map(read).join("\n");
/**
 * Everything an owner can be shown, minus the table that lists the retired
 * strings so they can be tested for.
 */
const instructionSource = [...VIEWS, ...COPY]
  .filter((name) => name !== "desktopControls.ts")
  .map(read)
  .join("\n");

describe("every named control is actually rendered", () => {
  it.each(DESKTOP_CONTROL_IDS)("renders %s", (id) => {
    const label = DESKTOP_CONTROLS[id];
    const token = DESKTOP_CONTROL_LABEL_TOKENS[id];
    const rendered =
      viewSource.includes(label) ||
      viewSource.includes(`DESKTOP_CONTROLS.${id}`) ||
      (token !== undefined && viewSource.includes(token));
    expect(rendered, `${label} is named but never rendered`).toBe(true);
  });

  it("keeps every label distinct, so no instruction is ambiguous", () => {
    const labels = desktopControlLabels();
    expect(new Set(labels).size).toBe(labels.length);
  });
});

describe("retired instructions never come back", () => {
  // Two false instructions in this codebase caused a permanent, unrecoverable
  // device revocation. Each of these named a control that did not exist, or an
  // action the control never performed.
  it.each(RETIRED_DESKTOP_INSTRUCTIONS)("never says %s again", (instruction) => {
    // Flattened: JSX wraps a sentence across lines, and a wrapped lie is still
    // a lie.
    expect(flatten(instructionSource)).not.toContain(flatten(instruction));
  });

  it("keeps the connector label honest about calling stop", () => {
    // The button reads "Clear the failed connector" and its handler is onStop.
    expect(viewSource).toContain("DESKTOP_CONTROLS.clear_failed_connector");
    expect(viewSource).not.toContain("Restart the AI agent connector");
  });

  it("offers a real route wherever another Agent Wallet owns something", () => {
    // The old copy said "Open that wallet to manage it" and the unlocked UI has
    // no wallet picker at all. Locking returns to the unlock screen, which has.
    const switches = viewSource.split("DESKTOP_CONTROLS.lock_and_switch_wallet");
    expect(switches.length - 1).toBeGreaterThanOrEqual(2);
  });
});

describe("irreversible actions warn before they are taken", () => {
  it.each(DESKTOP_IRREVERSIBLE_ACTIONS)(
    "warns before $id",
    (entry) => {
      expect(desktopControlLabels()).toContain(irreversibleControlLabel(entry));
      expect(entry.warning.length).toBeGreaterThan(40);
      expect(entry.warning.toLowerCase()).toMatch(
        /permanent|cannot|final|recalled/,
      );
      // The warning must be in the shipped sources, not only in this table.
      expect(allSource).toContain(entry.warning);
    },
  );

  it("renders every irreversible warning in at least one view", () => {
    for (const entry of DESKTOP_IRREVERSIBLE_ACTIONS) {
      const rendered = VIEWS.some((view) =>
        read(view).includes(`{${entry.renderedAs}}`),
      );
      expect(rendered, `${entry.id} warning is never rendered`).toBe(true);
    }
  });

  it("keeps every irreversible warning out of a collapsed disclosure", () => {
    // A <details> around a before-the-fact warning is the same failure as no
    // warning at all, so no warning may sit inside a disclosure block.
    for (const entry of DESKTOP_IRREVERSIBLE_ACTIONS) {
      for (const view of VIEWS) {
        const source = read(view);
        for (const needle of [entry.warning, `{${entry.renderedAs}}`]) {
          let index = source.indexOf(needle);
          while (index !== -1) {
            const before = source.slice(0, index);
            const opened = before.split("<details").length - 1;
            const closed = before.split("</details>").length - 1;
            expect(
              opened,
              `${entry.id} warning is inside a <details> in ${view}`,
            ).toBe(closed);
            index = source.indexOf(needle, index + 1);
          }
        }
      }
    }
  });

  it("requires a second press wherever the table says so", () => {
    for (const entry of DESKTOP_IRREVERSIBLE_ACTIONS) {
      if (!entry.confirmLabel) continue;
      expect(viewSource).toContain(entry.confirmLabel);
    }
  });

  it("finds the warning that belongs to a control", () => {
    expect(irreversibleWarningFor("revoke_agent")).toContain("permanent");
    expect(irreversibleWarningFor("disable_all_agent_payments")).toContain(
      "cannot reverse a transaction that has already been submitted",
    );
    // Reversible controls carry no irreversibility claim.
    expect(irreversibleWarningFor("refresh")).toBe("");
    expect(irreversibleWarningFor("turn_on_phone_connection")).toBe("");
  });
});

describe("the phone panel keeps both phone controls reachable", () => {
  const panel = read("MobileCompanionPanel.tsx");

  it("offers pairing whether the connection is on or off", () => {
    // The whole pairing UI used to live in the `else` of `status?.enabled`, so
    // pairing a second phone, or re-pairing after a revoke, was impossible.
    const branch = panel.split("{linkOn ? (")[1] ?? "";
    expect(branch).toContain("COMPANION_STOP_LINK_ACTION");
    // The pairing control sits outside that branch entirely.
    const afterBranch = panel.split("{!offer && (")[1] ?? "";
    expect(afterBranch).toContain("COMPANION_PAIR_ACTION");
    expect(panel).not.toContain("status?.enabled ? (");
  });

  it("hides, rather than disables, a control that cannot work in a state", () => {
    // No authorized phone means the desktop refuses to start the listener, so
    // the control is not shown and a sentence says why.
    expect(panel).toContain("!linkOn && !offer && hasAuthorizedDevice");
    expect(panel).toContain("!linkOn && !offer && !hasAuthorizedDevice");
    expect(panel).toContain("is not shown because no phone is");
  });
});

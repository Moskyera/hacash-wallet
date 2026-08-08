/**
 * Where the state-critical controls are, not merely that they exist.
 *
 * The regression these tests exist to stop, measured on the running desktop at
 * a 760px viewport:
 *
 *   Pair a phone                      y=657    above the fold
 *   Turn on the phone connection      above the fold
 *   Start the AI agent connector      y=1305   BURIED
 *
 * The previous pass had a test for every one of those controls. All of them
 * passed, because all of them only asserted that the control existed somewhere.
 * Existence is not placement, so every assertion below is about position: which
 * region renders the control, and whether that region is on the first screen.
 */
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import {
  DESKTOP_CONTROLS,
  type DesktopControlId,
} from "./desktopControls";
import {
  ABOVE_THE_FOLD_PANELS,
  aboveTheFoldBlocks,
  overviewAlerts,
  overviewBlockOrder,
  regionIsAboveTheFold,
  stateCriticalControls,
  STATE_CRITICAL_CONTROL_REGION,
  STRIP_PRESSABLE_CONTROLS,
  type ConnectorState,
  type NodeState,
  type OverviewStateInput,
  type PhoneLinkState,
} from "./overviewLayout";

/* -------------------------------------------------------------------------- */
/* The states                                                                  */
/* -------------------------------------------------------------------------- */

const PHONE_STATES: PhoneLinkState[] = [
  "unknown",
  "on",
  "off",
  // The listener slot is held and its server is dead. Reported as enabled:true
  // by the backend, so it used to be indistinguishable from a healthy "on".
  "failed",
  "pairing",
  "other_wallet",
];
const CONNECTOR_STATES: ConnectorState[] = [
  "running",
  "starting",
  "stopping",
  "stopped",
  "failed",
  "other_wallet",
];
const NODE_STATES: NodeState[] = [
  "verified",
  "unchecked",
  "offline",
  "network_mismatch",
  "capability_mismatch",
  "balance_error",
  "stale",
];

const base = (overrides: Partial<OverviewStateInput> = {}): OverviewStateInput => ({
  paymentsSuspended: false,
  clearStopBlocked: false,
  clearStopReason: "",
  phone: "on",
  hasAuthorizedPhone: true,
  phoneAddressReady: true,
  pairingBlocked: false,
  connector: "running",
  node: "verified",
  ...overrides,
});

/** Every reachable Overview state. */
function everyState(): OverviewStateInput[] {
  const states: OverviewStateInput[] = [];
  for (const phone of PHONE_STATES) {
    for (const connector of CONNECTOR_STATES) {
      for (const node of NODE_STATES) {
        for (const paymentsSuspended of [false, true]) {
          for (const hasAuthorizedPhone of [false, true]) {
            for (const phoneAddressReady of [false, true]) {
              for (const clearStopBlocked of [false, true]) {
                states.push(
                  base({
                    phone,
                    connector,
                    node,
                    paymentsSuspended,
                    hasAuthorizedPhone,
                    phoneAddressReady,
                    clearStopBlocked,
                    clearStopReason: clearStopBlocked
                      ? "An unresolved signed operation must be recovered."
                      : "",
                    pairingBlocked: paymentsSuspended,
                  }),
                );
              }
            }
          }
        }
      }
    }
  }
  return states;
}

function describeState(state: OverviewStateInput): string {
  return `phone=${state.phone} connector=${state.connector} node=${state.node} stop=${state.paymentsSuspended}`;
}

/* -------------------------------------------------------------------------- */
/* Placement, as a rule over every state                                       */
/* -------------------------------------------------------------------------- */

describe("every control a state depends on is on the first screen", () => {
  it("puts each state-critical control in the strip or in an above-the-fold block", () => {
    for (const state of everyState()) {
      const order = overviewBlockOrder(state);
      for (const { control, region } of stateCriticalControls(state)) {
        const inStrip = STRIP_PRESSABLE_CONTROLS.includes(control);
        const inFirstScreen = regionIsAboveTheFold(region, order);
        expect(
          inStrip || inFirstScreen,
          `${DESKTOP_CONTROLS[control]} is what ${describeState(state)} depends on, and it renders in "${region}", which is block ${order.indexOf(
            region as never,
          )} of ${order.length}. It cannot be reached without scrolling.`,
        ).toBe(true);
      }
    }
  });

  it("hoists the connector block whenever the connector state depends on it", () => {
    // The measured fault. "Start the AI agent connector" sat at y=1305 because
    // only `failed` was hoisted, so the ordinary "it is off" state left the
    // panel that owns it three blocks down.
    for (const connector of ["stopped", "failed", "other_wallet"] as const) {
      const order = overviewBlockOrder({
        paymentsSuspended: false,
        phone: "on",
        connector,
      });
      expect(
        aboveTheFoldBlocks(order),
        `the connector panel is below the fold while the connector is ${connector}`,
      ).toContain("connector");
    }
  });

  it("leaves the connector block where it is while it is only mid-transition", () => {
    // Neither state has a control that changes it, so hoisting would be noise.
    for (const connector of ["running", "starting", "stopping"] as const) {
      const order = overviewBlockOrder({
        paymentsSuspended: false,
        phone: "on",
        connector,
      });
      expect(order.indexOf("connector")).toBeGreaterThan(
        order.indexOf("metrics"),
      );
    }
  });

  it("keeps the region table agreeing with what each state names", () => {
    for (const state of everyState()) {
      for (const { control, region } of stateCriticalControls(state)) {
        const table = STATE_CRITICAL_CONTROL_REGION[control];
        if (table === undefined) continue;
        expect(
          region,
          `${DESKTOP_CONTROLS[control]} is claimed by two different regions`,
        ).toBe(table);
      }
    }
  });

  it("never treats a control the state would refuse as the way out of it", () => {
    for (const state of everyState()) {
      const named = stateCriticalControls(state).map((entry) => entry.control);
      if (!state.hasAuthorizedPhone || state.phone !== "off") {
        expect(named).not.toContain("turn_on_phone_connection");
      }
      // CompanionSupervisor::start refuses while a dead slot is still held
      // ("stop the active mobile companion before starting another"), so
      // turning it on is not a way out of a failed listener. Releasing it is.
      if (state.phone === "failed") {
        expect(named).not.toContain("turn_on_phone_connection");
        expect(named).toContain("turn_off_phone_connection");
      }
      if (state.pairingBlocked || state.phone !== "off") {
        expect(named).not.toContain("pair_a_phone");
      }
      if (!state.phoneAddressReady) {
        expect(named).not.toContain("turn_on_phone_connection");
        expect(named).not.toContain("pair_a_phone");
      }
      if (state.clearStopBlocked) {
        expect(named).not.toContain("enable_payments_locally");
      }
      if (
        state.node === "network_mismatch" ||
        state.node === "capability_mismatch"
      ) {
        expect(named).not.toContain("refresh");
      }
    }
  });

  it("says nothing is critical when the wallet is healthy", () => {
    expect(stateCriticalControls(base())).toEqual([]);
  });
});

describe("the attention strip presses, it does not point downwards", () => {
  it("can press every control any attention line names", () => {
    for (const state of everyState()) {
      for (const alert of overviewAlerts(state)) {
        if (!alert.action) continue;
        expect(
          STRIP_PRESSABLE_CONTROLS,
          `the strip names ${alert.action.label} but cannot press it, so the line only points further down the page`,
        ).toContain(alert.action.control);
      }
    }
  });

  it("is always the first block, in every state", () => {
    for (const state of everyState()) {
      expect(overviewBlockOrder(state)[0]).toBe("alerts");
    }
  });

  it("counts the strip plus one panel as the first screen at 760px", () => {
    // Measured: the page head, the boundary banner and the strip fill the top
    // of a 760px viewport and one panel fits under them.
    expect(ABOVE_THE_FOLD_PANELS).toBe(1);
    expect(
      aboveTheFoldBlocks([
        "alerts",
        "phone",
        "connector",
        "metrics",
      ]),
    ).toEqual(["alerts", "phone"]);
  });
});

/* -------------------------------------------------------------------------- */
/* Placement, as a rule over the rendered sources                              */
/* -------------------------------------------------------------------------- */

const readRaw = (name: string) =>
  readFileSync(new URL(`./${name}`, import.meta.url), "utf8");

/** Comments removed: a label named only in a comment is not rendered. */
const read = (name: string) =>
  readRaw(name)
    .replace(/\/\*[\s\S]*?\*\//g, " ")
    .replace(/^[ \t]*\/\/.*$/gm, " ");

const APP = read("AgentWalletApp.tsx");
const PANEL = read("MobileCompanionPanel.tsx");

/** The body of a top-level function component, by name. */
function component(source: string, name: string): string {
  const start = source.indexOf(`function ${name}(`);
  expect(start, `${name} was not found`).toBeGreaterThanOrEqual(0);
  const next = source.indexOf("\nfunction ", start + 1);
  return source.slice(start, next === -1 ? source.length : next);
}

/** Where a needle sits inside a slice, as a position that must be ordered. */
function at(source: string, needle: string): number {
  const index = source.indexOf(needle);
  expect(index, `${needle} was not found`).toBeGreaterThanOrEqual(0);
  return index;
}

describe("the sources put those controls where the model says they are", () => {
  it("renders the attention strip as the first Overview block", () => {
    const content = component(APP, "AgentPageContent");
    // The block list decides the order, and the strip is its first case.
    expect(content).toContain("const order = overviewBlockOrder({");
    expect(content).toContain("{order.map((id) => block(id))}");
    expect(content).toContain('case "alerts":');
    expect(at(content, 'case "alerts":')).toBeLessThan(
      at(content, 'case "metrics":'),
    );
    expect(
      content.slice(at(content, 'case "alerts":'), at(content, 'case "metrics":')),
    ).toContain("<OverviewAlerts");
  });

  it("gives the strip a real button for every control it may press", () => {
    const content = component(APP, "AgentPageContent");
    const start = at(content, "const alertHandlers");
    const handlers = content.slice(start, content.indexOf("\n  };", start));
    for (const control of STRIP_PRESSABLE_CONTROLS) {
      expect(
        handlers,
        `${DESKTOP_CONTROLS[control]} has no handler in the strip, so the row renders no button`,
      ).toContain(`${control}:`);
    }
  });

  it("renders the strip's action as a button, not as a sentence", () => {
    const strip = component(APP, "OverviewAlerts");
    expect(strip).toContain('className="agent-alert-strip"');
    const button = at(strip, "<button");
    const label = at(strip, "{alert.action.label}");
    expect(label).toBeGreaterThan(button);
    expect(strip.slice(button, label)).not.toContain("</button>");
  });

  it("keeps the connector's own control above everything that explains it", () => {
    const panel = component(APP, "ConnectorPanel");
    const controlRow = at(panel, '<div className="agent-control-row">');
    const start = at(panel, "DESKTOP_CONTROLS.start_connector");
    const clear = at(panel, "DESKTOP_CONTROLS.clear_failed_connector");
    const explanation = at(panel, '<p className="agent-muted">');
    const disclosure = at(panel, "<details");
    for (const control of [start, clear]) {
      expect(control).toBeGreaterThan(controlRow);
      expect(control).toBeLessThan(explanation);
      expect(control).toBeLessThan(disclosure);
    }
  });

  it("keeps every phone control inside the panel's first region", () => {
    // The panel's own comment: "The action first. Everything that explains it
    // is below it or behind a disclosure."
    const primary = at(PANEL, '<div className="agent-companion-primary">');
    const devices = at(PANEL, '<div className="agent-companion-devices">');
    expect(devices).toBeGreaterThan(primary);
    const inPrimary: Array<[string, string]> = [
      ["turn_on_phone_connection", "COMPANION_START_LINK_ACTION"],
      ["turn_off_phone_connection", "COMPANION_STOP_LINK_ACTION"],
      ["pair_a_phone", "COMPANION_PAIR_ACTION"],
      ["retry_automatic_setup", "DESKTOP_CONTROLS.retry_automatic_setup"],
      ["cancel_phone_pairing", "DESKTOP_CONTROLS.cancel_phone_pairing"],
    ];
    for (const [id, token] of inPrimary) {
      const index = at(PANEL, `{${token}}`);
      expect(
        index,
        `${DESKTOP_CONTROLS[id as DesktopControlId]} is rendered below the panel's first region`,
      ).toBeGreaterThan(primary);
      expect(index).toBeLessThan(devices);
      // And not folded away inside a disclosure, which is the same fault as
      // being below the fold: the control is on screen and cannot be seen.
      const before = PANEL.slice(0, index);
      expect(
        before.split("<details").length - before.split("</details>").length,
        `${DESKTOP_CONTROLS[id as DesktopControlId]} is inside a collapsed disclosure`,
      ).toBe(0);
    }
  });

  it("presses the panel's own handler for the setup retry, rather than a copy", () => {
    const content = component(APP, "AgentPageContent");
    expect(content).toContain(
      "companionActions.current.retryAutomaticSetup?.()",
    );
    // One implementation, in the panel, shared with the strip.
    expect(PANEL).toContain("const retryAutomaticSetup = useCallback(");
    expect(PANEL).toContain("onClick={retryAutomaticSetup}");
    expect(PANEL).toContain(
      "retryAutomaticSetup: canRetryAutomaticSetup ? retryAutomaticSetup : null,",
    );
  });
});

import { describe, expect, it } from "vitest";
import {
  DESKTOP_CONTROLS,
  desktopControlLabels,
  isDesktopControlLabel,
} from "./desktopControls";
import {
  CLEAR_STOP_CANCELS_PENDING_REQUESTS,
  PHONE_CONNECTION_REFUSED_WHILE_STOPPED,
  PHONE_LISTENER_FAILED_ROUTE,
  STRIP_PRESSABLE_CONTROLS,
  aboveTheFoldBlocks,
  nodeAlertState,
  overviewAlerts,
  overviewBlockOrder,
  phoneLinkState,
  type ConnectorState,
  type NodeState,
  type OverviewStateInput,
  type PhoneLinkState,
} from "./overviewLayout";

const healthy = (
  overrides: Partial<OverviewStateInput> = {},
): OverviewStateInput => ({
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

const PHONE_STATES: PhoneLinkState[] = [
  "unknown",
  "on",
  "off",
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

/** Every reachable Overview state, for the exhaustive sweeps below. */
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
                  healthy({
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

describe("the phone connection control is reachable without scrolling", () => {
  // The measured fault: "Turn on the phone connection" sat at y=2101 in a 760px
  // viewport. It is the one control the whole phone connection depends on.
  it("puts the phone panel first when the connection is off", () => {
    const order = overviewBlockOrder({
      paymentsSuspended: false,
      phone: "off",
      connector: "running",
    });
    expect(order[0]).toBe("alerts");
    expect(order[1]).toBe("phone");
  });

  it("keeps the phone panel above every reference block in every off state", () => {
    const reference = [
      "metrics",
      "node_health",
      "payment_blockers",
      "authorization",
    ] as const;
    for (const phone of PHONE_STATES) {
      if (phone === "on") continue;
      for (const connector of CONNECTOR_STATES) {
        for (const paymentsSuspended of [false, true]) {
          const order = overviewBlockOrder({ paymentsSuspended, phone, connector });
          const phoneIndex = order.indexOf("phone");
          expect(phoneIndex).toBeGreaterThan(-1);
          // Two blocks at most can precede it, and both are one-line panels.
          expect(phoneIndex).toBeLessThanOrEqual(2);
          for (const block of reference) {
            expect(phoneIndex).toBeLessThan(order.indexOf(block));
          }
        }
      }
    }
  });

  it("hoists the emergency stop above the phone, because it also blocks pairing", () => {
    const order = overviewBlockOrder({
      paymentsSuspended: true,
      phone: "off",
      connector: "running",
    });
    expect(order.indexOf("payment_control")).toBe(1);
    expect(order.indexOf("payment_control")).toBeLessThan(order.indexOf("phone"));
  });

  it("does not hoist anything when the wallet is healthy", () => {
    expect(
      overviewBlockOrder({
        paymentsSuspended: false,
        phone: "on",
        connector: "running",
      }),
    ).toEqual([
      "alerts",
      "metrics",
      "phone",
      "connector",
      "payment_control",
      "node_health",
      "payment_blockers",
      "authorization",
    ]);
  });

  it("renders every block exactly once in every state", () => {
    for (const state of everyState()) {
      const order = overviewBlockOrder(state);
      expect(new Set(order).size).toBe(order.length);
      expect(order).toHaveLength(8);
      expect(order[0]).toBe("alerts");
    }
  });
});

describe("no instruction names a control that does not exist", () => {
  it("only ever names a label from the control table", () => {
    for (const state of everyState()) {
      for (const alert of overviewAlerts(state)) {
        if (!alert.action) continue;
        expect(isDesktopControlLabel(alert.action.label)).toBe(true);
        expect(alert.action.label).toBe(
          DESKTOP_CONTROLS[alert.action.control],
        );
      }
    }
  });

  it("never names a control that the current state would refuse", () => {
    for (const state of everyState()) {
      const labels = overviewAlerts(state)
        .map((alert) => alert.action?.label)
        .filter((label): label is string => Boolean(label));

      // Rust refuses starting the listener with no authorized phone, and
      // refuses it again while a pairing owns the private-LAN port.
      if (!state.hasAuthorizedPhone || state.phone !== "off") {
        expect(labels).not.toContain(DESKTOP_CONTROLS.turn_on_phone_connection);
      }
      // Pairing is refused while a live blocker applies.
      if (state.pairingBlocked || state.phone !== "off") {
        expect(labels).not.toContain(DESKTOP_CONTROLS.pair_a_phone);
      }
      // Neither phone control can run without a private Wi-Fi address.
      if (!state.phoneAddressReady) {
        expect(labels).not.toContain(DESKTOP_CONTROLS.turn_on_phone_connection);
        expect(labels).not.toContain(DESKTOP_CONTROLS.pair_a_phone);
      }
      // A disabled Enable locally must not be named as the way out.
      if (state.clearStopBlocked) {
        expect(labels).not.toContain(DESKTOP_CONTROLS.enable_payments_locally);
      }
      // Refresh re-asks the same node, which is not the remedy for a wallet
      // pointed at the wrong chain.
      if (state.node === "network_mismatch" || state.node === "capability_mismatch") {
        expect(labels).not.toContain(DESKTOP_CONTROLS.refresh);
      }
    }
  });

  it("gives a state with no usable control an explanation instead of a button", () => {
    for (const state of everyState()) {
      for (const alert of overviewAlerts(state)) {
        if (alert.action) continue;
        expect(alert.detail.length).toBeGreaterThan(20);
      }
    }
  });

  it("carries a short status line and a longer explanation on every row", () => {
    for (const state of everyState()) {
      for (const alert of overviewAlerts(state)) {
        expect(alert.status.length).toBeGreaterThan(0);
        // Short and plain at rest; the detail is behind "Why?".
        expect(alert.status.split(" ").length).toBeLessThanOrEqual(10);
        expect(alert.detail.length).toBeGreaterThan(alert.status.length);
      }
    }
  });
});

describe("one primary action per screen", () => {
  it("marks at most one row primary, and only a row that has a control", () => {
    for (const state of everyState()) {
      const alerts = overviewAlerts(state);
      const primaries = alerts.filter((alert) => alert.primary);
      expect(primaries.length).toBeLessThanOrEqual(1);
      for (const primary of primaries) expect(primary.action).not.toBeNull();
    }
  });

  it("makes the first actionable row the primary one", () => {
    for (const state of everyState()) {
      const alerts = overviewAlerts(state);
      const firstActionable = alerts.findIndex((alert) => alert.action !== null);
      if (firstActionable === -1) {
        expect(alerts.some((alert) => alert.primary)).toBe(false);
      } else {
        expect(alerts[firstActionable].primary).toBe(true);
      }
    }
  });

  it("says nothing at all when the wallet is healthy", () => {
    expect(overviewAlerts(healthy())).toEqual([]);
  });
});

describe("the attention lines answer the states the owner can reach", () => {
  it("offers turning the connection on when a phone is paired and it is off", () => {
    const alerts = overviewAlerts(
      healthy({ phone: "off", hasAuthorizedPhone: true }),
    );
    expect(alerts[0].action?.label).toBe(
      DESKTOP_CONTROLS.turn_on_phone_connection,
    );
    expect(alerts[0].primary).toBe(true);
  });

  it("offers pairing when no phone is set up", () => {
    const alerts = overviewAlerts(
      healthy({ phone: "off", hasAuthorizedPhone: false }),
    );
    expect(alerts[0].action?.label).toBe(DESKTOP_CONTROLS.pair_a_phone);
  });

  it("offers no phone control while a pairing owns the connection", () => {
    const alerts = overviewAlerts(healthy({ phone: "pairing" }));
    expect(alerts[0].id).toBe("phone");
    expect(alerts[0].action).toBeNull();
    expect(alerts[0].detail).toContain(DESKTOP_CONTROLS.cancel_phone_pairing);
  });

  it("offers the wallet switch when another Agent Wallet holds the phone", () => {
    const alerts = overviewAlerts(healthy({ phone: "other_wallet" }));
    expect(alerts[0].action?.label).toBe(
      DESKTOP_CONTROLS.lock_and_switch_wallet,
    );
  });

  it("names Enable locally as the only way out of an emergency stop", () => {
    const alerts = overviewAlerts(
      healthy({ paymentsSuspended: true, pairingBlocked: true, phone: "off" }),
    );
    expect(alerts[0].id).toBe("payments");
    expect(alerts[0].action?.label).toBe(
      DESKTOP_CONTROLS.enable_payments_locally,
    );
    expect(alerts[0].primary).toBe(true);
  });

  it("explains rather than instructs when the stop cannot be cleared", () => {
    const alerts = overviewAlerts(
      healthy({
        paymentsSuspended: true,
        clearStopBlocked: true,
        clearStopReason: "An unresolved signed operation requires recovery.",
      }),
    );
    expect(alerts[0].action).toBeNull();
    expect(alerts[0].detail).toBe(
      "An unresolved signed operation requires recovery.",
    );
  });

  it("relabels the failed connector as what the click actually does", () => {
    const alerts = overviewAlerts(healthy({ connector: "failed" }));
    expect(alerts[0].action?.label).toBe(
      DESKTOP_CONTROLS.clear_failed_connector,
    );
    expect(desktopControlLabels()).not.toContain(
      "Restart the AI agent connector",
    );
  });
});

describe("derivations the panels share", () => {
  it("reports another wallet's listener before anything else", () => {
    expect(
      phoneLinkState({
        statusLoaded: true,
        belongsToAnotherWallet: true,
        enabled: false,
        listenerFailed: false,
        pairingActive: false,
      }),
    ).toBe("other_wallet");
  });

  it("reports a live pairing as owning the connection", () => {
    expect(
      phoneLinkState({
        statusLoaded: true,
        belongsToAnotherWallet: false,
        enabled: true,
        listenerFailed: false,
        pairingActive: true,
      }),
    ).toBe("pairing");
  });

  it("never guesses before the status has been read", () => {
    expect(
      phoneLinkState({
        statusLoaded: false,
        belongsToAnotherWallet: false,
        enabled: false,
        listenerFailed: false,
        pairingActive: false,
      }),
    ).toBe("unknown");
  });

  // agent_wallet_companion_status reports "enabled": true for every phase,
  // including the one where the slot is held and its server is dead. Reading
  // enabled alone made Overview report a healthy phone connection while every
  // phone was being refused, and dropped the phone row from the alert strip.
  it("never reports a dead listener as an on connection", () => {
    expect(
      phoneLinkState({
        statusLoaded: true,
        belongsToAnotherWallet: false,
        enabled: true,
        listenerFailed: true,
        pairingActive: false,
      }),
    ).toBe("failed");
  });

  it("treats stale balance data as a node problem", () => {
    expect(nodeAlertState({ nodeStatus: "verified", stale: true })).toBe("stale");
    expect(nodeAlertState({ nodeStatus: "offline", stale: false })).toBe("offline");
    expect(nodeAlertState({ nodeStatus: "verified", stale: false })).toBe("verified");
  });
});


/* -------------------------------------------------------------------------- */
/* Closures pinned by the condition that makes them true                       */
/* -------------------------------------------------------------------------- */

describe("a dead phone listener is reported, and only its way out is named", () => {
  const failed = healthy({ phone: "failed" });

  it("raises a phone row instead of reporting nothing at all", () => {
    // phoneAlert returned [] for "on", and a failed listener read as "on", so
    // Overview showed no phone problem while every phone was refused.
    const row = overviewAlerts(failed).find((alert) => alert.id === "phone");
    expect(row).toBeDefined();
    expect(row?.tone).toBe("warning");
    expect(row?.status).toContain("failed");
  });

  it("names the two presses that work, in the order that works", () => {
    const row = overviewAlerts(failed).find((alert) => alert.id === "phone");
    expect(row?.detail).toBe(PHONE_LISTENER_FAILED_ROUTE);
    const off = row!.detail.indexOf(DESKTOP_CONTROLS.turn_off_phone_connection);
    const on = row!.detail.indexOf(DESKTOP_CONTROLS.turn_on_phone_connection);
    expect(off).toBeGreaterThanOrEqual(0);
    expect(on).toBeGreaterThan(off);
  });

  it("offers the one press that can succeed, and never the one that cannot", () => {
    // Start is refused while the dead slot is held, so the strip must press
    // the control that releases it rather than the one that would throw.
    const row = overviewAlerts(failed).find((alert) => alert.id === "phone");
    expect(row?.action?.control).toBe("turn_off_phone_connection");
    expect(row?.action?.label).toBe(
      DESKTOP_CONTROLS.turn_off_phone_connection,
    );
    expect(STRIP_PRESSABLE_CONTROLS).toContain("turn_off_phone_connection");
  });

  it("hoists the panel that owns both presses onto the first screen", () => {
    const order = overviewBlockOrder({
      paymentsSuspended: false,
      phone: "failed",
      connector: "running",
    });
    expect(aboveTheFoldBlocks(order)).toContain("phone");
  });
});

describe("clearing the emergency stop says what it destroys", () => {
  it("carries the cancellation warning on the row that recommends it", () => {
    // enable_agent_payments_locally cancels every pending pre-signing operation
    // on the wallet, scope None. The strip recommends this control as the
    // primary action while describing it as changing nothing but a flag.
    const row = overviewAlerts(
      healthy({ paymentsSuspended: true, pairingBlocked: true }),
    ).find((alert) => alert.id === "payments");
    expect(row?.action?.control).toBe("enable_payments_locally");
    expect(row?.primary).toBe(true);
    expect(row?.detail).toContain(CLEAR_STOP_CANCELS_PENDING_REQUESTS);
  });

  it("drops both the action and the claim when the control is refused", () => {
    const row = overviewAlerts(
      healthy({
        paymentsSuspended: true,
        clearStopBlocked: true,
        clearStopReason: "An unresolved signed operation must be recovered.",
        pairingBlocked: true,
      }),
    ).find((alert) => alert.id === "payments");
    expect(row?.action).toBeNull();
    expect(row?.detail).not.toContain(CLEAR_STOP_CANCELS_PENDING_REQUESTS);
  });
});

describe("turning the phone connection on while the stop is engaged", () => {
  const suspended = healthy({
    phone: "off",
    hasAuthorizedPhone: true,
    phoneAddressReady: true,
    paymentsSuspended: true,
    pairingBlocked: true,
  });

  it("still offers the control, because the listener really does start", () => {
    // agent_wallet_companion_start is not gated on the stop. Disabling the
    // button would be a new refusal, which this pass must not add.
    const row = overviewAlerts(suspended).find((alert) => alert.id === "phone");
    expect(row?.action?.control).toBe("turn_on_phone_connection");
  });

  it("stops claiming a phone can then reach this desktop", () => {
    // issue_connectivity_permit fails closed while payments are suspended, so
    // every session the phone opens is refused. The detail asserted otherwise.
    const row = overviewAlerts(suspended).find((alert) => alert.id === "phone");
    expect(row?.detail).toContain(PHONE_CONNECTION_REFUSED_WHILE_STOPPED);
    expect(row?.detail).toContain(DESKTOP_CONTROLS.enable_payments_locally);

    const running = overviewAlerts(
      healthy({ phone: "off", hasAuthorizedPhone: true, phoneAddressReady: true }),
    ).find((alert) => alert.id === "phone");
    expect(running?.detail).not.toContain(PHONE_CONNECTION_REFUSED_WHILE_STOPPED);
  });
});

describe("a pinned capability failure is not a wrong chain", () => {
  it("gives it its own line", () => {
    const capability = overviewAlerts(healthy({ node: "capability_mismatch" })).find(
      (alert) => alert.id === "node",
    );
    const network = overviewAlerts(healthy({ node: "network_mismatch" })).find(
      (alert) => alert.id === "node",
    );
    expect(capability?.status).not.toBe(network?.status);
    expect(capability?.detail).not.toBe(network?.detail);
    // The retired claim: capability_mismatch is a pinned-capability-contract
    // failure, not a chain identity failure.
    expect(capability?.status).not.toContain("not this wallet's chain");
    expect(capability?.detail).toContain("This is not a wrong chain");
    // Neither names Refresh: re-asking the same node fails the same way.
    expect(capability?.action).toBeNull();
    expect(network?.action).toBeNull();
  });
});

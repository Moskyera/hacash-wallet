/**
 * Where the Overview blocks go, and what the short line at the top says.
 *
 * The measured fault this fixes: "Turn on the phone connection" sat at y=2101 in
 * a 760px viewport, 2.8 screens below the fold, and it is the single control the
 * entire phone connection depends on. Nothing else on that screen works without
 * it. The fix is ordering, not new behaviour: the block that owns the control
 * the current state depends on is rendered first.
 *
 * This module decides what to SAY and WHERE TO PUT IT. It performs no work, has
 * no side effects, calls nothing and gates nothing. Every action it names is an
 * existing control from `DESKTOP_CONTROLS`, and it names one only when pressing
 * that control genuinely resolves the state the line describes.
 */
import { DESKTOP_CONTROLS, type DesktopControlId } from "./desktopControls";

/** What this desktop's phone connection is doing right now. */
export type PhoneLinkState =
  /** The companion status has not been read yet. */
  | "unknown"
  /** This desktop is accepting phone connections. */
  | "on"
  /** This desktop is not accepting phone connections. */
  | "off"
  /** A pairing owns the private-LAN port. The wizard below is the only route. */
  | "pairing"
  /** The active listener belongs to a different Agent Wallet. */
  | "other_wallet";

export type ConnectorState =
  | "running"
  | "starting"
  | "stopping"
  | "stopped"
  | "failed"
  /** The running connector belongs to a different Agent Wallet. */
  | "other_wallet";

export type NodeState =
  | "verified"
  | "unchecked"
  | "offline"
  | "network_mismatch"
  | "capability_mismatch"
  | "balance_error"
  | "stale";

export type OverviewStateInput = {
  paymentsSuspended: boolean;
  /** True when the control that clears the stop is itself unavailable. */
  clearStopBlocked: boolean;
  /** Why it is unavailable, already written by `emergencyStopControl`. */
  clearStopReason: string;
  phone: PhoneLinkState;
  /** At least one phone is paired and not revoked. */
  hasAuthorizedPhone: boolean;
  /** This desktop knows the private Wi-Fi address it would listen on. */
  phoneAddressReady: boolean;
  /** A live refusal genuinely stops a phone being paired right now. */
  pairingBlocked: boolean;
  connector: ConnectorState;
  node: NodeState;
};

/* -------------------------------------------------------------------------- */
/* Block order                                                                 */
/* -------------------------------------------------------------------------- */

export type OverviewBlockId =
  /** The short attention lines. Always first, usually empty. */
  | "alerts"
  /** Balance tiles. One compact row. */
  | "metrics"
  /** MobileCompanionPanel: the phone connection and the pairing wizard. */
  | "phone"
  /** The local AI agent connector and its pairing. */
  | "connector"
  /** The emergency stop and the one control that clears it. */
  | "payment_control"
  /** The Local Pilot health rows. Three at rest, the rest collapsed. */
  | "node_health"
  /** Why the agent cannot pay. One line at rest. */
  | "payment_blockers"
  /** Agent and approval counts. */
  | "authorization";

/**
 * The resting order, used when nothing needs attention.
 *
 * The phone sits directly under the compact balance row because it is what an
 * owner touches most and what they could not find. Everything reference-shaped
 * sits below it.
 */
const RESTING_ORDER: readonly OverviewBlockId[] = [
  "alerts",
  "metrics",
  "phone",
  "connector",
  "payment_control",
  "node_health",
  "payment_blockers",
  "authorization",
];

/**
 * The Overview blocks, top first.
 *
 * A block is hoisted when the current state DEPENDS on a control it owns:
 *  - the emergency stop, because "Enable locally" is the only control that
 *    clears it and clearing it is also what unblocks pairing a phone;
 *  - the phone panel, whenever the connection is not on, because it owns both
 *    "Pair a phone" and "Turn on the phone connection";
 *  - the connector, when it has failed, because it owns the control that clears
 *    the failure.
 */
export function overviewBlockOrder(
  input: Pick<OverviewStateInput, "paymentsSuspended" | "phone" | "connector">,
): OverviewBlockId[] {
  const hoisted: OverviewBlockId[] = [];
  if (input.paymentsSuspended) hoisted.push("payment_control");
  if (input.phone !== "on") hoisted.push("phone");
  if (input.connector === "failed") hoisted.push("connector");

  const order: OverviewBlockId[] = ["alerts", ...hoisted];
  for (const block of RESTING_ORDER) {
    if (!order.includes(block)) order.push(block);
  }
  return order;
}

/* -------------------------------------------------------------------------- */
/* The attention lines                                                         */
/* -------------------------------------------------------------------------- */

export type OverviewAlertId = "payments" | "phone" | "node" | "connector";

export type OverviewAlertAction = {
  control: DesktopControlId;
  /** The exact rendered label. Never a paraphrase. */
  label: string;
};

export type OverviewAlert = {
  id: OverviewAlertId;
  /** Short and plain. This is all that shows at rest. */
  status: string;
  /**
   * The one control that resolves this state, or null when no control can.
   * Null is a statement, not a gap: the detail then says why.
   */
  action: OverviewAlertAction | null;
  /** The longer explanation, shown behind "Why?". */
  detail: string;
  /** Exactly one row per screen carries the primary weight. */
  primary: boolean;
  tone: "warning" | "info";
};

function action(control: DesktopControlId): OverviewAlertAction {
  return { control, label: DESKTOP_CONTROLS[control] };
}

/**
 * The short lines at the top of Overview, most urgent first.
 *
 * Returns [] when nothing needs the owner. That is the point: at rest this
 * strip is empty and the screen is quiet.
 */
export function overviewAlerts(input: OverviewStateInput): OverviewAlert[] {
  const rows: OverviewAlert[] = [];

  if (input.paymentsSuspended) {
    rows.push({
      id: "payments",
      status: "Agent payments are off.",
      // Naming "Enable locally" while it is disabled would be an instruction
      // that cannot be followed, which is the exact fault this pass removes.
      action: input.clearStopBlocked
        ? null
        : action("enable_payments_locally"),
      detail: input.clearStopBlocked
        ? input.clearStopReason
        : "The emergency stop is on. It also stops phones connecting and stops new phones being paired. Enable locally clears it. It approves no payment: every payment still needs your decision.",
      primary: false,
      tone: "warning",
    });
  }

  rows.push(...phoneAlert(input));

  if (
    input.node === "offline" ||
    input.node === "balance_error" ||
    input.node === "stale"
  ) {
    rows.push({
      id: "node",
      status:
        input.node === "offline"
          ? "The Local Pilot node is not answering."
          : "The balance could not be read.",
      action: action("refresh"),
      detail:
        "No balance was read and no payment was attempted. Refresh asks the node again. Until it answers, the agent cannot pay.",
      primary: false,
      tone: "warning",
    });
  } else if (
    input.node === "network_mismatch" ||
    input.node === "capability_mismatch"
  ) {
    rows.push({
      id: "node",
      status: "This node is not this wallet's chain.",
      // Refresh re-asks the same node and will fail the same way. There is no
      // control in this build that repoints a wallet, so none is named.
      action: null,
      detail:
        "Balance, transaction building, signing and broadcasting are blocked. The node this wallet points at was fixed when the wallet was created and cannot be changed here. Start the Local Pilot node this wallet was created against.",
      primary: false,
      tone: "warning",
    });
  }

  if (input.connector === "failed") {
    rows.push({
      id: "connector",
      status: "The AI agent connector failed to start.",
      action: action("clear_failed_connector"),
      detail:
        "AI agent software on this computer cannot connect. Clearing the failure stops the connector; the start control appears once it is clear. This is not the phone connection.",
      primary: false,
      tone: "warning",
    });
  } else if (input.connector === "stopped") {
    rows.push({
      id: "connector",
      status: "AI agent connector is off.",
      action: action("start_connector"),
      detail:
        "AI agent software running on this computer cannot connect while it is off. Starting it costs nothing and moves no money. This is not the phone connection.",
      primary: false,
      tone: "info",
    });
  } else if (input.connector === "other_wallet") {
    rows.push({
      id: "connector",
      status: "The running connector belongs to another Agent Wallet.",
      action: action("lock_and_switch_wallet"),
      detail:
        "This wallet cannot manage a connector another Agent Wallet is running. Locking this wallet returns to the unlock screen, where you can choose the other Agent Wallet.",
      primary: false,
      tone: "warning",
    });
  }

  const first = rows.find((row) => row.action !== null);
  return rows.map((row) => (row === first ? { ...row, primary: true } : row));
}

function phoneAlert(input: OverviewStateInput): OverviewAlert[] {
  if (input.phone === "on" || input.phone === "unknown") return [];

  if (input.phone === "other_wallet") {
    return [
      {
        id: "phone",
        status: "The phone connection belongs to another Agent Wallet.",
        action: action("lock_and_switch_wallet"),
        detail:
          "One Agent Wallet at a time can hold the phone connection. Locking this wallet returns to the unlock screen, where you can choose the Agent Wallet that holds it.",
        primary: false,
        tone: "warning",
      },
    ];
  }

  if (input.phone === "pairing") {
    return [
      {
        id: "phone",
        status: "Phone pairing is running.",
        // Pairing owns the private-LAN port, so the connection genuinely cannot
        // be turned on until the pairing finishes or is cancelled. Naming
        // "Turn on the phone connection" here would be refused by the desktop.
        action: null,
        detail:
          "Pairing holds the private Wi-Fi connection while it runs. Finish the steps in Pair your phone below, or choose Cancel pairing there. The connection comes back on when pairing ends.",
        primary: false,
        tone: "info",
      },
    ];
  }

  // The connection is off.
  if (!input.phoneAddressReady) {
    return [
      {
        id: "phone",
        status: "Your phone cannot reach this desktop.",
        // Neither phone control can run without a private Wi-Fi address, so
        // the control that finds one is the only honest thing to name.
        action: action("retry_automatic_setup"),
        detail:
          "This desktop does not know its own private Wi-Fi address yet, so it cannot open the phone connection or show a pairing QR code. Try automatic setup again is in Pair your phone below, next to Advanced connection settings.",
        primary: false,
        tone: "warning",
      },
    ];
  }

  if (input.hasAuthorizedPhone) {
    return [
      {
        id: "phone",
        status: "Your phone cannot reach this desktop.",
        action: action("turn_on_phone_connection"),
        detail:
          "A phone is paired but this desktop is not accepting connections. Turning it on costs nothing, moves no money and pairs nothing new: it opens the encrypted connection on your private Wi-Fi.",
        primary: false,
        tone: "warning",
      },
    ];
  }

  // No phone is authorized, so pairing is the only route, and pairing is what
  // the live refusal blocks. Naming a control that will be refused is exactly
  // the fault this pass exists to remove.
  if (input.pairingBlocked) {
    return [
      {
        id: "phone",
        status: "No phone is set up yet.",
        action: null,
        detail:
          "A phone cannot be paired while the reason above applies. Clear that first, then set the phone up in Pair your phone below.",
        primary: false,
        tone: "warning",
      },
    ];
  }

  return [
    {
      id: "phone",
      status: "No phone is set up yet.",
      action: action("pair_a_phone"),
      detail:
        "The phone is a read-only safety companion. It never receives a private key and cannot send Hacash transactions. Pairing costs nothing and shows a QR code that stops working after a few minutes.",
      primary: false,
      tone: "info",
    },
  ];
}

/* -------------------------------------------------------------------------- */
/* Small derivations the panels share                                          */
/* -------------------------------------------------------------------------- */

/** The phone link state, from the two facts the companion status carries. */
export function phoneLinkState(input: {
  statusLoaded: boolean;
  belongsToAnotherWallet: boolean;
  enabled: boolean;
  pairingActive: boolean;
}): PhoneLinkState {
  if (input.belongsToAnotherWallet) return "other_wallet";
  if (!input.statusLoaded) return "unknown";
  if (input.pairingActive) return "pairing";
  return input.enabled ? "on" : "off";
}

/** The node state used by the alert lines, including the stale-data case. */
export function nodeAlertState(input: {
  nodeStatus: NodeState;
  stale: boolean;
}): NodeState {
  if (input.nodeStatus !== "verified" && input.nodeStatus !== "unchecked") {
    return input.nodeStatus;
  }
  return input.stale ? "stale" : input.nodeStatus;
}

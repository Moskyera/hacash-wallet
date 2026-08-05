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
  /**
   * The listener slot is still held but its server is no longer running, so
   * every phone is refused. `agent_wallet_companion_status` reports
   * `"enabled": true` for this phase as it does for every other, which is why
   * this state has to be derived from the phase and not from that flag.
   */
  | "failed"
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
 *  - the connector, whenever it is not doing its job, because it owns the one
 *    control that changes that: "Start the AI agent connector" when it is off,
 *    "Clear the failed connector" when it failed, and the wallet switch when
 *    the running connector belongs to another Agent Wallet.
 *
 * The measured fault this last clause fixes: with the connector stopped,
 * "Start the AI agent connector" sat at y=1305 in a 760px viewport. It is the
 * control that connects the AI agent itself, and only `failed` was hoisted, so
 * the ordinary "it is off" state left it below the fold.
 */
export function overviewBlockOrder(
  input: Pick<OverviewStateInput, "paymentsSuspended" | "phone" | "connector">,
): OverviewBlockId[] {
  const hoisted: OverviewBlockId[] = [];
  if (input.paymentsSuspended) hoisted.push("payment_control");
  if (input.phone !== "on") hoisted.push("phone");
  if (connectorNeedsAttention(input.connector)) hoisted.push("connector");

  const order: OverviewBlockId[] = ["alerts", ...hoisted];
  for (const block of RESTING_ORDER) {
    if (!order.includes(block)) order.push(block);
  }
  return order;
}

/**
 * Whether the connector state depends on a control the connector block owns.
 *
 * "starting" and "stopping" are deliberately absent: both are transient, both
 * resolve themselves, and the panel offers no control that changes them.
 */
function connectorNeedsAttention(connector: ConnectorState): boolean {
  return (
    connector === "stopped" ||
    connector === "failed" ||
    connector === "other_wallet"
  );
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
 * What "Enable locally" actually destroys, said before it is pressed.
 *
 * `enable_agent_payments_locally` (crates/agent-wallet-core/src/service.rs)
 * calls `cancel_pre_signing_operations(&mut state, None, "policy_changed")`.
 * Scope `None` is every agent on the wallet, and the operation states it
 * covers include ApprovalRequested and Approved, so every payment request that
 * was waiting for a decision is cancelled and its reservation zeroed. Three
 * separate sentences described this control as one that "changes nothing but
 * the flag", which is the exact shape of an app-recommended action that
 * destroys the owner's work.
 */
export const CLEAR_STOP_CANCELS_PENDING_REQUESTS =
  "Clearing the stop also cancels every payment request that is waiting for your decision, on every agent on this wallet. Those requests are gone and each agent has to ask again.";

/**
 * What the phone connection can and cannot do while the stop is engaged.
 *
 * Turning the listener on is genuinely not gated
 * (crates/wallet-tauri-common/src/agent_commands.rs), so the button really
 * does open the port. Every session the phone then opens is refused, because
 * `issue_connectivity_permit` fails closed while payments are suspended
 * (crates/agent-wallet-core/src/service/companion/*). Saying only "a paired
 * phone can now reach this desktop" asserted the opposite of what happens.
 */
export const PHONE_CONNECTION_REFUSED_WHILE_STOPPED =
  "The emergency stop is on, so the connection opens but every session a phone tries to open is still refused. Clear the stop with Enable locally in Payment control to let a phone connect.";

/**
 * The failed-listener route back.
 *
 * `CompanionSupervisor::start` refuses while a slot is held
 * ("stop the active mobile companion before starting another"), so the only
 * way out is off then on. No sentence in the surface named it.
 */
/** Reported after the dead listener slot has actually been released. */
export const PHONE_LISTENER_RELEASED_INFO = `The failed phone connection was released. Choose ${DESKTOP_CONTROLS.turn_on_phone_connection} to open it again. Every paired phone stays paired and nothing was unpaired.`;

export const PHONE_LISTENER_FAILED_ROUTE = `The phone connection started and then stopped, so every phone is refused. Use ${DESKTOP_CONTROLS.turn_off_phone_connection} in Pair your phone below, then ${DESKTOP_CONTROLS.turn_on_phone_connection}. Neither costs anything, moves money or unpairs a phone.`;

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
        : `The emergency stop is on. It also stops phones connecting and stops new phones being paired. Enable locally clears it. It approves no payment: every payment still needs your decision. ${CLEAR_STOP_CANCELS_PENDING_REQUESTS}`,
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
  } else if (input.node === "network_mismatch") {
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
  } else if (input.node === "capability_mismatch") {
    // Not a wrong chain. `capability_mismatch` is a pinned-capability-contract
    // failure (crates/agent-wallet-core/src/error.rs), so the node may well be
    // the right one and simply not offer what this wallet pinned. Printing the
    // network-mismatch sentence for it named the wrong cause and sent owners
    // hunting for a chain problem that does not exist.
    rows.push({
      id: "node",
      status: "This node does not offer what this wallet pinned.",
      action: null,
      detail:
        "The node answered, but it does not provide the exact capability contract this wallet was created against, so balance, transaction building, signing and broadcasting are blocked. This is not a wrong chain. Run the Local Pilot node release this wallet was created against. The exact refusal is under Node details in Local Pilot health.",
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

  if (input.phone === "failed") {
    return [
      {
        id: "phone",
        status: "The phone connection failed and refuses every phone.",
        // Turning it on is refused while the dead slot is still held, so the
        // one control that can succeed here is the one that releases it.
        action: action("turn_off_phone_connection"),
        detail: PHONE_LISTENER_FAILED_ROUTE,
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
        detail: `This desktop does not know its own private Wi-Fi address yet, so it cannot open the phone connection or show a pairing QR code. ${DESKTOP_CONTROLS.retry_automatic_setup} is in Pair your phone below, above Advanced connection settings, and looks for the address again. If it keeps failing, open Advanced connection settings and type the address in.`,
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
        detail: input.paymentsSuspended
          ? `A phone is paired but this desktop is not accepting connections. Turning it on costs nothing, moves no money and pairs nothing new. ${PHONE_CONNECTION_REFUSED_WHILE_STOPPED}`
          : "A phone is paired but this desktop is not accepting connections. Turning it on costs nothing, moves no money and pairs nothing new: it opens the encrypted connection on your private Wi-Fi.",
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
/* Placement: which controls must be on the first screen, and where they are   */
/* -------------------------------------------------------------------------- */

/**
 * Where a control is rendered on Overview.
 *
 * "page_head" is the row that carries Copy address and Refresh. It is above
 * every block and is never scrolled past.
 */
export type OverviewRegion = OverviewBlockId | "page_head";

/**
 * How much of Overview a 760px viewport shows without scrolling.
 *
 * Measured, not assumed: the page head, the boundary banner and the attention
 * strip fill the top of the screen, and one panel fits under them. The second
 * panel begins below the fold, which is how "Start the AI agent connector"
 * came to sit at y=1305.
 */
export const ABOVE_THE_FOLD_PANELS = 1;

/**
 * The blocks a 760px viewport shows without scrolling.
 *
 * Always the attention strip, because it is always first and every row in it
 * is one line, plus the one panel directly under it.
 */
export function aboveTheFoldBlocks(
  order: readonly OverviewBlockId[],
): OverviewBlockId[] {
  return order.slice(0, 1 + ABOVE_THE_FOLD_PANELS);
}

/** True when this region is on the first screen for this block order. */
export function regionIsAboveTheFold(
  region: OverviewRegion,
  order: readonly OverviewBlockId[],
): boolean {
  if (region === "page_head") return true;
  return aboveTheFoldBlocks(order).includes(region);
}

/**
 * The block that renders each control the Overview states depend on.
 *
 * Verified against the sources before it was written, and pinned there by
 * `overviewPlacement.test.ts`, so a control that moves panel breaks the build
 * rather than quietly falling below the fold again.
 */
export const STATE_CRITICAL_CONTROL_REGION: Readonly<
  Partial<Record<DesktopControlId, OverviewRegion>>
> = {
  refresh: "page_head",
  enable_payments_locally: "payment_control",
  turn_on_phone_connection: "phone",
  turn_off_phone_connection: "phone",
  pair_a_phone: "phone",
  retry_automatic_setup: "phone",
  cancel_phone_pairing: "phone",
  start_connector: "connector",
  clear_failed_connector: "connector",
  // Rendered by both the phone panel and the connector panel. It is only ever
  // state-critical for one of them at a time, so the region is resolved from
  // the state in `stateCriticalControls` instead of from this table.
};

/**
 * The controls the attention strip can press itself.
 *
 * A row whose control is not in here renders its line without a button, so the
 * strip would only be pointing at something further down the page. This list
 * is checked against `alertHandlers` in `AgentWalletApp.tsx`.
 */
export const STRIP_PRESSABLE_CONTROLS: readonly DesktopControlId[] = [
  "enable_payments_locally",
  "refresh",
  "start_connector",
  "clear_failed_connector",
  "lock_and_switch_wallet",
  "turn_on_phone_connection",
  // The only control that can succeed against a dead listener slot.
  "turn_off_phone_connection",
  "pair_a_phone",
  "retry_automatic_setup",
];

export type StateCriticalControl = {
  control: DesktopControlId;
  /** The block that renders it in this state. */
  region: OverviewRegion;
};

/**
 * The controls this state DEPENDS on: pressing one is what moves the wallet
 * out of the state it is in. Everything else on Overview is reference.
 *
 * A control is listed only when it would really run in this state. The same
 * refusals `overviewAlerts` respects are respected here, because a control the
 * desktop would refuse is not a way out of anything, and hoisting it would be
 * the same false instruction in a different place.
 */
export function stateCriticalControls(
  input: OverviewStateInput,
): StateCriticalControl[] {
  const controls: StateCriticalControl[] = [];
  const add = (control: DesktopControlId, region: OverviewRegion) =>
    controls.push({ control, region });

  if (input.paymentsSuspended && !input.clearStopBlocked) {
    add("enable_payments_locally", "payment_control");
  }

  if (input.phone === "other_wallet") {
    add("lock_and_switch_wallet", "phone");
  } else if (input.phone === "failed") {
    // Starting is refused while the dead listener slot is still held, so the
    // only control that moves this state on is the one that releases it.
    add("turn_off_phone_connection", "phone");
  } else if (input.phone === "pairing") {
    // Deliberately empty. A running pairing is finished on the phone, and the
    // desktop step that ends it is inside the wizard. "Cancel pairing" is the
    // way out of the state, not the thing the state depends on, so hoisting it
    // would promote abandoning the pairing over completing it.
  } else if (input.phone === "off") {
    if (!input.phoneAddressReady) {
      add("retry_automatic_setup", "phone");
    } else if (input.hasAuthorizedPhone) {
      add("turn_on_phone_connection", "phone");
    } else if (!input.pairingBlocked) {
      add("pair_a_phone", "phone");
    }
  }

  if (input.connector === "stopped") add("start_connector", "connector");
  else if (input.connector === "failed") {
    add("clear_failed_connector", "connector");
  } else if (input.connector === "other_wallet") {
    add("lock_and_switch_wallet", "connector");
  }

  if (
    input.node === "offline" ||
    input.node === "balance_error" ||
    input.node === "stale"
  ) {
    add("refresh", "page_head");
  }

  return controls;
}

/* -------------------------------------------------------------------------- */
/* Small derivations the panels share                                          */
/* -------------------------------------------------------------------------- */

/** The phone link state, from the facts the companion status carries. */
export function phoneLinkState(input: {
  statusLoaded: boolean;
  belongsToAnotherWallet: boolean;
  enabled: boolean;
  /** The listener phase is "failed": the slot is held, the server is down. */
  listenerFailed: boolean;
  pairingActive: boolean;
}): PhoneLinkState {
  if (input.belongsToAnotherWallet) return "other_wallet";
  if (!input.statusLoaded) return "unknown";
  if (input.pairingActive) return "pairing";
  // A failed listener reports enabled:true from the backend. Reading it as
  // "on" made Overview say the phone connection was fine while every phone was
  // refused, and hid the panel that owns the only two controls that fix it.
  if (input.listenerFailed) return "failed";
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

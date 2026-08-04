import type { AgentRuntimeStatus, AgentWalletOverview } from "./api";

export const HPAY_LOCAL_PILOT = Object.freeze({
  label: "HPAY Local Pilot Chain V1",
  networkKind: "local_pilot_v1",
  profileId: "hpay-local-pilot-chain-v1",
  nodeUrl: "http://127.0.0.1:8197",
  chainId: 7,
  blockOne:
    "000087f67e55660eaefed72e0b9499147556a33a34f18fa48900f4a2fa30cd29",
  networkInstance:
    "9ebd8657a72faed35ed4d6e309fab2ef259f054e4820684fab6c6b848e4438f3",
});

export type AgentWalletUiState =
  | "loading"
  | "unavailable_in_this_build"
  | "not_created"
  | "locked"
  | "read_only"
  | "recovery_required"
  | "available";

export type AgentWalletWriteReadiness =
  | "disabled_by_build"
  | "wrong_network"
  | "missing_block_one"
  | "node_not_ready"
  | "mobile_not_paired"
  | "witness_not_initialized"
  | "wallet_not_funded"
  | "payments_suspended"
  | "recovery_required"
  | "ready";

/**
 * Prerequisites for MAKING A PAYMENT.
 *
 * This is the original `agentWalletWriteBlockers` body, unchanged. Every
 * condition, its order and the dedup are preserved, so the set of states in
 * which the desktop reports a payment as blocked is identical to before the
 * predicate was split. Nothing may be removed from this list: the Rust payment
 * gate is the real enforcement, and this list is its honest mirror.
 *
 * Do not reuse it for any decision that is not a payment. Clearing an emergency
 * stop and pairing a phone have their own, much smaller, predicates below.
 */
export function agentWalletPaymentBlockers(
  runtime: AgentRuntimeStatus,
  overview: AgentWalletOverview,
): AgentWalletWriteReadiness[] {
  const blockers: AgentWalletWriteReadiness[] = [];
  if (!runtime.pilot_enabled || !overview.pilot_enabled) {
    blockers.push("disabled_by_build");
  }
  if (!overview.block_one_fingerprint) blockers.push("missing_block_one");
  if (
    overview.node_status === "network_mismatch" ||
    overview.network_mode !== "testnet" ||
    overview.node?.mainnet
  ) {
    blockers.push("wrong_network");
  } else if (
    overview.node_status !== "verified" ||
    !overview.node ||
    overview.node.current_height < 2 ||
    !overview.node.transaction_ready
  ) {
    blockers.push("node_not_ready");
  }
  if (
    overview.node?.funding_confirmed === false ||
    overview.confirmed_balance_units === "0"
  ) {
    blockers.push("wallet_not_funded");
  }
  if (!overview.mobile_witness_ready) blockers.push("mobile_not_paired");
  if (!overview.mobile_witness_synchronized) {
    blockers.push("witness_not_initialized");
  }
  if (overview.payments_suspended) blockers.push("payments_suspended");
  if (overview.unresolved_signed_operations > 0) {
    blockers.push("recovery_required");
  }
  return [...new Set(blockers)];
}

/**
 * Prerequisites for CLEARING THE EMERGENCY STOP from this desktop.
 *
 * `enable_agent_payments_locally` (crates/agent-wallet-core/src/service.rs)
 * makes no network call, reads no balance, reads no witness and contacts no
 * companion. It only touches the unlocked local state, the journal and the
 * on-disk marker, and it authorizes no spend by itself: every payment still
 * traverses the full payment gate above and still needs an explicit
 * per-payment desktop approval.
 *
 * A blocker belongs here only if (a) the enable operation actually depends on
 * it and (b) the owner can clear it while the stop is engaged. `node_not_ready`
 * and `wallet_not_funded` fail (a). `mobile_not_paired` and
 * `witness_not_initialized` fail both, and they are the deadlock: the stop
 * itself refuses companion connectivity, so a phone can never be paired to
 * satisfy them while the stop is engaged.
 *
 * `payments_suspended` is absent by construction: it is the state this action
 * exists to leave, not an obstacle to it.
 */
export function agentWalletLocalEnableBlockers(
  runtime: AgentRuntimeStatus,
  overview: AgentWalletOverview,
): AgentWalletWriteReadiness[] {
  const blockers: AgentWalletWriteReadiness[] = [];
  // No pilot backend means the Tauri command is not registered at all.
  if (!runtime.pilot_enabled || !overview.pilot_enabled) {
    blockers.push("disabled_by_build");
  }
  // An unanchored wallet was never bound to the pilot chain. The anchor is
  // fixed at creation, so this is not something the stop can be hiding.
  if (!overview.block_one_fingerprint) blockers.push("missing_block_one");
  // Re-arming payments while pointed at mainnet or a mismatched chain is the
  // one environment fault where "enabled" is actively dangerous. It is fixed by
  // correcting the node configuration, which the stop does not prevent.
  if (
    overview.node_status === "network_mismatch" ||
    overview.network_mode !== "testnet" ||
    overview.node?.mainnet
  ) {
    blockers.push("wrong_network");
  }
  // Mandated. Clearing the stop advances the permit generation around an
  // operation that may already be on the wire.
  if (overview.unresolved_signed_operations > 0) {
    blockers.push("recovery_required");
  }
  return [...new Set(blockers)];
}

/**
 * Prerequisites for PAIRING A PHONE.
 *
 * This adds no refusal that does not already exist. It mirrors what Rust
 * enforces at service/companion/pairing.rs `issue_connectivity_permit` ->
 * emergency.rs `require_running`, so the desktop can say why the button will
 * fail instead of letting the owner discover it as a thrown error.
 *
 * Pairing is a private-LAN device-admission ceremony. It spends nothing,
 * contacts no node and consults no chain anchor, so node readiness, funding,
 * network identity and the witness are all irrelevant to it. `mobile_not_paired`
 * is self-contradictory here: it is the condition pairing exists to resolve.
 */
export function agentWalletPairingBlockers(
  runtime: AgentRuntimeStatus,
  overview: AgentWalletOverview,
): AgentWalletWriteReadiness[] {
  const blockers: AgentWalletWriteReadiness[] = [];
  if (!runtime.pilot_enabled || !overview.pilot_enabled) {
    blockers.push("disabled_by_build");
  }
  // Rust genuinely refuses pairing while the stop is engaged. We deliberately
  // do not widen that; we only explain the escape route.
  if (overview.payments_suspended) blockers.push("payments_suspended");
  // An Unsafe marker maps to RecoveryRequired, so pairing fails server-side.
  if (overview.unresolved_signed_operations > 0) {
    blockers.push("recovery_required");
  }
  return [...new Set(blockers)];
}

export function agentWalletWriteReadiness(
  runtime: AgentRuntimeStatus,
  overview: AgentWalletOverview,
): AgentWalletWriteReadiness {
  return agentWalletPaymentBlockers(runtime, overview)[0] ?? "ready";
}

export function agentWalletUiState(
  runtime: AgentRuntimeStatus | null,
  overview: AgentWalletOverview | null,
): AgentWalletUiState {
  if (!runtime) return "loading";
  if (!runtime.pilot_enabled) return "unavailable_in_this_build";
  if (!runtime.available) return "recovery_required";
  if (runtime.wallets.length === 0) return "not_created";
  if (!overview?.unlocked) return "locked";
  return agentWalletWriteReadiness(runtime, overview) === "ready"
    ? "available"
    : "read_only";
}

/** Why a PAYMENT is refused. Unchanged. */
export const WRITE_BLOCKER_LABELS: Record<AgentWalletWriteReadiness, string> = {
  disabled_by_build: "The Testnet Pilot backend is disabled in this build.",
  wrong_network: "The configured node does not match this Local Pilot network.",
  missing_block_one: "The wallet has no verified block 1 fingerprint.",
  node_not_ready: "The Local Pilot node is not transaction-ready.",
  mobile_not_paired: "A mobile approval device is not paired.",
  witness_not_initialized: "The rollback witness is not initialized and synchronized.",
  wallet_not_funded: "Funding is required before a test payment.",
  payments_suspended: "Agent payments are locally suspended.",
  recovery_required: "An unresolved signed operation requires recovery.",
  ready: "Payment prerequisites are satisfied.",
};

/**
 * Why CLEARING THE EMERGENCY STOP is refused.
 *
 * A disabled button must explain itself in terms of the action it is blocking.
 * Payment prose such as "Funding is required before a test payment." reads as
 * nonsense next to a control that spends nothing, which is what made the
 * original refusal impossible to act on.
 *
 * The entries `agentWalletLocalEnableBlockers` never emits are still spelled
 * out honestly, so the record stays total and any future reuse reads correctly.
 */
export const LOCAL_ENABLE_BLOCKER_LABELS: Record<AgentWalletWriteReadiness, string> = {
  disabled_by_build:
    "The Testnet Pilot backend is disabled in this build, so agent payments cannot be re-enabled.",
  wrong_network:
    "The configured node does not match this Local Pilot network. Correct the node before re-enabling agent payments.",
  missing_block_one:
    "This wallet has no verified block 1 fingerprint, so it is not bound to the Local Pilot chain.",
  node_not_ready:
    "Node readiness is required for a payment, not for re-enabling agent payments locally.",
  mobile_not_paired:
    "A paired phone is required for a payment, not for re-enabling agent payments locally.",
  witness_not_initialized:
    "A synchronized rollback witness is required for a payment, not for re-enabling agent payments locally.",
  wallet_not_funded:
    "Funding is required for a payment, not for re-enabling agent payments locally.",
  payments_suspended:
    "Agent payments are locally suspended. That is the state this action clears.",
  recovery_required:
    "An unresolved signed operation must be recovered before agent payments can be re-enabled.",
  ready: "Agent payments can be re-enabled locally from this unlocked desktop.",
};

/** Why PAIRING A PHONE is refused. Mirrors the existing Rust refusals only. */
export const PAIRING_BLOCKER_LABELS: Record<AgentWalletWriteReadiness, string> = {
  disabled_by_build:
    "The Testnet Pilot backend is disabled in this build, so no phone can be paired.",
  wrong_network: "The configured node is not consulted when pairing a phone.",
  missing_block_one: "The block 1 fingerprint is not consulted when pairing a phone.",
  node_not_ready: "The Local Pilot node is not contacted when pairing a phone.",
  mobile_not_paired: "Pairing a phone is what resolves this. It is not a prerequisite for it.",
  witness_not_initialized:
    "The rollback witness synchronizes after a phone is admitted, not before.",
  wallet_not_funded: "Pairing a phone spends nothing and needs no funds.",
  payments_suspended:
    "Agent payments are locally suspended, which also blocks the phone connection. Clear the emergency stop in Payment control first, then pair the phone.",
  recovery_required:
    "An unresolved signed operation must be recovered before a phone can be paired.",
  ready: "A phone can be paired.",
};

export type EmergencyStopControl =
  /** The stop is engaged. This is the only control that can clear it. */
  | { action: "enable"; disabled: boolean; reason: string }
  /** The stop is clear. This control engages it. It is never gated. */
  | { action: "disable"; disabled: boolean; reason: string };

/**
 * The single source of truth for the emergency-stop control, shared by the
 * Overview page and the Security page so the two surfaces can never disagree
 * about whether the owner has a way out of a stop.
 *
 * Engaging the stop is never gated: fail-closed must always be reachable.
 */
export function emergencyStopControl(input: {
  paymentsSuspended: boolean;
  busy: boolean;
  localEnableBlockers: AgentWalletWriteReadiness[];
}): EmergencyStopControl {
  if (!input.paymentsSuspended) {
    return {
      action: "disable",
      disabled: input.busy,
      reason: "Blocks new agent payment progress and invalidates active permits.",
    };
  }
  return {
    action: "enable",
    disabled: input.busy || input.localEnableBlockers.length > 0,
    reason:
      input.localEnableBlockers
        .map((blocker) => LOCAL_ENABLE_BLOCKER_LABELS[blocker])
        .join(" ") || LOCAL_ENABLE_BLOCKER_LABELS.ready,
  };
}

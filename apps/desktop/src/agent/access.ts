import type {
  AgentRuntimeStatus,
  AgentWalletOverview,
  OperationStatus,
} from "./api";

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
export const HPAY_MAINNET = Object.freeze({
  label: "Hacash Mainnet",
  networkKind: "mainnet",
  profileId: "hacash-mainnet",
  chainId: 0,
  blockOne:
    "001e231cb03f9938d54f04407797b8188f0375eb10f0bcb426dccae87dcadb56",
});
/**
 * What the owner is actually agreeing to, said in the words that matter.
 *
 * The sentence this replaces was "a trusted bounded pilot and I accept its
 * recovery limits". True, and opaque: it named neither the amount at risk nor
 * what "trusted" costs. Somebody reading it understands "limited, probably
 * fine" rather than "this provider can keep my money".
 *
 * Three facts, in the order a person needs them: what trusted means, how much
 * is on the table, and that they should not exceed what they can lose. The
 * amount is stated rather than left to a settings screen, because a consent
 * that does not name the number is not consent to the number.
 */
export const AGENT_MAINNET_PILOT_ACKNOWLEDGEMENT =
  "I understand that this provider holds my channel funds, and that if it stops answering there is no way yet to recover them without it. At most 10 HAC per channel is at risk. I will not put in more than I can afford to lose.";

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
  | "mainnet_consent_missing"
  | "missing_block_one"
  | "node_not_ready"
  | "mobile_not_paired"
  | "witness_not_initialized"
  | "wallet_not_funded"
  | "payments_suspended"
  | "recovery_required"
  /**
   * A witness rotation is part-way through.
   *
   * `create_payment_intent` (crates/agent-wallet-core/src/service/payment.rs)
   * returns `RecoveryRequired` for every intent while the rotation phase is
   * not Stable or Completed. That surfaces to the agent as "Agent Wallet state
   * requires manual recovery" while this desktop printed "Agent payments:
   * ready", so the two surfaces named opposite causes for the same refusal.
   * This mirrors the existing Rust gate; it adds none.
   */
  | "rotation_in_progress"
  | "ready";

/**
 * The rotation phases in which Rust permits an agent write.
 *
 * `WitnessRotationPhase::permits_agent_writes`
 * (crates/companion-protocol/src/rotation.rs) is exactly this set. Nothing
 * else is derived from it here.
 */
const ROTATION_PHASES_THAT_PERMIT_WRITES = new Set(["stable", "completed"]);

/** True when a rotation is far enough along to be refusing agent writes. */
export function rotationBlocksAgentWrites(
  phase: AgentWalletOverview["witness_rotation_phase"],
): boolean {
  return phase !== null && !ROTATION_PHASES_THAT_PERMIT_WRITES.has(phase);
}

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
  const expectsMainnet = overview.network_mode === "mainnet";
  if (
    overview.node_status === "network_mismatch" ||
    !["mainnet", "testnet"].includes(overview.network_mode) ||
    (overview.node !== null && overview.node.mainnet !== expectsMainnet)
  ) {
    blockers.push("wrong_network");
  } else if (
    expectsMainnet &&
    (!overview.trusted_mainnet_fast_pay_pilot || !overview.mainnet_spending_ready)
  ) {
    blockers.push("mainnet_consent_missing");
  } else if (
    overview.node_status !== "verified" ||
    !overview.node ||
    overview.node.current_height < (expectsMainnet ? 765_432 : 2) ||
    !overview.node.transaction_ready
  ) {
    blockers.push("node_not_ready");
  }
  if (
    (!expectsMainnet && overview.node?.funding_confirmed === false) ||
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
  // The rotation the owner started is what blocks every agent write, and until
  // now nothing on either surface said so: Overview reported "Agent payments:
  // ready" while the agent was told the wallet needed manual recovery.
  if (rotationBlocksAgentWrites(overview.witness_rotation_phase)) {
    blockers.push("rotation_in_progress");
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
  const expectsMainnet = overview.network_mode === "mainnet";
  // Re-arming payments while pointed at mainnet or a mismatched chain is the
  // one environment fault where "enabled" is actively dangerous. It is fixed by
  // correcting the node configuration, which the stop does not prevent.
  if (
    overview.node_status === "network_mismatch" ||
    !["mainnet", "testnet"].includes(overview.network_mode) ||
    (overview.node !== null && overview.node.mainnet !== expectsMainnet)
  ) {
    blockers.push("wrong_network");
  }
  if (
    expectsMainnet &&
    (!overview.trusted_mainnet_fast_pay_pilot || !overview.mainnet_spending_ready)
  ) {
    blockers.push("mainnet_consent_missing");
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
  disabled_by_build: "The Agent Wallet backend is disabled in this build.",
  wrong_network: "The configured node does not match this Agent Wallet network.",
  mainnet_consent_missing:
    "This wallet has no authenticated consent for the bounded mainnet Fast Pay pilot.",
  missing_block_one: "The wallet has no verified block 1 fingerprint.",
  node_not_ready: "The selected Hacash node is not transaction-ready.",
  mobile_not_paired: "A mobile approval device is not paired.",
  witness_not_initialized: "The rollback witness is not initialized and synchronized.",
  wallet_not_funded: "Funding is required before a payment.",
  payments_suspended: "Agent payments are locally suspended.",
  recovery_required: "An unresolved signed operation requires recovery.",
  rotation_in_progress:
    "A phone replacement is part-way through. Every agent payment request is refused until it finishes or is cancelled, and the agent is told the wallet needs manual recovery. Finish or cancel it under Replace the paired phone on Security.",
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
    "The Agent Wallet backend is disabled in this build, so agent payments cannot be re-enabled.",
  wrong_network:
    "The configured node does not match this Agent Wallet network. Correct the node before re-enabling agent payments.",
  mainnet_consent_missing:
    "This wallet was not created with authenticated bounded-mainnet consent, so mainnet payments stay blocked.",
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
  rotation_in_progress:
    "A phone replacement in progress blocks agent payments, not the local re-enable. Clearing the stop still works.",
  ready: "Agent payments can be re-enabled locally from this unlocked desktop.",
};

/** Why PAIRING A PHONE is refused. Mirrors the existing Rust refusals only. */
export const PAIRING_BLOCKER_LABELS: Record<AgentWalletWriteReadiness, string> = {
  disabled_by_build:
    "The Agent Wallet backend is disabled in this build, so no phone can be paired.",
  wrong_network: "The configured node is not consulted when pairing a phone.",
  mainnet_consent_missing:
    "Mainnet payment consent is not consulted when pairing a phone.",
  missing_block_one: "The block 1 fingerprint is not consulted when pairing a phone.",
  node_not_ready: "The Hacash node is not contacted when pairing a phone.",
  mobile_not_paired: "Pairing a phone is what resolves this. It is not a prerequisite for it.",
  witness_not_initialized:
    "The rollback witness synchronizes after a phone is admitted, not before.",
  wallet_not_funded: "Pairing a phone spends nothing and needs no funds.",
  payments_suspended:
    "Agent payments are locally suspended, which also blocks the phone connection. Clear the emergency stop in Payment control first, then pair the phone.",
  recovery_required:
    "An unresolved signed operation must be recovered before a phone can be paired.",
  rotation_in_progress:
    "A phone replacement in progress does not block ordinary pairing. Use Replace the paired phone on Security to finish it.",
  ready: "A phone can be paired.",
};

/**
 * The pairing refusal, with the escape route it names checked against reality.
 *
 * `PAIRING_BLOCKER_LABELS.payments_suspended` instructs the owner to clear the
 * emergency stop first. That instruction is only followable while "Enable
 * locally" is itself available: with a wrong network or a missing block 1
 * anchor, `agentWalletLocalEnableBlockers` disables it, so the escape route is
 * closed and the sentence named a control that is refused. Overview already
 * drops the action in that case; the phone panel printed the refusal verbatim.
 *
 * Copy only. The refusals themselves are unchanged and still come from Rust.
 */
export function pairingRefusalText(
  pairingBlockers: AgentWalletWriteReadiness[],
  localEnableBlockers: AgentWalletWriteReadiness[],
): string {
  const base = pairingBlockers
    .map((blocker) => PAIRING_BLOCKER_LABELS[blocker])
    .join(" ");
  if (!base) return "";
  if (
    !pairingBlockers.includes("payments_suspended") ||
    localEnableBlockers.length === 0
  ) {
    return base;
  }
  const why = localEnableBlockers
    .map((blocker) => LOCAL_ENABLE_BLOCKER_LABELS[blocker])
    .join(" ");
  return `${base} Enable locally is unavailable too, so that route is closed until this is fixed: ${why}`;
}

/**
 * WHAT PRESSING APPROVE ACTUALLY DOES, IN THIS BUILD.
 *
 * `approve_desktop_and_broadcast`
 * (crates/agent-wallet-core/src/service/payment.rs) used to refuse EVERY
 * desktop approval under `agent-wallet-testnet-pilot`, so the desktop hid the
 * control rather than offering one that could not succeed. That refusal was a
 * fail-closed stub standing in for a phone that could not yet witness an
 * operation it had not itself approved. The phone can now discover such an
 * operation through the least-privilege witness disclosure and witness it, the
 * whole path is executed end to end in
 * crates/agent-wallet-core/src/service/companion/tests/desktop_witness_flow.rs,
 * and the control is back.
 *
 * What is NOT the same in both builds is what a yes does, and the copy beside
 * the control has to say which one it is:
 *
 * * Pilot build: approving signs the exact transaction and then STOPS at
 *   `SignedAwaitingWitness`. Nothing reaches the network until the paired phone
 *   signs the rollback anchor that witnesses it. Telling the owner the payment
 *   was "submitted" at that point would be false.
 * * Non-pilot build: approving signs and submits in the same call.
 *
 * This is the only build-dependent thing left about approval, so it is the only
 * thing this exports. Whether an individual approval can succeed is decided by
 * Rust - the agent's Approval device, the exactness of the commitment, its
 * expiry, the emergency stop, and whether a phone that can witness is paired -
 * and every one of those refusals carries its own message.
 */
export type ApprovalOutcome =
  /** Signs now; the network sees nothing until the phone witnesses it. */
  | "signs_then_waits_for_the_phone"
  /** Signs and submits in the same call. */
  | "signs_and_broadcasts";

export function approvalOutcome(overview: AgentWalletOverview): ApprovalOutcome {
  return overview.pilot_enabled
    ? "signs_then_waits_for_the_phone"
    : "signs_and_broadcasts";
}

/**
 * Rendered beside the Approve control, before the press, never behind a
 * disclosure.
 *
 * The pilot sentence has to hold in every state the button can be pressed in,
 * including the one where no phone is paired yet. It does: in that state Rust
 * refuses before signing and says so, which is why this promises a stop rather
 * than a completed payment.
 */
export const APPROVE_OUTCOME_NOTICE: Record<ApprovalOutcome, string> = {
  signs_then_waits_for_the_phone:
    "Approving signs this exact transaction and then stops. Nothing is sent to the network until you confirm it on " +
    "your paired phone, which is what witnesses the payment. If no phone is able to witness it - none paired yet, or " +
    "the phone set up to witness was replaced or revoked - this is refused and nothing is signed.",
  signs_and_broadcasts:
    "Approving signs this exact transaction and submits it to the network in the same step.",
};

/**
 * What the owner is told AFTER the press, derived from the status Rust actually
 * returned rather than from the build.
 *
 * The old message said "The exact approved transaction was submitted." for
 * every success. In a pilot build a successful approval returns
 * `signed_awaiting_witness`, where nothing has been submitted and the owner
 * still has something to do, so that sentence would have been the button's old
 * lie moved one step later.
 */
export function approvalResultNotice(status: OperationStatus): string {
  switch (status) {
    case "signed_awaiting_witness":
      return (
        "Approved and signed. Nothing has been sent to the network yet: open the AI Agent Wallet on your paired " +
        "phone and confirm this payment to complete it."
      );
    case "witnessed_awaiting_broadcast":
      return (
        "Your phone confirmed this payment and it is being submitted. Refresh to see where it got to; do not " +
        "approve it again."
      );
    case "broadcast_submitted":
    case "submitted_awaiting_final_witness":
      return "The exact approved transaction was submitted.";
    case "broadcast_uncertain":
      return "Broadcast status is uncertain. Do not retry automatically.";
    case "approved":
      return (
        "Your approval was recorded, but the transaction has not been signed yet. Check the node connection and " +
        "open this payment again."
      );
    default:
      return `Approval accepted. This payment is now ${status.replace(/_/g, " ")}.`;
  }
}

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

import type {
  CompanionEncryptedFrame,
  CompanionPairingConfirmation,
  CompanionPairingOffer,
  CompanionPairingRequest,
} from "@hacash/wallet-ui";

export type {
  CompanionEncryptedFrame,
  CompanionPairingConfirmation,
  CompanionPairingOffer,
  CompanionPairingRequest,
};

export type AgentCompanionIdentityStatus = {
  platformSupported: boolean;
  configured: boolean;
  ready: boolean;
  keySecurityLevel: string;
  hardwareBacked: boolean;
  strongBoxBacked: boolean;
  authenticationEnforcedBySecureHardware: boolean;
  authPerUse: boolean;
};

export type CompanionPairingStartView = {
  request: CompanionPairingRequest;
  confirmation?: CompanionPairingConfirmation | null;
  automaticTransport: boolean;
};

export type CompanionPairingAckDeliveryView = {
  delivered: boolean;
};

export type CompanionPairingCancelView = {
  pairingCancelled: boolean;
};

export type CompanionPairingCompletionView = {
  encryptedAck: CompanionEncryptedFrame;
  agentWalletId: string;
  desktopDeviceId: string;
  mobileDeviceId: string;
};

export type SignedRotationPairingTicket = {
  ticket: {
    ticket_version: string;
    ticket_id: string;
    pairing_id: string;
    rotation_id: string;
    agent_wallet_id: string;
    desktop_device_id: string;
    expected_candidate_device_id: string;
    expected_candidate_identity_fingerprint: string;
    network_id: "testnet";
    expires_at: string;
  };
  desktop_signature_hex: string;
};

export type SignedRotationCandidateAcceptance = {
  acceptance: {
    ticket_id: string;
    ticket_hash: string;
    pairing_id: string;
    rotation_id: string;
    agent_wallet_id: string;
    desktop_device_id: string;
    candidate_device_id: string;
    candidate_identity_fingerprint: string;
    network_id: "testnet";
    accepted_at: string;
  };
  candidate_signature_hex: string;
};

export type RotationCandidatePairingCompletionView =
  CompanionPairingCompletionView & {
    signedAcceptance: SignedRotationCandidateAcceptance;
  };

/**
 * Every witness rotation phase the native side can persist, in the exact
 * snake_case spelling `WitnessRotationPhase` serialises to
 * (crates/companion-protocol/src/rotation.rs). This is the single source of
 * truth for both the declared type and the runtime validator in
 * companionView.ts, so the two can never drift apart: a phase missing from the
 * runtime set makes the whole stored state unreadable and the phone reports
 * itself unpaired while it is still paired.
 */
export const COMPANION_ROTATION_PHASES = [
  "stable",
  "rotation_required",
  "rotation_prepared",
  "rotation_requested",
  "awaiting_old_witness_authorization",
  "rotation_ticket_issued",
  "awaiting_candidate_pairing",
  "candidate_paired_restricted",
  "candidate_baseline_verified",
  "awaiting_old_device_revocation",
  "awaiting_completion_anchor",
  "awaiting_new_device_pairing",
  "awaiting_new_witness_baseline",
  "awaiting_rotation_completion_anchor",
  "completed",
  "blocked_by_pending_approval",
  "blocked_by_unresolved_signed_operation",
  "blocked_by_broadcast_uncertainty",
  "recovery_rotation_required",
  "rotation_recovery_required",
] as const;

export type CompanionRotationPhase = (typeof COMPANION_ROTATION_PHASES)[number];

export type CompanionStoredStateView = {
  configured: boolean;
  connected: boolean;
  agentWalletId: string | null;
  desktopDeviceId: string | null;
  mobileDeviceId: string | null;
  endpoints: string[];
  responseSequence: string | null;
  pendingPairingFinalization: boolean;
  pilotEnabled: boolean;
  controlledRotationRequired: boolean;
  rotationPhase: CompanionRotationPhase | null;
  /**
   * What the pairing-only reset would actually refuse with right now.
   *
   * `controlledRotationRequired` only reads `rotationPhase`, but
   * `reset_before_witness_rotation`
   * (apps/mobile/src-tauri/src/agent_companion/storage.rs) refuses on the wider
   * `rotation_blocking_phase()`, which also covers a pending pilot approval and
   * any witness record. The screen could not see those two facts, so it offered
   * a reset that could only refuse - and the refusal durably replaced the reset
   * section for good.
   */
  resetBlockingPhase: CompanionRotationPhase | null;
  /** Whether this phone still holds the key its stored pairing is bound to. */
  pairingIdentity: CompanionPairingIdentity;
  hardwareIdentityRetainedOnReset: boolean;
  /**
   * The one payment this phone is still holding a consent record for.
   *
   * Holding one blocks the pairing-only reset, blocks pairing again, and blocks
   * every other payment this phone could approve or witness. Until this field
   * existed the record was invisible: the only screen that could reach it was
   * the witness card, and that card disappears the moment the desktop stops
   * offering the operation. The owner has to be able to read what they are
   * holding before they can be asked to discard it.
   */
  pendingConsent: CompanionPendingConsentView | null;
  /**
   * Every consent record this phone stopped holding, newest first.
   *
   * This was a single record, so a second discard erased the first receipt
   * before the owner could ever read it - and losing that evidence is the one
   * thing the receipt exists to prevent. The native side now keeps a bounded
   * append-only history; see `MAX_COMPANION_DISCARDED_CONSENTS`.
   */
  discardedConsents: CompanionDiscardedConsentView[];
  /**
   * How many older receipts the cap has pushed out of that history, decimal.
   *
   * Shown to the owner verbatim. A history that dropped something without
   * saying so would be the same defect as the single slot.
   */
  discardedConsentsDropped: string;
};

/**
 * How many discard receipts the phone keeps.
 *
 * Mirrors `MAX_DISCARDED_CONSENTS` in
 * apps/mobile/src-tauri/src/agent_companion/storage.rs. The screen refuses a
 * longer list rather than rendering a history the native side could not have
 * written.
 */
export const MAX_COMPANION_DISCARDED_CONSENTS = 32;

export const COMPANION_CONSENT_KINDS = [
  "witness_confirmation",
  "pilot_approval",
] as const;

export type CompanionConsentKind = (typeof COMPANION_CONSENT_KINDS)[number];

/** A consent record this phone is holding right now. */
export type CompanionPendingConsentView = {
  kind: CompanionConsentKind;
  operationId: string;
  amountUnits: string;
  recipient: string;
  recordedAtUnix: string;
};

/**
 * A consent record this phone stopped holding.
 *
 * A receipt, not a witness. It says nothing about whether the payment was
 * signed, broadcast or committed, and the native side never consults it when
 * admitting a rollback anchor.
 */
export type CompanionDiscardedConsentView = {
  kind: CompanionConsentKind;
  operationId: string;
  amountUnits: string;
  recipient: string;
  recordedAtUnix: string;
  discardedAtUnix: string;
  reason: string;
};

export type CompanionDiscardConsentView = {
  discarded: CompanionDiscardedConsentView;
};

export const COMPANION_PAIRING_IDENTITIES = [
  "not_paired",
  "matches",
  "replaced",
  "absent",
  "unknown",
] as const;

/**
 * How the Android identity this phone holds relates to its stored pairing.
 *
 * Only `replaced` and `absent` mean the durable witness state can never be
 * presented again. `unknown` is a failed or unavailable read and concludes
 * nothing.
 */
export type CompanionPairingIdentity =
  (typeof COMPANION_PAIRING_IDENTITIES)[number];

export type CompanionSessionView = {
  connected: boolean;
  sessionId: string;
  localDeviceId: string;
  remoteDeviceId: string;
  establishedAtUnix: string;
  expiresAtUnix: string;
};

export type CompanionRotationView = {
  rotationId: string;
  phase: NonNullable<CompanionStoredStateView["rotationPhase"]>;
  detail: string;
};

export type CompanionMessageEnvelopeView = {
  messageId: string;
  sessionId: string;
  senderDeviceId: string;
  recipientDeviceId: string;
  sequence: string;
  issuedAtUnix: string;
  expiresAtUnix: string;
};

export type NativeCompanionStatus = {
  agent_wallet_id: string;
  address: string;
  available_units: string | null;
  node_status: string;
  reserved_units: string;
  spent_today_units: string;
  spent_month_units: string;
  paused: boolean;
  policy_epoch: string;
};

export type NativeAgentSummary = {
  agent_id: string;
  display_name: string;
  authorization: "authorized" | "disabled" | "revoked";
};

export type NativeAgentPolicySummary = {
  agent_id: string;
  max_per_payment_units: string;
  max_daily_units: string;
  max_pending_operations: number;
  approval_mode:
    | "desktop_manual"
    | "mobile_manual"
    | "either_trusted_device";
  permissions: string[];
  allowed_recipients: string[];
  blocked_recipients: string[];
  policy_epoch: string;
};

export type NativeApprovalNetworkBinding = {
  network_id: string;
  chain_id: number;
  genesis_identifier: string;
  node_profile_id: string;
  transaction_format_version: string;
};

export type NativeApprovalCommitment = {
  approval_version: string;
  approval_id: string;
  operation_id: string;
  agent_wallet_id: string;
  agent_id: string;
  desktop_device_id: string;
  transaction_commitment: string;
  amount_units: string;
  fee_units: string;
  wallet_fee_units: string;
  total_debit_units: string;
  recipient: string;
  policy_epoch: string;
  challenge_nonce: string;
  issued_at: string;
  expires_at: string;
  network_binding?: NativeApprovalNetworkBinding;
};

export type NativeActivitySummary = {
  activity_id: string;
  description: string;
  asset: string;
  recipient: string;
  amount_units: string;
  occurred_at: string;
  status: string;
};

export type CompanionStatusSnapshotView = {
  envelope: CompanionMessageEnvelopeView;
  status: NativeCompanionStatus;
  agents: NativeAgentSummary[];
  policies: NativeAgentPolicySummary[];
  approvals: NativeApprovalCommitment[];
  activity: NativeActivitySummary[];
};

export type CompanionPilotDecisionView = {
  operationId: string;
  approved: boolean;
  witnessed: boolean;
  anchorId: string | null;
  detail: string;
};

export type CompanionWitnessView = {
  anchorId: string;
  accepted: boolean;
  detail: string;
};

export type CompanionPongView = {
  envelope: CompanionMessageEnvelopeView;
  pong: boolean;
};

export type CompanionDisconnectView = {
  disconnected: boolean;
};

export type CompanionLifecycleEvent =
  | "foreground_heartbeat"
  | "webview_closing";

export type CompanionLifecycleView = {
  sessionAllowedInBackground: boolean;
  nativeDisconnectEnforced: boolean;
};

export type CompanionResetView = {
  reset: boolean;
  disconnected: boolean;
  pairingCancelled: boolean;
  hardwareIdentityRetained: boolean;
  requiresNewPairing: boolean;
};

export type AuthenticatedCompanionSession = {
  state: "authenticated";
  sessionId: string;
  mobileDeviceId: string;
  desktopDeviceId: string;
  establishedAtUnix: string;
  expiresAtUnix: string;
  snapshotIssuedAtUnix: string;
  snapshotExpiresAtUnix: string;
  messageId: string;
  sequence: string;
};

export type AgentCompanionWallet = {
  walletId: string;
  address: string;
  availableUnits: string | null;
  reservedUnits: string;
  spentTodayUnits: string;
  spentMonthUnits: string;
  nodeStatus: string;
  paused: boolean;
  policyEpoch: string;
};

export type AgentCompanionAgent = {
  agentId: string;
  displayName: string;
  authorization: "authorized" | "disabled" | "revoked";
};

export type AgentCompanionPolicy = {
  agentId: string;
  maximumPerRequestUnits: string;
  maximumPerDayUnits: string;
  maximumPendingOperations: number;
  approvalMode:
    | "desktop_manual"
    | "mobile_manual"
    | "either_trusted_device";
  permissions: string[];
  allowedRecipients: string[];
  blockedRecipients: string[];
  policyEpoch: string;
};

export type AgentCompanionActivity = {
  activityId: string;
  description: string;
  asset: string;
  recipient: string;
  amountUnits: string;
  occurredAtUnix: string;
  status: string;
};

export type AgentCompanionApprovalNetworkBinding = {
  networkId: "testnet";
  chainId: number;
  genesisIdentifier: string;
  nodeProfileId: string;
  transactionFormatVersion: "2";
};

export type AgentCompanionPendingApproval = {
  approvalVersion: string;
  approvalId: string;
  operationId: string;
  agentWalletId: string;
  agentId: string;
  desktopDeviceId: string;
  transactionCommitment: string;
  amountUnits: string;
  feeUnits: string;
  walletFeeUnits: string;
  totalDebitUnits: string;
  recipient: string;
  policyEpoch: string;
  challengeNonce: string;
  issuedAtUnix: string;
  expiresAtUnix: string;
  networkBinding: AgentCompanionApprovalNetworkBinding | null;
};

/**
 * Read-only data accepted by the mobile UI only after native authentication
 * and a second strict JavaScript scope/time/shape validation.
 */
export type AgentCompanionSnapshot = {
  pilotEnabled: boolean;
  session: AuthenticatedCompanionSession;
  wallet: AgentCompanionWallet;
  agents: AgentCompanionAgent[];
  policies: AgentCompanionPolicy[];
  activity: AgentCompanionActivity[];
  pendingApprovals: AgentCompanionPendingApproval[];
};

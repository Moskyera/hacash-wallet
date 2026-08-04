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
  rotationPhase:
    | "stable"
    | "rotation_required"
    | "rotation_prepared"
    | "rotation_requested"
    | "awaiting_old_witness_authorization"
    | "rotation_ticket_issued"
    | "awaiting_candidate_pairing"
    | "candidate_paired_restricted"
    | "candidate_baseline_verified"
    | "awaiting_old_device_revocation"
    | "awaiting_completion_anchor"
    | "awaiting_new_device_pairing"
    | "awaiting_new_witness_baseline"
    | "awaiting_rotation_completion_anchor"
    | "completed"
    | "blocked_by_pending_approval"
    | "blocked_by_unresolved_signed_operation"
    | "blocked_by_broadcast_uncertainty"
    | "recovery_rotation_required"
    | "rotation_recovery_required"
    | null;
  hardwareIdentityRetainedOnReset: boolean;
};

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

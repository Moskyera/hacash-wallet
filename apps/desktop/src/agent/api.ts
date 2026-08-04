import { invoke } from "@tauri-apps/api/core";

export type AgentWalletRegistryEntry = {
  wallet_id: string;
  address: string;
  created_at_unix: number;
};

export type AgentConnectorStatus = {
  phase: "stopped" | "starting" | "running" | "stopping" | "failed";
  walletId: string | null;
  endpoint: string | null;
  lastError: string | null;
};

export type AgentRuntimeStatus = {
  available: boolean;
  pilot_enabled: boolean;
  application_version: string;
  build_profile: "debug" | "release";
  error: string | null;
  wallets: AgentWalletRegistryEntry[];
  connector: AgentConnectorStatus;
};

export type MobileCompanionStatus = {
  enabled: boolean;
  walletId: string | null;
  localAddress: string | null;
  phase: "stopped" | "listening" | "stopping" | "failed";
  transport: "encrypted_private_lan";
};

export type MobileCompanionDevice = {
  record_version: string;
  device_id: string;
  role: "mobile";
  agent_wallet_id: string;
  identity_public_key_sec1_hex: string;
  identity_fingerprint: string;
  authorization_epoch: string;
  permissions: Array<
| "view_agent_wallet_status"
    | "view_pending_approvals"
    | "view_agents"
    | "approve_payment"
    | "reject_payment"
    | "witness_rollback_anchor"
  >;
  paired_at: string;
  revoked_at: string | null;
};
export type MobilePairingOffer = {
  protocol_version: string;
  pairing_id: string;
  agent_wallet_id: string;
  desktop_device_id: string;
  desktop_ephemeral_public_key: string;
  desktop_identity_public_key: string;
  desktop_identity_fingerprint: string;
  lan_endpoints: string[];
  pairing_nonce: string;
  issued_at: string;
  expires_at: string;
};

export type MobilePairingProgress = {
  offer: MobilePairingOffer;
  confirmation: MobilePairingConfirmation | null;
  ackReceived: boolean;
  /**
   * Bounded retry budget of the live pairing. Counters only: the desktop never
   * sends a code, nonce, key or device identifier here.
   */
  attemptsUsed: number;
  attemptsRemaining: number;
  maxAttempts: number;
};

export type MobilePairingRequest = {
  protocol_version: string;
  pairing_id: string;
  agent_wallet_id: string;
  desktop_device_id: string;
  mobile_device_id: string;
  mobile_ephemeral_public_key: string;
  mobile_identity_public_key: string;
  mobile_identity_fingerprint: string;
  pairing_nonce: string;
  mobile_challenge: string;
  issued_at: string;
  expires_at: string;
  identity_signature: string;
};

export type MobilePairingConfirmation = {
  protocol_version: string;
  pairing_id: string;
  agent_wallet_id: string;
  desktop_device_id: string;
  mobile_device_id: string;
  desktop_challenge: string;
  verification_code: string;
  session_id: string;
  issued_at: string;
  expires_at: string;
  desktop_identity_signature: string;
};

export type EncryptedCompanionFrame = {
  frame_version: string;
  session_id: string;
  sender_device_id: string;
  recipient_device_id: string;
  sequence: string;
  issued_at: string;
  expires_at: string;
  nonce_hex: string;
  ciphertext_hex: string;
};
export type PairingActivation = {
  pairingId: string;
  walletId: string;
  expiresAtUnix: string;
  serverIdentity: PinnedServerIdentity;
};

export type PendingPairing = {
  walletId: string;
  agentName: string;
  agentVersion: string;
  identityFingerprint: string;
  requestedCapabilities: AgentPermission[];
  submissionCommitment: string;
  expiresAtUnix: string;
};

export type CreatedAgentWallet = {
  wallet_id: string;
  address: string;
  network_mode: "mainnet" | "testnet";
};

export type AgentWalletStatus = {
  wallet_id: string;
  address: string;
  network_mode: "mainnet" | "testnet";
  signer_epoch: number;
  payments_suspended: boolean;
};

export type AgentWalletOverview = {
  wallet_id: string;
  address: string;
  network_mode: "mainnet" | "testnet";
  node_url: string | null;
  block_one_fingerprint: string | null;
  node: {
    node_name: string;
    node_version: string;
    network_kind: string;
    node_profile_id: string;
    chain_id: number;
    mainnet: boolean;
    current_height: number;
    block_one_fingerprint: string;
    network_instance_id: string;
    funding_confirmed: boolean;
    transaction_ready: boolean;
    transaction_format_version: number;
  } | null;
  node_status:
    | "unchecked"
    | "verified"
    | "offline"
    | "network_mismatch"
    | "capability_mismatch"
    | "balance_error";
  node_error: string | null;
  unlocked: boolean;
  payments_suspended: boolean;
  mainnet_spending_ready: boolean;
  confirmed_balance_units: string | null;
  reserved_units: string;
  available_units: string | null;
  spent_today_units: string;
  spent_this_month_units: string;
  authorized_agents: number;
  pending_approvals: number;
  pilot_enabled: boolean;
  mobile_witness_ready: boolean;
  mobile_witness_synchronized: boolean;
  latest_anchor_sequence: number;
  unresolved_signed_operations: number;
  witness_rotation_phase: WitnessRotationPhase | null;
  stale: boolean;
};

export type WitnessRotationPhase =
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
  | "rotation_recovery_required";

export type AgentPermission =
  | "read_wallet_info"
  | "read_balance"
  | "create_payment_intent"
  | "read_own_operation_status"
  | "list_own_operations"
  | "cancel_own_unsigned_operation";

export type ApprovalMode =
  | "desktop_manual"
  | "mobile_manual"
  | "either_trusted_device";

export type AgentPolicy = {
  permissions: AgentPermission[];
  max_per_payment_units: string;
  max_daily_units: string;
  max_pending_operations: number;
  allowed_recipients: string[];
  blocked_recipients: string[];
  approval_mode: ApprovalMode;
  policy_epoch: number;
};

export type PinnedServerIdentity = {
  desktop_instance_id: string;
  identity_public_key_sec1_hex: string;
  identity_fingerprint: string;
};

export type AgentRecord = {
  agent_id: string;
  wallet_scope: string;
  name: string;
  version: string;
  identity_public_key_sec1: string;
  identity_fingerprint: string;
  identity_key_sha256: string;
  server_identity: PinnedServerIdentity;
  status: "active" | "disabled" | "revoked";
  authorization_epoch: number;
  policy: AgentPolicy;
  paired_at: number;
};

export type OperationStatus =
  | "payment_intent_created"
  | "funds_reserved"
  | "unsigned_transaction_persisted"
  | "approval_requested"
  | "approved"
  | "rejected"
  | "signed"
  | "signed_awaiting_witness"
  | "witnessed_awaiting_broadcast"
  | "broadcast_submitted"
  | "broadcast_uncertain"
  | "submitted_awaiting_final_witness"
  | "reconciliation_required"
  | "reconciled_awaiting_final_witness"
  | "committed"
  | "failed"
  | "cancelled"
  | "recovery_required";

export type PaymentOperation = {
  operation_id: string;
  agent_wallet_id: string;
  agent_id: string;
  idempotency_key: string;
  request_commitment: string;
  asset: string;
  amount_units: string;
  recipient: string;
  reason: string;
  status: OperationStatus;
  network_fee_units: string;
  wallet_fee_units: string;
  total_debit_units: string;
  reserved_units: string;
  transaction_commitment: string | null;
  approval_mode: ApprovalMode | null;
  created_at: number;
  expires_at: number;
  tx_hash: string | null;
  final_result: string | null;
};

export type ApprovalCommitment = {
  approval_version: string;
  approval_id: string;
  operation_id: string;
  agent_wallet_id: string;
  agent_id: string;
  desktop_device_id: string;
  amount_units: string;
  recipient: string;
  fee_units: string;
  wallet_fee_units: string;
  total_debit_units: string;
  transaction_commitment: string;
  policy_epoch: string;
  challenge_nonce: string;
  issued_at: string;
  expires_at: string;
};

export type AgentPilotDiagnosticsPreview = {
  categories: string[];
  excluded_categories: string[];
  preview_sha256: string;
  diagnostics: {
    schema_version: number;
    application_version: string;
    pilot_protocol_version: string;
    platform: string;
    build_profile: string;
    network_id: string;
    node_profile_id: string;
    witness_epoch: number | null;
    signer_epoch: number;
    journal_epoch: number;
    journal_sequence: number;
    anchor_sequence: number | null;
    witness_rotation_phase: WitnessRotationPhase | null;
  };
};

export type AgentPilotDiagnosticsExport = {
  path: string;
  size_bytes: number;
  sha256: string;
};

export type WitnessRotationRecord = {
  rotation_version: string;
  rotation_id: string;
  agent_wallet_id: string;
  old_mobile_device_id: string;
  new_mobile_device_id: string;
  old_witness_epoch: string;
  new_witness_epoch: string;
  rotation_mode: "normal" | "lost_phone_recovery";
  rotation_reason: "replace_phone" | "lost_phone" | "compromised_device";
  created_at: string;
  expires_at: string;
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
    pairing_id: string;
    rotation_id: string;
    agent_wallet_id: string;
    desktop_device_id: string;
    candidate_device_id: string;
    candidate_identity_fingerprint: string;
    network_id: "testnet";
  };
  candidate_signature_hex: string;
};

export const agentWalletApi = {
  runtimeStatus: () => invoke<AgentRuntimeStatus>("agent_wallet_runtime_status"),
  companionStatus: () =>
    invoke<MobileCompanionStatus>("agent_wallet_companion_status"),
  companionPairingStatus: (walletId: string) =>
    invoke<MobilePairingProgress | null>(
      "agent_wallet_companion_pairing_status",
      { walletId },
    ),
  suggestCompanionEndpoint: () =>
    invoke<string>("agent_wallet_companion_pairing_suggest_endpoint"),
  companionDevices: (walletId: string) =>
    invoke<MobileCompanionDevice[]>("agent_wallet_companion_devices", {
      walletId,
    }),
  prepareWitnessRotation: (
    walletId: string,
    rotationId: string,
    newMobileDeviceId: string,
    mode: "normal" | "lost_phone_recovery",
    reason: "replace_phone" | "lost_phone" | "compromised_device",
  ) => invoke<WitnessRotationRecord>("agent_wallet_witness_rotation_prepare", {
    walletId,
    rotationId,
    newMobileDeviceId,
    mode,
    reason,
  }),
  witnessRotationStatus: (walletId: string) =>
    invoke<WitnessRotationRecord | null>("agent_wallet_witness_rotation_status", {
      walletId,
    }),
  cancelWitnessRotation: (walletId: string, rotationId: string) =>
    invoke<void>("agent_wallet_witness_rotation_cancel", {
      walletId,
      rotationId,
    }),
  startRotationCandidatePairing: (
    walletId: string,
    rotationId: string,
    privateLanEndpoint: string,
  ) => invoke<MobilePairingOffer>(
    "agent_wallet_rotation_candidate_pairing_start",
    { walletId, rotationId, privateLanEndpoint },
  ),
  acceptRotationCandidatePairingRequest: (
    walletId: string,
    request: MobilePairingRequest,
  ) => invoke<{
    confirmation: MobilePairingConfirmation;
    ticket: SignedRotationPairingTicket;
  }>("agent_wallet_rotation_candidate_pairing_accept_request", {
    walletId,
    request,
  }),
  completeRotationCandidatePairing: (
    walletId: string,
    encryptedAck: EncryptedCompanionFrame,
    verificationCode: string,
    signedAcceptance: SignedRotationCandidateAcceptance,
  ) => invoke<MobileCompanionDevice>(
    "agent_wallet_rotation_candidate_pairing_complete",
    { walletId, encryptedAck, verificationCode, signedAcceptance },
  ),
  revokeCompanionDevice: (walletId: string, deviceId: string) =>
    invoke<MobileCompanionDevice>(
      "agent_wallet_companion_revoke_device",
      { walletId, deviceId },
    ),  startCompanionPairing: (walletId: string, privateLanEndpoint: string) =>
    invoke<MobilePairingOffer>("agent_wallet_companion_pairing_start", {
      walletId,
      privateLanEndpoint,
    }),
  acceptCompanionPairingRequest: (
    walletId: string,
    request: MobilePairingRequest,
  ) =>
    invoke<MobilePairingConfirmation>(
      "agent_wallet_companion_pairing_accept_request",
      { walletId, request },
    ),
  completeAutomaticCompanionPairing: (
    walletId: string,
    verificationCode: string,
  ) => invoke<MobileCompanionDevice>(
    "agent_wallet_companion_pairing_complete_automatic",
    { walletId, verificationCode },
  ),
  completeCompanionPairing: (
    walletId: string,
    encryptedAck: EncryptedCompanionFrame,
    verificationCode: string,
  ) =>
    invoke("agent_wallet_companion_pairing_complete", {
      walletId,
      encryptedAck,
      verificationCode,
    }),
  cancelCompanionPairing: (walletId: string) =>
    invoke<void>("agent_wallet_companion_pairing_cancel", { walletId }),
  startCompanion: (walletId: string, privateLanBind: string) =>
    invoke<MobileCompanionStatus>("agent_wallet_companion_start", {
      walletId,
      privateLanBind,
    }),
  stopCompanion: (walletId: string) =>
    invoke<void>("agent_wallet_companion_stop", { walletId }),
  startRuntime: (walletId: string) =>
    invoke<AgentConnectorStatus>("agent_wallet_runtime_start", { walletId }),
  stopRuntime: (walletId: string) =>
    invoke<AgentConnectorStatus>("agent_wallet_runtime_stop", { walletId }),
  activatePairing: (walletId: string) =>
    invoke<PairingActivation>("agent_wallet_pairing_activate", { walletId }),
  pendingPairing: (walletId: string) =>
    invoke<PendingPairing | null>("agent_wallet_pairing_pending", { walletId }),
  approvePairing: (
    walletId: string,
    pairingId: string,
    submissionCommitment: string,
    policy: AgentPolicy,
  ) =>
    invoke<AgentRecord>("agent_wallet_pairing_approve", {
      walletId,
      pairingId,
      submissionCommitment,
      policy,
    }),
  rejectPairing: (
    walletId: string,
    pairingId: string,
    submissionCommitment: string,
  ) =>
    invoke<void>("agent_wallet_pairing_reject", {
      walletId,
      pairingId,
      submissionCommitment,
    }),
  create: (
    passphrase: string,
    networkMode: "mainnet" | "testnet",
    nodeUrl: string,
    blockOneFingerprint: string | null,
  ) =>
    invoke<CreatedAgentWallet>("agent_wallet_create", {
      passphrase,
      networkMode,
      nodeUrl,
      blockOneFingerprint,
    }),
  unlock: (walletId: string, passphrase: string) =>
    invoke<AgentWalletStatus>("agent_wallet_unlock", { walletId, passphrase }),
  lock: (walletId: string) =>
    invoke<void>("agent_wallet_lock", { walletId }),
  overview: (walletId: string) =>
    invoke<AgentWalletOverview>("agent_wallet_overview", { walletId }),
  diagnosticsPreview: (walletId: string) =>
    invoke<AgentPilotDiagnosticsPreview>("agent_wallet_pilot_diagnostics_preview", { walletId }),
  diagnosticsExport: (
    walletId: string,
    expectedPreviewSha256: string,
    destinationPath: string,
  ) =>
    invoke<AgentPilotDiagnosticsExport>("agent_wallet_pilot_diagnostics_export", {
      walletId,
      expectedPreviewSha256,
      destinationPath,
    }),
  enablePayments: (walletId: string) =>
    invoke<void>("agent_wallet_enable_payments", { walletId }),
  emergencyStop: (walletId: string) =>
    invoke<void>("agent_wallet_emergency_stop", { walletId }),
  listAgents: (walletId: string) =>
    invoke<AgentRecord[]>("agent_wallet_list_agents", { walletId }),
  getPolicy: (walletId: string, agentId: string) =>
    invoke<AgentPolicy>("agent_wallet_get_policy", { walletId, agentId }),
  updatePolicy: (walletId: string, agentId: string, policy: AgentPolicy) =>
    invoke<AgentPolicy>("agent_wallet_update_policy", { walletId, agentId, policy }),
  listActivity: (walletId: string) =>
    invoke<PaymentOperation[]>("agent_wallet_list_activity", { walletId }),
  listPendingApprovals: (walletId: string) =>
    invoke<PaymentOperation[]>("agent_wallet_list_pending_approvals", { walletId }),
  revokeAgent: (walletId: string, agentId: string) =>
    invoke<void>("agent_wallet_revoke_agent", { walletId, agentId }),
  pendingApproval: (walletId: string, operationId: string) =>
    invoke<ApprovalCommitment>("agent_wallet_pending_approval", { walletId, operationId }),
  approveDesktop: (walletId: string, approval: ApprovalCommitment) =>
    invoke<PaymentOperation>("agent_wallet_approve_desktop", { walletId, approval }),
  reject: (walletId: string, operationId: string, approvalMode: ApprovalMode) =>
    invoke<PaymentOperation>("agent_wallet_reject", { walletId, operationId, approvalMode }),
};

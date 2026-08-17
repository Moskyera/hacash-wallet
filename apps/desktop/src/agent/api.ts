import { invoke } from "@tauri-apps/api/core";
import {
  requireSealedAcknowledgement,
  type SealedAcknowledgement,
} from "./backupWarning";

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

export type AgentChannelSetupPhase =
  | "prepared"
  | "signature_may_exist"
  | "signed"
  | "submitted"
  | "awaiting_confirmations"
  | "recovery_required"
  | "confirmed";

export type AgentChannelSetupReview = {
  wallet_id: string;
  operation_id: string;
  review_commitment: string;
  expires_at: number;
  network_mode: "mainnet" | "testnet";
  hub_url: string;
  hub_address: string;
  channel_id: string;
  channel_reuse_version: number;
  deposit_units: string;
  network_fee_units: string;
  wallet_fee_units: string;
  total_debit_units: string;
  phase: AgentChannelSetupPhase;
};

export type AgentChannelClosePhase =
  | "prepared"
  | "signature_may_exist"
  | "signed"
  | "submitted"
  | "recovery_required"
  | "confirmed";

export type AgentChannelCloseReview = {
  wallet_id: string;
  operation_id: string;
  review_commitment: string;
  expires_at: number;
  network_mode: "mainnet" | "testnet";
  hub_url: string;
  hub_address: string;
  channel_id: string;
  channel_reuse_version: number;
  channel_open_height: number;
  bill_auto_number: number;
  original_agent_units: string;
  final_agent_units: string;
  network_fee_units: string;
  wallet_fee_units: string;
  phase: AgentChannelClosePhase;
};

export type AgentL2Binding = {
  schema_version: number;
  wallet_id: string;
  wallet_scope: string;
  network_mode: "mainnet" | "testnet";
  agent_address: string;
  hub_url: string;
  hub_address: string;
  channel_id: string;
  channel_reuse_version: number;
  channel_open_height: number;
  confirmed_at_height: number;
  deposit_units: string;
  bound_at: number;
  commitment_sha256: string;
  closed?: {
    transaction_hash: string;
    close_height: number;
    closed_at: number;
  };
};

export type AgentHvmNetworkBinding = {
  schema_version: number;
  network_kind: string;
  chain_id: number;
  mainnet: boolean;
  block_1_hash: string;
  node_profile_id: string;
  network_instance_id: string;
  transaction_format_version: number;
};

export type AgentHvmContractBinding = {
  schema: string;
  settlement_profile: string;
  network_mode: "mainnet" | "testnet";
  chain_id: number;
  network_instance_id: string;
  contract_address: string;
  deployment_tx_hash: string;
  deployment_height: number;
  bytecode_sha3: string;
  channel_id: string;
  reuse_version: number;
  left_address: string;
  right_hub_address: string;
  left_deposit_zhu: number;
  right_hub_deposit_zhu: number;
  challenge_blocks: number;
};

export type AgentHvmChannelBinding = {
  schema_version: number;
  wallet_id: string;
  network_mode: "mainnet" | "testnet";
  network_binding: AgentHvmNetworkBinding;
  hub_url: string;
  hub_address: string;
  binding_commitment: string;
  recovery_bundle: {
    schema: string;
    binding: AgentHvmContractBinding;
    initial_recovery_bill: {
      schema: string;
      binding_commitment: string;
      serial: number;
      left_balance_zhu: number;
      right_balance_zhu: number;
      left_signature_hex: string;
      right_signature_hex: string;
    };
  };
  activation_snapshot_commitment: string;
  minimum_required_live_blocks: number;
  minimum_required_recover_blocks: number;
  adopted_at: number;
};

export type AgentHvmRegistryBinding = {
  schema_version: 2;
  wallet_id: string;
  network_mode: "mainnet" | "testnet";
  network_binding: AgentHvmNetworkBinding;
  hub_url: string;
  hub_address: string;
  binding_commitment: string;
  recovery_bundle: {
    schema: string;
    binding: {
      schema: string;
      settlement_profile: "hpay-hvm-shared-registry-v2";
      network_mode: "mainnet" | "testnet";
      chain_id: number;
      network_instance_id: string;
      contract_address: string;
      deployment_tx_hash: string;
      deployment_height: number;
      bytecode_sha3: string;
      channel_id: string;
      reuse_version: number;
      left_address: string;
      right_hub_address: string;
      left_deposit_zhu: number;
      right_hub_deposit_zhu: number;
      challenge_blocks: number;
    };
    initial_recovery_bill: {
      schema: string;
      binding_commitment: string;
      serial: number;
      left_balance_zhu: number;
      hub_balance_zhu: number;
      left_signature_hex: string;
      hub_signature_hex: string;
    };
  };
  activation_snapshot_commitment: string;
  minimum_required_live_blocks: number;
  minimum_required_recover_blocks: number;
  adopted_at: number;
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
  trusted_mainnet_fast_pay_pilot: boolean;
  l2_binding: AgentL2Binding | null;
  hvm_channel_binding: AgentHvmChannelBinding | null;
  hvm_registry_binding: AgentHvmRegistryBinding | null;
  l2_channel_setup: AgentChannelSetupReview | null;
  l2_channel_close: AgentChannelCloseReview | null;
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
  /**
   * Owner-only, per-agent, default false. When true the agent may propose a
   * payment to a recipient that is not on `allowed_recipients`; that payment
   * still requires the same exact manual approval, and approving it never adds
   * the recipient to `allowed_recipients`. `blocked_recipients` is unaffected.
   */
  allow_unlisted_recipient_with_approval: boolean;
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

/**
 * A payment that is waiting on the paired phone, and which recovery controls
 * the core would actually accept on it right now.
 *
 * `abandonable` and `retryable` are the core's own enforcement predicates, not
 * a guess made here, so the desktop can never offer a control that is then
 * refused. Nothing in this shape ever means "witnessed": a payment that reaches
 * it is one no phone has signed for.
 */
export type StrandedWitness = {
  operation_id: string;
  agent_id: string;
  asset: string;
  amount_units: string;
  total_debit_units: string;
  recipient: string;
  /**
   * Four statuses reach this shape, and only `signed_awaiting_witness` is
   * pre-broadcast. Nothing rendered from this may describe the other three the
   * way it describes that one.
   */
  status:
    | "signed_awaiting_witness"
    | "submitted_awaiting_final_witness"
    | "broadcast_uncertain"
    | "reconciled_awaiting_final_witness";
  /** The transaction is already on the network. The money moved. */
  submitted: boolean;
  /**
   * The id of the signed transaction. It exists from signing onward, so it is
   * NOT the answer to "did the money move" - `submitted` is.
   */
  transaction_id: string | null;
  anchor_issued: boolean;
  anchor_expires_at: number | null;
  retryable: boolean;
  abandonable: boolean;
  /** `releaseDeadWitnessAnchor` would succeed right now. */
  anchor_releasable: boolean;
  /** Replacing the paired phone is available and would keep the payment. */
  phone_replacement_unblocked: boolean;
};

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

export type AgentFastPayStatus =
  | "payment_intent_created"
  | "funds_reserved"
  | "approval_requested"
  | "approved"
  | "execution_prepared"
  | "signed"
  | "submitted"
  | "awaiting_recipient"
  | "exact_retry_ready"
  | "committed"
  | "rejected"
  | "cancelled"
  | "recovery_required";

/** Exact, zero-fee Agent-only L2 operation. It can never fall back to L1. */
export type AgentFastPayOperation = {
  operation_id: string;
  hub_operation_id: string;
  agent_wallet_id: string;
  agent_id: string;
  agent_authorization_epoch: number;
  idempotency_key: string;
  request_commitment: string;
  binding_commitment: string;
  route_commitment: string;
  network_mode: "mainnet" | "testnet";
  payer: string;
  recipient: string;
  amount_units: string;
  network_fee_units: string;
  wallet_fee_units: string;
  total_debit_units: string;
  reserved_units: string;
  status: AgentFastPayStatus;
  policy_epoch: number;
  signer_epoch: number;
  emergency_epoch: number;
  approval_commitment: string | null;
  owner_authority_commitment: string | null;
  created_at: number;
  expires_at: number;
  settled_at: number | null;
};

export type AgentHvmPaymentStatus =
  | "payment_intent_created"
  | "funds_reserved"
  | "unsigned_prepared"
  | "approval_requested"
  | "approved"
  | "signing_prepared"
  | "signed"
  | "submitted"
  | "exact_retry_ready"
  | "committed"
  | "rejected"
  | "cancelled"
  | "recovery_required";

/** Exact, zero-fee Agent HVM operation. It never exposes generic signing or an L1 fallback. */
export type AgentHvmPaymentOperation = {
  operation_id: string;
  hub_operation_id: string;
  agent_wallet_id: string;
  agent_id: string;
  agent_authorization_epoch: number;
  idempotency_key: string;
  request_commitment: string;
  network_mode: "mainnet" | "testnet";
  hub_url: string;
  hub_address: string;
  binding_commitment: string;
  lease_snapshot_commitment: string | null;
  previous_bill_commitment: string | null;
  unsigned_request_commitment: string | null;
  payer: string;
  recipient: string;
  amount_units: string;
  amount_zhu: number;
  wallet_fee_zhu: number;
  hub_fee_zhu: number;
  total_debit_zhu: number;
  reserved_units: string;
  status: AgentHvmPaymentStatus;
  policy_epoch: number;
  signer_epoch: number;
  emergency_epoch: number;
  approval_commitment: string | null;
  approval_decision_commitment: string | null;
  owner_authority_commitment: string | null;
  created_at: number;
  expires_at: number;
  settled_at: number | null;
};

/**
 * One rollback-anchor witness, described by what the wallet actually keyed on.
 *
 * `signer_address` is recovered from the receipt signature and is half of the
 * identity. `hub_supplied_label` is a name the Hub typed and is never part of
 * it; it is shown labelled as such so a reader is not invited to trust it.
 */
export type AnchorWitnessRecord = {
  signer_address: string;
  witness_instance_id: string;
  hub_supplied_label: string;
  witness_epoch: number;
  first_seen_serial: number;
  last_seen_serial: number;
};

/**
 * The Hub has stopped using at least one witness that signed an earlier bill
 * on this channel, and the channel will not advance until a person answers.
 */
export type AnchorWitnessChange = {
  binding_commitment: string;
  serial: number;
  last_accepted_serial: number;
  zero_overlap: boolean;
  headline: string;
  dropped: AnchorWitnessRecord[];
  retained: AnchorWitnessRecord[];
  offered: AnchorWitnessRecord[];
};

/** The only two answers. There is deliberately no third. */
export type AnchorWitnessAnswer = "accept_new_witness_set" | "close_channel";

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
  /**
   * Present exactly when `approval_version` is "3", which is what a Testnet
   * Pilot build issues. Rust binds the two together (`ApprovalCommitment
   * ::validate` in crates/companion-protocol/src/approval.rs admits only
   * (2, None) and (3, Some)), and the whole object is sent back verbatim on
   * approval, so this must be declared rather than silently carried: a
   * commitment that loses it no longer matches the stored one.
   */
  network_binding?: {
    network_id: string;
    chain_id: number;
    genesis_identifier: string;
    node_profile_id: string;
    transaction_format_version: number;
  } | null;
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

/**
 * Which rotation escapes the core would accept right now.
 *
 * Answered by `witness_rotation_controls`
 * (crates/agent-wallet-core/src/service/companion/rotation.rs), which uses the
 * same predicates the mutating calls enforce.
 */
export type WitnessRotationControls = {
  cancellable: boolean;
  retargetable: boolean;
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

/// The four facts an owner must be told, in the core's own words. Never
/// re-worded here: a second copy of a warning is a copy that can go stale while
/// the thing it warns about does not.
export type AgentBackupWarning = {
  headline: string;
  restore_rewinds_spending: string;
  revoked_agents_return: string;
  old_phone_must_be_replaced: string;
  the_file_is_a_working_wallet: string;
};

export type AgentBackupWarnings = {
  backup: AgentBackupWarning;
  restore: AgentBackupWarning;
};

/// One tick per fact. The core refuses unless all four are true, so a screen
/// that omits one cannot complete the flow.
export type AgentBackupAcknowledgement = {
  restore_rewinds_spending: boolean;
  revoked_agents_return: boolean;
  old_phone_must_be_replaced: boolean;
  the_file_is_a_working_wallet: boolean;
};

export type AgentBackupPreview = {
  wallet_id: string;
  address: string;
  network_mode: string;
  journal_sequence: number;
  backed_up_at_unix: number;
  wallet_created_at_unix: number;
  already_present: boolean;
  warning: AgentBackupWarning;
};

export type AgentRestoreOutcome = {
  wallet_id: string;
  address: string;
  network_mode: string;
  journal_sequence: number;
  witness_phone_must_be_replaced: boolean;
  restored_active_agents: number;
};

export const agentWalletApi = {
  runtimeStatus: () => invoke<AgentRuntimeStatus>("agent_wallet_runtime_status"),
  backupWarnings: () =>
    invoke<AgentBackupWarnings>("agent_wallet_backup_warnings"),
  // THE WARNING GATE IS ON THE CALL, NOT ON THE SCREEN.
  //
  // Both of these take a `SealedAcknowledgement`, which only
  // `sealAcknowledgement` produces and only after every point of the warning the
  // owner was shown has been ticked. `requireSealedAcknowledgement` asks again at
  // runtime and throws BEFORE `invoke`, so a caller that casts past the type
  // system never reaches the core at all. A disabled button is a styling
  // decision; this is the control.
  backupCreate: (
    walletId: string,
    passphrase: string,
    acknowledgement: SealedAcknowledgement,
  ) =>
    invoke<{ document: string; warning: AgentBackupWarning }>(
      "agent_wallet_backup_create",
      {
        walletId,
        passphrase,
        acknowledgement: requireSealedAcknowledgement(acknowledgement),
      },
    ),
  backupPreview: (document: string) =>
    invoke<AgentBackupPreview>("agent_wallet_backup_preview", { document }),
  backupRestore: (
    document: string,
    passphrase: string,
    acknowledgement: SealedAcknowledgement,
  ) =>
    invoke<AgentRestoreOutcome>("agent_wallet_backup_restore", {
      document,
      passphrase,
      acknowledgement: requireSealedAcknowledgement(acknowledgement),
    }),
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
  /**
   * The payment waiting on the phone, or null when there is none.
   *
   * A read. It signs nothing, submits nothing and changes no state.
   */
  strandedWitness: (walletId: string) =>
    invoke<StrandedWitness | null>("agent_wallet_stranded_witness", {
      walletId,
    }),
  /**
   * Gives up a signed payment that no phone can witness any more.
   *
   * The reservation comes back and nothing reaches the network: the core
   * accepts this only for `signed_awaiting_witness`, which provably never was
   * submitted. The panel says what it costs before the press.
   */
  abandonStrandedWitness: (walletId: string, operationId: string) =>
    invoke<PaymentOperation>("agent_wallet_abandon_stranded_witness", {
      walletId,
      operationId,
    }),
  /**
   * Drops an anchor that expired unwitnessed out of the single pending slot.
   *
   * It moves no money, marks nothing witnessed and leaves the payment exactly
   * where it stands - status, transaction id and reservation unchanged. It is
   * the step that frees the slot so the paired phone can be replaced.
   */
  releaseDeadWitnessAnchor: (walletId: string, operationId: string) =>
    invoke<PaymentOperation>("agent_wallet_release_dead_witness_anchor", {
      walletId,
      operationId,
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
  /**
   * Which rotation escapes the core would actually accept right now.
   *
   * The desktop asks rather than guessing from the phase, so a cancel is never
   * offered on a re-targeted rotation whose old phone is already revoked, and
   * the re-target is never hidden when it is the only way out.
   */
  witnessRotationControls: (walletId: string) =>
    invoke<WitnessRotationControls>("agent_wallet_witness_rotation_controls", {
      walletId,
    }),
  /**
   * Points a stranded rotation at a different replacement phone. Discards the
   * unusable candidate's baseline and burns its witness epoch; the panel says
   * so before the press.
   */
  retargetWitnessRotation: (
    walletId: string,
    rotationId: string,
    newRotationId: string,
    newCandidateSlotId: string,
  ) => invoke<WitnessRotationRecord>("agent_wallet_witness_rotation_retarget", {
    walletId,
    rotationId,
    newRotationId,
    newCandidateSlotId,
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
    mainnetPilotAcknowledgement: string | null = null,
  ) =>
    invoke<CreatedAgentWallet>("agent_wallet_create", {
      passphrase,
      networkMode,
      nodeUrl,
      blockOneFingerprint,
      mainnetPilotAcknowledgement,
    }),
  unlock: (walletId: string, passphrase: string) =>
    invoke<AgentWalletStatus>("agent_wallet_unlock", { walletId, passphrase }),
  lock: (walletId: string) =>
    invoke<void>("agent_wallet_lock", { walletId }),
  overview: (walletId: string) =>
    invoke<AgentWalletOverview>("agent_wallet_overview", { walletId }),
  prepareFastPayChannel: (walletId: string, hubUrl: string, deposit: string) =>
    invoke<AgentChannelSetupReview>("agent_wallet_prepare_fast_pay_channel", {
      walletId,
      hubUrl,
      deposit,
    }),
  confirmFastPayChannelSetup: (
    walletId: string,
    operationId: string,
    reviewCommitment: string,
  ) =>
    invoke<AgentChannelSetupReview>("agent_wallet_confirm_fast_pay_channel_setup", {
      walletId,
      operationId,
      reviewCommitment,
    }),
  recoverFastPayChannelSetup: (walletId: string) =>
    invoke<AgentChannelSetupReview>("agent_wallet_recover_fast_pay_channel_setup", { walletId }),
  prepareFastPayChannelClose: (walletId: string) =>
    invoke<AgentChannelCloseReview>("agent_wallet_prepare_fast_pay_channel_close", { walletId }),
  confirmFastPayChannelClose: (
    walletId: string,
    operationId: string,
    reviewCommitment: string,
  ) =>
    invoke<AgentChannelCloseReview>("agent_wallet_confirm_fast_pay_channel_close", {
      walletId,
      operationId,
      reviewCommitment,
    }),
  recoverFastPayChannelClose: (walletId: string) =>
    invoke<AgentChannelCloseReview>("agent_wallet_recover_fast_pay_channel_close", { walletId }),
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
  listFastPayActivity: (walletId: string) =>
    invoke<AgentFastPayOperation[]>("agent_wallet_list_fast_pay_activity", { walletId }),
  executeApprovedFastPay: (walletId: string, operationId: string) =>
    invoke<AgentFastPayOperation>("agent_wallet_execute_approved_fast_pay", {
      walletId,
      operationId,
    }),
  reconcileFastPay: (walletId: string, operationId: string) =>
    invoke<AgentFastPayOperation>("agent_wallet_reconcile_fast_pay", {
      walletId,
      operationId,
    }),
  retryFastPayExact: (walletId: string, operationId: string) =>
    invoke<AgentFastPayOperation>("agent_wallet_retry_fast_pay_exact", {
      walletId,
      operationId,
    }),
  bindHvmChannel: (walletId: string, hubUrl: string, bindingCommitment: string) =>
    invoke<AgentHvmChannelBinding>("agent_wallet_bind_hvm_channel", {
      walletId,
      hubUrl,
      bindingCommitment,
    }),
  bindHvmRegistry: (walletId: string, hubUrl: string, bindingCommitment: string) =>
    invoke<AgentHvmRegistryBinding>("agent_wallet_bind_hvm_registry", {
      walletId,
      hubUrl,
      bindingCommitment,
    }),
  listHvmActivity: (walletId: string) =>
    invoke<AgentHvmPaymentOperation[]>("agent_wallet_list_hvm_activity", { walletId }),
  executeApprovedHvm: (walletId: string, operationId: string) =>
    invoke<AgentHvmPaymentOperation>("agent_wallet_execute_approved_hvm", {
      walletId,
      operationId,
    }),
  reconcileHvm: (walletId: string, operationId: string) =>
    invoke<AgentHvmPaymentOperation>("agent_wallet_reconcile_hvm", {
      walletId,
      operationId,
    }),
  retryHvmExact: (walletId: string, operationId: string) =>
    invoke<AgentHvmPaymentOperation>("agent_wallet_retry_hvm_exact", {
      walletId,
      operationId,
    }),
  hvmAnchorDecision: (walletId: string, operationId: string) =>
    invoke<AnchorWitnessChange | null>("agent_wallet_hvm_anchor_decision", {
      walletId,
      operationId,
    }),
  // Asks the Hub to re-anchor this channel's existing head - same serial, same
  // bill commitment, nothing newly signed - under the witness it is answering
  // with now, and adjudicates the result. This is the only route into the
  // witness ratchet on a channel whose Hub has lost its one witness and will
  // therefore never co-sign another bill; every other route needs a new bill.
  refreshHvmAnchorContinuity: (walletId: string, operationId: string) =>
    invoke<AnchorWitnessChange | null>("agent_wallet_refresh_hvm_anchor_continuity", {
      walletId,
      operationId,
    }),
  resolveHvmAnchorDecision: (
    walletId: string,
    operationId: string,
    decision: AnchorWitnessAnswer,
  ) =>
    invoke<{ resolved: boolean }>("agent_wallet_resolve_hvm_anchor_decision", {
      walletId,
      operationId,
      decision,
    }),
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

import {
  encodeCompanionAck,
  encodeCompanionRequest,
  parseCompanionAck,
  parseCompanionRequest,
  type CompanionPairingOffer,
} from "@hacash/wallet-ui";
import type {
  AgentCompanionIdentityStatus,
  AgentCompanionPendingApproval,
  AgentCompanionSnapshot,
  CompanionMessageEnvelopeView,
  CompanionPairingCompletionView,
  CompanionPairingConfirmation,
  CompanionPairingStartView,
  CompanionPongView,
  CompanionSessionView,
  CompanionStatusSnapshotView,
  CompanionStoredStateView,
  NativeActivitySummary,
  NativeAgentPolicySummary,
  NativeAgentSummary,
  NativeApprovalCommitment,
  NativeCompanionStatus,
} from "./types";

const HAC_ATOMIC_UNITS = 1_000_000n;
const MAX_U64 = 18_446_744_073_709_551_615n;
const MAX_SAFE_INTEGER = BigInt(Number.MAX_SAFE_INTEGER);
const MAX_LIST_ITEMS = 4_096;
const MAX_POLICY_RECIPIENTS = 256;
const MAX_CLOCK_SKEW_SECONDS = 60;
const AGENT_NETWORK_FEE_UNITS = 1_000n;
const MAX_PAIRING_TTL_SECONDS = 5 * 60;
const ROTATION_PHASES = new Set([
  "stable",
  "rotation_required",
  "rotation_prepared",
  "awaiting_old_witness_authorization",
  "awaiting_new_device_pairing",
  "awaiting_new_witness_baseline",
  "awaiting_rotation_completion_anchor",
  "completed",
  "blocked_by_pending_approval",
  "blocked_by_unresolved_signed_operation",
  "recovery_rotation_required",
  "rotation_recovery_required",
]);
export const MAX_COMPANION_SESSION_TTL_SECONDS = 5 * 60;
export const MAX_COMPANION_MESSAGE_TTL_SECONDS = 15 * 60;

const STORED_STATE_FIELDS = [
  "configured",
  "connected",
  "agentWalletId",
  "desktopDeviceId",
  "mobileDeviceId",
  "endpoints",
  "responseSequence",
  "pendingPairingFinalization",
  "pilotEnabled",
  "controlledRotationRequired",
  "rotationPhase",
  "hardwareIdentityRetainedOnReset",
] as const;
const SESSION_FIELDS = [
  "connected",
  "sessionId",
  "localDeviceId",
  "remoteDeviceId",
  "establishedAtUnix",
  "expiresAtUnix",
] as const;
const ENVELOPE_FIELDS = [
  "messageId",
  "sessionId",
  "senderDeviceId",
  "recipientDeviceId",
  "sequence",
  "issuedAtUnix",
  "expiresAtUnix",
] as const;
const STATUS_FIELDS = [
  "agent_wallet_id",
  "address",
  "available_units",
  "node_status",
  "reserved_units",
  "spent_today_units",
  "spent_month_units",
  "paused",
  "policy_epoch",
] as const;
const AGENT_FIELDS = ["agent_id", "display_name", "authorization"] as const;
const POLICY_FIELDS = [
  "agent_id",
  "max_per_payment_units",
  "max_daily_units",
  "max_pending_operations",
  "approval_mode",
  "permissions",
  "allowed_recipients",
  "blocked_recipients",
  "policy_epoch",
] as const;
const APPROVAL_V2_FIELDS = [
  "approval_version",
  "approval_id",
  "operation_id",
  "agent_wallet_id",
  "agent_id",
  "desktop_device_id",
  "transaction_commitment",
  "amount_units",
  "fee_units",
  "wallet_fee_units",
  "total_debit_units",
  "recipient",
  "policy_epoch",
  "challenge_nonce",
  "issued_at",
  "expires_at",
] as const;
const APPROVAL_NETWORK_BINDING_FIELDS = [
  "network_id",
  "chain_id",
  "genesis_identifier",
  "node_profile_id",
  "transaction_format_version",
] as const;
const APPROVAL_V3_FIELDS = [
  ...APPROVAL_V2_FIELDS,
  "network_binding",
] as const;
const ACTIVITY_FIELDS = [
  "activity_id",
  "description",
  "asset",
  "recipient",
  "amount_units",
  "occurred_at",
  "status",
] as const;

export function parseU64Decimal(raw: string): bigint | null {
  if (!/^(0|[1-9]\d{0,19})$/.test(raw)) return null;
  try {
    const value = BigInt(raw);
    return value <= MAX_U64 ? value : null;
  } catch {
    return null;
  }
}

function parseSafeUnixSeconds(raw: string): number | null {
  const value = parseU64Decimal(raw);
  return value !== null && value <= MAX_SAFE_INTEGER ? Number(value) : null;
}

function nowUnix(nowMilliseconds: number): number {
  if (!Number.isFinite(nowMilliseconds) || nowMilliseconds < 0) {
    throw new Error("The local companion clock is unavailable.");
  }
  return Math.floor(nowMilliseconds / 1_000);
}

function validateFreshWindow(
  issuedRaw: string,
  expiresRaw: string,
  now: number,
  maxTtl: number,
  label: string,
): { issued: number; expires: number } {
  const issued = parseSafeUnixSeconds(issuedRaw);
  const expires = parseSafeUnixSeconds(expiresRaw);
  if (
    issued === null ||
    expires === null ||
    issued > now + MAX_CLOCK_SKEW_SECONDS ||
    expires <= now ||
    expires <= issued ||
    expires - issued > maxTtl
  ) {
    throw new Error(`${label} is expired or has invalid timestamps.`);
  }
  return { issued, expires };
}

export function validateFreshPairingOffer(
  offer: CompanionPairingOffer,
  nowMilliseconds = Date.now(),
): CompanionPairingOffer {
  const now = nowUnix(nowMilliseconds);
  validateFreshWindow(
    offer.issued_at,
    offer.expires_at,
    now,
    MAX_PAIRING_TTL_SECONDS,
    "The pairing offer",
  );
  if (
    offer.protocol_version !== "1" ||
    !offer.pairing_id ||
    !offer.agent_wallet_id ||
    !offer.desktop_device_id ||
    offer.lan_endpoints.length === 0
  ) {
    throw new Error("The pairing offer is incomplete.");
  }
  return offer;
}

export function validatePairingStart(
  view: CompanionPairingStartView,
  offer: CompanionPairingOffer,
  nowMilliseconds = Date.now(),
): CompanionPairingStartView {
  const request = parseCompanionRequest(
    encodeCompanionRequest(view.request),
    offer.agent_wallet_id,
    offer.pairing_id,
  );
  const now = nowUnix(nowMilliseconds);
  validateFreshWindow(
    request.issued_at,
    request.expires_at,
    now,
    MAX_PAIRING_TTL_SECONDS,
    "The mobile pairing request",
  );
  if (
    request.desktop_device_id !== offer.desktop_device_id ||
    request.pairing_nonce !== offer.pairing_nonce ||
    request.expires_at !== offer.expires_at
  ) {
    throw new Error("The mobile pairing request does not match the offer.");
  }
  if (typeof view.automaticTransport !== "boolean") {
    throw new Error("The pairing transport state is invalid.");
  }
  const confirmation = view.confirmation
    ? validatePairingConfirmationFresh(
        view.confirmation,
        offer,
        request.mobile_device_id,
        nowMilliseconds,
      )
    : null;
  return { request, confirmation, automaticTransport: view.automaticTransport };
}

export function validatePairingConfirmationFresh(
  confirmation: CompanionPairingConfirmation,
  offer: CompanionPairingOffer,
  mobileDeviceId: string,
  nowMilliseconds = Date.now(),
): CompanionPairingConfirmation {
  const now = nowUnix(nowMilliseconds);
  validateFreshWindow(
    confirmation.issued_at,
    confirmation.expires_at,
    now,
    MAX_PAIRING_TTL_SECONDS,
    "The desktop pairing confirmation",
  );
  if (
    confirmation.protocol_version !== "1" ||
    confirmation.pairing_id !== offer.pairing_id ||
    confirmation.agent_wallet_id !== offer.agent_wallet_id ||
    confirmation.desktop_device_id !== offer.desktop_device_id ||
    confirmation.mobile_device_id !== mobileDeviceId ||
    confirmation.expires_at !== offer.expires_at ||
    !/^\d{6}$/.test(confirmation.verification_code)
  ) {
    throw new Error("The desktop confirmation does not match this pairing.");
  }
  return confirmation;
}

export function validatePairingCompletion(
  view: CompanionPairingCompletionView,
  confirmation: CompanionPairingConfirmation,
  nowMilliseconds = Date.now(),
): CompanionPairingCompletionView {
  if (
    view.agentWalletId !== confirmation.agent_wallet_id ||
    view.desktopDeviceId !== confirmation.desktop_device_id ||
    view.mobileDeviceId !== confirmation.mobile_device_id
  ) {
    throw new Error("The encrypted acknowledgement scope is invalid.");
  }
  const ack = parseCompanionAck(
    encodeCompanionAck(view.encryptedAck),
    confirmation.session_id,
    confirmation.mobile_device_id,
    confirmation.desktop_device_id,
  );
  const now = nowUnix(nowMilliseconds);
  const { expires } = validateFreshWindow(
    ack.issued_at,
    ack.expires_at,
    now,
    MAX_PAIRING_TTL_SECONDS,
    "The encrypted acknowledgement",
  );
  if (parseU64Decimal(ack.sequence) === 0n || expires > Number(confirmation.expires_at)) {
    throw new Error("The encrypted acknowledgement lifetime is invalid.");
  }
  return { ...view, encryptedAck: ack };
}

export function validatedIdentityStatus(
  value: AgentCompanionIdentityStatus,
): AgentCompanionIdentityStatus {
  const fields: Array<keyof AgentCompanionIdentityStatus> = [
    "platformSupported",
    "configured",
    "ready",
    "hardwareBacked",
    "strongBoxBacked",
    "authenticationEnforcedBySecureHardware",
    "authPerUse",
  ];
  if (
    fields.some((field) => typeof value[field] !== "boolean") ||
    typeof value.keySecurityLevel !== "string"
  ) {
    throw new Error("The mobile companion identity response is invalid.");
  }
  return value;
}

export function validatedStoredState(
  value: CompanionStoredStateView,
): CompanionStoredStateView {
  const record = exactObject(value, STORED_STATE_FIELDS, "companion state");
  requireBoolean(record, "configured");
  requireBoolean(record, "connected");
  requireBoolean(record, "pendingPairingFinalization");
  requireBoolean(record, "pilotEnabled");
  requireBoolean(record, "controlledRotationRequired");
  const rotationPhase = optionalNonemptyString(record.rotationPhase);
  if (rotationPhase !== null && !ROTATION_PHASES.has(rotationPhase)) {
    throw new Error("The companion rotation phase is invalid.");
  }
  requireBoolean(record, "hardwareIdentityRetainedOnReset");
  const endpoints = requireStringArray(record, "endpoints", false);
  const responseSequence = optionalDecimal(record.responseSequence);
  const agentWalletId = optionalNonemptyString(record.agentWalletId);
  const desktopDeviceId = optionalNonemptyString(record.desktopDeviceId);
  const mobileDeviceId = optionalNonemptyString(record.mobileDeviceId);
  const configured = record.configured as boolean;
  if (
    record.hardwareIdentityRetainedOnReset !== true ||
    (configured &&
      (!agentWalletId ||
        !desktopDeviceId ||
        !mobileDeviceId ||
        endpoints.length === 0 ||
        responseSequence === null)) ||
    (!configured &&
      (record.connected === true ||
        agentWalletId !== null ||
        desktopDeviceId !== null ||
        mobileDeviceId !== null ||
        rotationPhase !== null ||
        endpoints.length !== 0 ||
        responseSequence !== null))
  ) {
    throw new Error("The stored companion state is inconsistent.");
  }
  return value;
}

export function validatedSession(
  value: CompanionSessionView,
  state: CompanionStoredStateView,
  nowMilliseconds = Date.now(),
): CompanionSessionView {
  const record = exactObject(value, SESSION_FIELDS, "companion session");
  const sessionId = requireNonemptyString(record, "sessionId");
  const localDeviceId = requireNonemptyString(record, "localDeviceId");
  const remoteDeviceId = requireNonemptyString(record, "remoteDeviceId");
  const now = nowUnix(nowMilliseconds);
  validateFreshWindow(
    requireDecimal(record, "establishedAtUnix"),
    requireDecimal(record, "expiresAtUnix"),
    now,
    MAX_COMPANION_SESSION_TTL_SECONDS,
    "The companion session",
  );
  if (
    record.connected !== true ||
    !sessionId ||
    !state.configured ||
    localDeviceId !== state.mobileDeviceId ||
    remoteDeviceId !== state.desktopDeviceId
  ) {
    throw new Error("The companion session scope is invalid.");
  }
  return value;
}

export function validatePong(
  value: CompanionPongView,
  session: CompanionSessionView,
  nowMilliseconds = Date.now(),
): CompanionPongView {
  const record = exactObject(value, ["envelope", "pong"], "companion pong");
  if (record.pong !== true) throw new Error("The desktop did not return pong.");
  validateEnvelope(
    record.envelope as CompanionMessageEnvelopeView,
    session,
    nowUnix(nowMilliseconds),
  );
  return value;
}

export function validateCompanionStatusSnapshot(
  value: CompanionStatusSnapshotView,
  session: CompanionSessionView,
  state: CompanionStoredStateView,
  nowMilliseconds = Date.now(),
): AgentCompanionSnapshot {
  const record = exactObject(
    value,
    ["envelope", "status", "agents", "policies", "approvals", "activity"],
    "companion snapshot",
  );
  const now = nowUnix(nowMilliseconds);
  const envelope = validateEnvelope(
    record.envelope as CompanionMessageEnvelopeView,
    session,
    now,
  );
  const status = validateStatus(record.status as NativeCompanionStatus, state);
  const agents = validateAgents(record.agents);
  const policies = validatePolicies(record.policies, agents);
  const approvals = validateApprovals(
    record.approvals,
    status,
    state,
    now,
  );
  const activity = validateActivity(record.activity);

  const snapshot: AgentCompanionSnapshot = {
    pilotEnabled: state.pilotEnabled,
    session: {
      state: "authenticated",
      sessionId: session.sessionId,
      mobileDeviceId: session.localDeviceId,
      desktopDeviceId: session.remoteDeviceId,
      establishedAtUnix: session.establishedAtUnix,
      expiresAtUnix: session.expiresAtUnix,
      snapshotIssuedAtUnix: envelope.issuedAtUnix,
      snapshotExpiresAtUnix: envelope.expiresAtUnix,
      messageId: envelope.messageId,
      sequence: envelope.sequence,
    },
    wallet: {
      walletId: status.agent_wallet_id,
      address: status.address,
      availableUnits: status.available_units,
      reservedUnits: status.reserved_units,
      spentTodayUnits: status.spent_today_units,
      spentMonthUnits: status.spent_month_units,
      nodeStatus: status.node_status,
      paused: status.paused,
      policyEpoch: status.policy_epoch,
    },
    agents: agents.map((agent) => ({
      agentId: agent.agent_id,
      displayName: agent.display_name,
      authorization: agent.authorization,
    })),
    policies: policies.map((policy) => ({
      agentId: policy.agent_id,
      maximumPerRequestUnits: policy.max_per_payment_units,
      maximumPerDayUnits: policy.max_daily_units,
      maximumPendingOperations: policy.max_pending_operations,
      approvalMode: policy.approval_mode,
      permissions: policy.permissions,
      allowedRecipients: policy.allowed_recipients,
      blockedRecipients: policy.blocked_recipients,
      policyEpoch: policy.policy_epoch,
    })),
    pendingApprovals: approvals.map(mapApproval),
    activity: activity.map((item) => ({
      activityId: item.activity_id,
      description: item.description,
      asset: item.asset,
      recipient: item.recipient,
      amountUnits: item.amount_units,
      occurredAtUnix: item.occurred_at,
      status: item.status,
    })),
  };
  if (!authenticatedSnapshot(snapshot, nowMilliseconds)) {
    throw new Error("The companion snapshot failed final validation.");
  }
  return snapshot;
}

function validateEnvelope(
  value: CompanionMessageEnvelopeView,
  session: CompanionSessionView,
  now: number,
): CompanionMessageEnvelopeView {
  const record = exactObject(value, ENVELOPE_FIELDS, "companion envelope");
  const issuedRaw = requireDecimal(record, "issuedAtUnix");
  const expiresRaw = requireDecimal(record, "expiresAtUnix");
  const { expires } = validateFreshWindow(
    issuedRaw,
    expiresRaw,
    now,
    MAX_COMPANION_MESSAGE_TTL_SECONDS,
    "The companion message",
  );
  const sessionExpiry = parseSafeUnixSeconds(session.expiresAtUnix);
  if (
    requireNonemptyString(record, "messageId").length === 0 ||
    requireNonemptyString(record, "sessionId") !== session.sessionId ||
    requireNonemptyString(record, "senderDeviceId") !== session.remoteDeviceId ||
    requireNonemptyString(record, "recipientDeviceId") !== session.localDeviceId ||
    parseU64Decimal(requireDecimal(record, "sequence")) === 0n ||
    sessionExpiry === null ||
    expires > sessionExpiry
  ) {
    throw new Error("The companion message scope is invalid.");
  }
  return value;
}

function validateStatus(
  value: NativeCompanionStatus,
  state: CompanionStoredStateView,
): NativeCompanionStatus {
  const record = exactObject(value, STATUS_FIELDS, "wallet status");
  const available = record.available_units;
  if (available !== null) requireDecimal(record, "available_units");
  for (const field of [
    "reserved_units",
    "spent_today_units",
    "spent_month_units",
    "policy_epoch",
  ] as const) {
    requireDecimal(record, field);
  }
  if (
    requireNonemptyString(record, "agent_wallet_id") !== state.agentWalletId ||
    requireNonemptyString(record, "address").length === 0 ||
    requireNonemptyString(record, "node_status").length === 0 ||
    typeof record.paused !== "boolean" ||
    parseU64Decimal(record.policy_epoch as string) === 0n
  ) {
    throw new Error("The Agent Wallet status scope is invalid.");
  }
  return value;
}

function validateAgents(value: unknown): NativeAgentSummary[] {
  const items = boundedArray(value, "agents");
  const ids = new Set<string>();
  return items.map((item) => {
    const record = exactObject(item, AGENT_FIELDS, "agent summary");
    const agentId = requireNonemptyString(record, "agent_id");
    requireNonemptyString(record, "display_name");
    if (
      !["authorized", "disabled", "revoked"].includes(
        String(record.authorization),
      ) ||
      ids.has(agentId)
    ) {
      throw new Error("An Agent Wallet agent summary is invalid.");
    }
    ids.add(agentId);
    return item as NativeAgentSummary;
  });
}

function validatePolicies(
  value: unknown,
  agents: NativeAgentSummary[],
): NativeAgentPolicySummary[] {
  const items = boundedArray(value, "policies");
  const agentIds = new Set(agents.map((agent) => agent.agent_id));
  const policyAgents = new Set<string>();
  return items.map((item) => {
    const record = exactObject(item, POLICY_FIELDS, "policy summary");
    const agentId = requireNonemptyString(record, "agent_id");
    requireDecimal(record, "max_per_payment_units");
    requireDecimal(record, "max_daily_units");
    const policyEpoch = requireDecimal(record, "policy_epoch");
    const permissions = requireStringArray(record, "permissions", false);
    const allowed = requireStringArray(record, "allowed_recipients", false);
    const blocked = requireStringArray(record, "blocked_recipients", false);
    const pending = record.max_pending_operations;
    if (
      !agentIds.has(agentId) ||
      policyAgents.has(agentId) ||
      !Number.isInteger(pending) ||
      Number(pending) < 0 ||
      Number(pending) > 65_535 ||
      ![
        "desktop_manual",
        "mobile_manual",
        "either_trusted_device",
      ].includes(String(record.approval_mode)) ||
      parseU64Decimal(policyEpoch) === 0n ||
      permissions.some((permission) => !permission) ||
      allowed.length > MAX_POLICY_RECIPIENTS ||
      blocked.length > MAX_POLICY_RECIPIENTS ||
      new Set(allowed).size !== allowed.length ||
      new Set(blocked).size !== blocked.length ||
      allowed.some((recipient) => blocked.includes(recipient))
    ) {
      throw new Error("An Agent Wallet policy summary is invalid.");
    }
    policyAgents.add(agentId);
    return item as NativeAgentPolicySummary;
  });
}

function validateApprovals(
  value: unknown,
  status: NativeCompanionStatus,
  state: CompanionStoredStateView,
  now: number,
): NativeApprovalCommitment[] {
  const items = boundedArray(value, "approvals");
  const ids = new Set<string>();
  return items.map((item) => {
    const record = exactObject(
      item,
      state.pilotEnabled ? APPROVAL_V3_FIELDS : APPROVAL_V2_FIELDS,
      "approval summary",
    );
    if (state.pilotEnabled) {
      exactObject(
        record.network_binding,
        APPROVAL_NETWORK_BINDING_FIELDS,
        "approval network binding",
      );
    }
    const approvalId = requireNonemptyString(record, "approval_id");
    const approval = mapApproval(item as NativeApprovalCommitment);
    const scopeSnapshot: AgentCompanionSnapshot = {
      pilotEnabled: state.pilotEnabled,
      session: {
        state: "authenticated",
        sessionId: "scope",
        mobileDeviceId: state.mobileDeviceId ?? "",
        desktopDeviceId: state.desktopDeviceId ?? "",
        establishedAtUnix: String(now),
        expiresAtUnix: String(now + 1),
        snapshotIssuedAtUnix: String(now),
        snapshotExpiresAtUnix: String(now + 1),
        messageId: "scope",
        sequence: "1",
      },
      wallet: {
        walletId: status.agent_wallet_id,
        address: status.address,
        availableUnits: status.available_units,
        reservedUnits: status.reserved_units,
        spentTodayUnits: status.spent_today_units,
        spentMonthUnits: status.spent_month_units,
        nodeStatus: status.node_status,
        paused: status.paused,
        policyEpoch: status.policy_epoch,
      },
      agents: [],
      policies: [],
      activity: [],
      pendingApprovals: [],
    };
    if (
      ids.has(approvalId) ||
      !verifiedAgentApprovalFacts(approval, scopeSnapshot, now * 1_000)
    ) {
      throw new Error(
        "A pending approval failed the exact fee or scope invariants.",
      );
    }
    ids.add(approvalId);
    return item as NativeApprovalCommitment;
  });
}

function validateActivity(value: unknown): NativeActivitySummary[] {
  const items = boundedArray(value, "activity");
  const ids = new Set<string>();
  return items.map((item) => {
    const record = exactObject(item, ACTIVITY_FIELDS, "activity summary");
    const activityId = requireNonemptyString(record, "activity_id");
    requireNonemptyString(record, "description");
    requireNonemptyString(record, "asset");
    requireNonemptyString(record, "recipient");
    requireNonemptyString(record, "status");
    if (
      ids.has(activityId) ||
      parseU64Decimal(requireDecimal(record, "amount_units")) === 0n ||
      parseU64Decimal(requireDecimal(record, "occurred_at")) === 0n
    ) {
      throw new Error("An Agent Wallet activity summary is invalid.");
    }
    ids.add(activityId);
    return item as NativeActivitySummary;
  });
}

function mapApproval(value: NativeApprovalCommitment): AgentCompanionPendingApproval {
  return {
    approvalVersion: value.approval_version,
    approvalId: value.approval_id,
    operationId: value.operation_id,
    agentWalletId: value.agent_wallet_id,
    agentId: value.agent_id,
    desktopDeviceId: value.desktop_device_id,
    transactionCommitment: value.transaction_commitment,
    amountUnits: value.amount_units,
    feeUnits: value.fee_units,
    walletFeeUnits: value.wallet_fee_units,
    totalDebitUnits: value.total_debit_units,
    recipient: value.recipient,
    policyEpoch: value.policy_epoch,
    challengeNonce: value.challenge_nonce,
    issuedAtUnix: value.issued_at,
    expiresAtUnix: value.expires_at,
    networkBinding: value.network_binding
      ? {
          networkId: value.network_binding.network_id as "testnet",
          chainId: value.network_binding.chain_id,
          genesisIdentifier: value.network_binding.genesis_identifier,
          nodeProfileId: value.network_binding.node_profile_id,
          transactionFormatVersion:
            value.network_binding.transaction_format_version as "2",
        }
      : null,
  };
}

export function toNativeApprovalCommitment(
  approval: AgentCompanionPendingApproval,
): NativeApprovalCommitment {
  return {
    approval_version: approval.approvalVersion,
    approval_id: approval.approvalId,
    operation_id: approval.operationId,
    agent_wallet_id: approval.agentWalletId,
    agent_id: approval.agentId,
    desktop_device_id: approval.desktopDeviceId,
    transaction_commitment: approval.transactionCommitment,
    amount_units: approval.amountUnits,
    fee_units: approval.feeUnits,
    wallet_fee_units: approval.walletFeeUnits,
    total_debit_units: approval.totalDebitUnits,
    recipient: approval.recipient,
    policy_epoch: approval.policyEpoch,
    challenge_nonce: approval.challengeNonce,
    issued_at: approval.issuedAtUnix,
    expires_at: approval.expiresAtUnix,
    ...(approval.networkBinding
      ? {
          network_binding: {
            network_id: approval.networkBinding.networkId,
            chain_id: approval.networkBinding.chainId,
            genesis_identifier: approval.networkBinding.genesisIdentifier,
            node_profile_id: approval.networkBinding.nodeProfileId,
            transaction_format_version:
              approval.networkBinding.transactionFormatVersion,
          },
        }
      : {}),
  };
}

export function companionSessionExpiryMilliseconds(
  snapshot: AgentCompanionSnapshot,
): number | null {
  const expiries = [
    snapshot.session.expiresAtUnix,
    snapshot.session.snapshotExpiresAtUnix,
    ...snapshot.pendingApprovals.map((approval) => approval.expiresAtUnix),
  ].map(parseSafeUnixSeconds);
  if (expiries.some((value) => value === null)) return null;
  const expires = Math.min(...(expiries as number[]));
  return expires <= Number.MAX_SAFE_INTEGER / 1_000 ? expires * 1_000 : null;
}

export function authenticatedSnapshot(
  snapshot: AgentCompanionSnapshot | null,
  nowMilliseconds = Date.now(),
): AgentCompanionSnapshot | null {
  if (!snapshot || snapshot.session.state !== "authenticated") return null;
  let now: number;
  try {
    now = nowUnix(nowMilliseconds);
  } catch {
    return null;
  }
  const established = parseSafeUnixSeconds(snapshot.session.establishedAtUnix);
  const sessionExpires = parseSafeUnixSeconds(snapshot.session.expiresAtUnix);
  const snapshotIssued = parseSafeUnixSeconds(
    snapshot.session.snapshotIssuedAtUnix,
  );
  const snapshotExpires = parseSafeUnixSeconds(
    snapshot.session.snapshotExpiresAtUnix,
  );
  if (
    established === null ||
    sessionExpires === null ||
    snapshotIssued === null ||
    snapshotExpires === null ||
    established > now ||
    sessionExpires <= now ||
    sessionExpires <= established ||
    sessionExpires - established > MAX_COMPANION_SESSION_TTL_SECONDS ||
    snapshotIssued > now + MAX_CLOCK_SKEW_SECONDS ||
    snapshotExpires <= now ||
    snapshotExpires <= snapshotIssued ||
    snapshotExpires - snapshotIssued > MAX_COMPANION_MESSAGE_TTL_SECONDS ||
    snapshotExpires > sessionExpires ||
    typeof snapshot.pilotEnabled !== "boolean" ||
    !snapshot.session.sessionId ||
    !snapshot.session.mobileDeviceId ||
    !snapshot.session.desktopDeviceId ||
    !snapshot.session.messageId ||
    parseU64Decimal(snapshot.session.sequence) === 0n ||
    !snapshot.wallet.walletId ||
    !snapshot.wallet.address ||
    !snapshot.wallet.nodeStatus ||
    parseU64Decimal(snapshot.wallet.policyEpoch) === 0n ||
    (snapshot.wallet.availableUnits !== null &&
      parseU64Decimal(snapshot.wallet.availableUnits) === null) ||
    [
      snapshot.wallet.reservedUnits,
      snapshot.wallet.spentTodayUnits,
      snapshot.wallet.spentMonthUnits,
    ].some((value) => parseU64Decimal(value) === null) ||
    snapshot.pendingApprovals.some(
      (approval) =>
        verifiedAgentApprovalFacts(approval, snapshot, nowMilliseconds) === null,
    )
  ) {
    return null;
  }
  return snapshot;
}

export function formatHacUnits(raw: string | null): string {
  if (raw === null) return "Unavailable";
  const units = parseU64Decimal(raw);
  if (units === null) return "Unavailable";
  const whole = units / HAC_ATOMIC_UNITS;
  const fraction = (units % HAC_ATOMIC_UNITS)
    .toString()
    .padStart(6, "0")
    .replace(/0+$/, "");
  return `${whole}${fraction ? `.${fraction}` : ""} HAC`;
}

export function formatTotalDebit(
  amountUnits: string,
  networkFeeUnits: string,
): string {
  const amount = parseU64Decimal(amountUnits);
  const networkFee = parseU64Decimal(networkFeeUnits);
  if (amount === null || networkFee === null || amount > MAX_U64 - networkFee) {
    return "Unavailable";
  }
  return formatHacUnits((amount + networkFee).toString());
}

export type AgentApprovalFacts = {
  amountUnits: string;
  networkFeeUnits: string;
  walletFeeUnits: "0";
  totalDebitUnits: string;
};

export function verifiedAgentApprovalFacts(
  approval: AgentCompanionPendingApproval,
  snapshot: AgentCompanionSnapshot,
  nowMilliseconds = Date.now(),
): AgentApprovalFacts | null {
  const amount = parseU64Decimal(approval.amountUnits);
  const networkFee = parseU64Decimal(approval.feeUnits);
  const walletFee = parseU64Decimal(approval.walletFeeUnits);
  const totalDebit = parseU64Decimal(approval.totalDebitUnits);
  const version = parseU64Decimal(approval.approvalVersion);
  const expectedVersion = snapshot.pilotEnabled ? 3n : 2n;
  const binding = approval.networkBinding;
  const networkBindingValid = snapshot.pilotEnabled
    ? binding !== null &&
      binding.networkId === "testnet" &&
      Number.isSafeInteger(binding.chainId) &&
      binding.chainId > 0 &&
      binding.chainId <= 0xffff_ffff &&
      /^[0-9a-f]{64}$/.test(binding.genesisIdentifier) &&
      /^[0-9a-f]{64}$/.test(binding.nodeProfileId) &&
      binding.transactionFormatVersion === "2"
    : binding === null;
  const policyEpoch = parseU64Decimal(approval.policyEpoch);
  const issuedAt = parseSafeUnixSeconds(approval.issuedAtUnix);
  const expiresAt = parseSafeUnixSeconds(approval.expiresAtUnix);
  const walletPolicyEpoch = parseU64Decimal(snapshot.wallet.policyEpoch);
  let now: number;
  try {
    now = nowUnix(nowMilliseconds);
  } catch {
    return null;
  }
  if (
    amount === null ||
    amount === 0n ||
    networkFee !== AGENT_NETWORK_FEE_UNITS ||
    walletFee !== 0n ||
    totalDebit === null ||
    amount > MAX_U64 - networkFee ||
    totalDebit !== amount + networkFee ||
    version !== expectedVersion ||
    !networkBindingValid ||
    policyEpoch === null ||
    policyEpoch === 0n ||
    policyEpoch !== walletPolicyEpoch ||
    issuedAt === null ||
    expiresAt === null ||
    issuedAt > now + MAX_CLOCK_SKEW_SECONDS ||
    expiresAt <= now ||
    expiresAt <= issuedAt ||
    approval.agentWalletId !== snapshot.wallet.walletId ||
    approval.desktopDeviceId !== snapshot.session.desktopDeviceId ||
    !approval.approvalId ||
    !approval.operationId ||
    !approval.agentId ||
    !approval.recipient ||
    !/^[0-9a-f]{64}$/.test(approval.transactionCommitment) ||
    !/^[0-9a-f]{32}$/.test(approval.challengeNonce)
  ) {
    return null;
  }
  return {
    amountUnits: approval.amountUnits,
    networkFeeUnits: approval.feeUnits,
    walletFeeUnits: "0",
    totalDebitUnits: approval.totalDebitUnits,
  };
}

export function authorizedAgentForApproval(
  approval: AgentCompanionPendingApproval,
  snapshot: AgentCompanionSnapshot,
) {
  return snapshot.agents.find(
    (agent) =>
      agent.agentId === approval.agentId && agent.authorization === "authorized",
  ) ?? null;
}

export function shortValue(value: string): string {
  return value.length > 22
    ? `${value.slice(0, 10)}...${value.slice(-8)}`
    : value;
}

export function formatCompanionNodeStatus(value: string): string {
  if (value === "verified") return "Verified";
  if (value === "offline") return "Offline";
  if (value === "network_mismatch") return "Network mismatch";
  if (value === "balance_error") return "Balance unavailable";
  if (value === "unchecked") return "Not checked";
  if (value === "verified; companion_snapshot_limited") {
    return "Verified. Limited companion snapshot";
  }
  return "Unrecognized desktop status";
}
export function formatCompanionTime(unixSeconds: string): string {
  const value = parseSafeUnixSeconds(unixSeconds);
  if (value === null || value > Number.MAX_SAFE_INTEGER / 1_000) {
    return "Unavailable";
  }
  const date = new Date(value * 1_000);
  return Number.isNaN(date.getTime()) ? "Unavailable" : date.toLocaleString();
}

function exactObject<const T extends readonly string[]>(
  value: unknown,
  fields: T,
  label: string,
): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`The ${label} has an invalid shape.`);
  }
  const record = value as Record<string, unknown>;
  const actual = Object.keys(record).sort();
  const expected = [...fields].sort();
  if (
    actual.length !== expected.length ||
    actual.some((field, index) => field !== expected[index])
  ) {
    throw new Error(`The ${label} contains missing or unknown fields.`);
  }
  return record;
}

function requireNonemptyString(
  record: Record<string, unknown>,
  field: string,
): string {
  const value = record[field];
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`The companion field ${field} is invalid.`);
  }
  return value;
}

function requireDecimal(
  record: Record<string, unknown>,
  field: string,
): string {
  const value = requireNonemptyString(record, field);
  if (parseU64Decimal(value) === null) {
    throw new Error(`The companion field ${field} is not a decimal u64 string.`);
  }
  return value;
}

function requireBoolean(record: Record<string, unknown>, field: string): void {
  if (typeof record[field] !== "boolean") {
    throw new Error(`The companion field ${field} is invalid.`);
  }
}

function optionalNonemptyString(value: unknown): string | null {
  if (value === null) return null;
  if (typeof value !== "string" || value.length === 0) {
    throw new Error("An optional companion identifier is invalid.");
  }
  return value;
}

function optionalDecimal(value: unknown): string | null {
  if (value === null) return null;
  if (typeof value !== "string" || parseU64Decimal(value) === null) {
    throw new Error("An optional companion sequence is invalid.");
  }
  return value;
}

function requireStringArray(
  record: Record<string, unknown>,
  field: string,
  requireItems: boolean,
): string[] {
  const value = record[field];
  if (
    !Array.isArray(value) ||
    (requireItems && value.length === 0) ||
    value.some((item) => typeof item !== "string" || item.length === 0)
  ) {
    throw new Error(`The companion field ${field} is invalid.`);
  }
  return value as string[];
}

function boundedArray(value: unknown, label: string): unknown[] {
  if (!Array.isArray(value) || value.length > MAX_LIST_ITEMS) {
    throw new Error(`The companion ${label} list is invalid.`);
  }
  return value;
}

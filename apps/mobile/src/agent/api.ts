import { invoke } from "@tauri-apps/api/core";
import type {
  AgentCompanionIdentityStatus,
  CompanionDisconnectView,
  CompanionLifecycleEvent,
  CompanionLifecycleView,
  CompanionPairingAckDeliveryView,
  CompanionPairingCancelView,
  CompanionPairingCompletionView,
  CompanionPairingConfirmation,
  CompanionPairingOffer,
  CompanionPairingStartView,
  RotationCandidatePairingCompletionView,
  SignedRotationPairingTicket,
  CompanionPilotDecisionView,
  CompanionPongView,
  CompanionResetView,
  CompanionRotationView,
  CompanionSessionView,
  CompanionStatusSnapshotView,
  CompanionStoredStateView,
  NativeApprovalCommitment,
} from "./types";

export const agentCompanionApi = {
  identityStatus: () =>
    invoke<AgentCompanionIdentityStatus>(
      "agent_wallet_companion_identity_status",
    ),
  createIdentity: () =>
    invoke<AgentCompanionIdentityStatus>(
      "agent_wallet_companion_create_identity",
    ),
  pairingStart: (offer: CompanionPairingOffer) =>
    invoke<CompanionPairingStartView>(
      "agent_wallet_companion_pairing_start",
      { offer },
    ),
  pairingRetryRequest: () =>
    invoke<CompanionPairingConfirmation>(
      "agent_wallet_companion_pairing_retry_request",
    ),  rotationPairingStart: (offer: CompanionPairingOffer) =>
    invoke<CompanionPairingStartView>(
      "agent_wallet_rotation_candidate_pairing_start",
      { offer },
    ),
  pairingCancel: () =>
    invoke<CompanionPairingCancelView>(
      "agent_wallet_companion_pairing_cancel",
    ),
  pairingConfirm: (
    confirmation: CompanionPairingConfirmation,
    humanCode: string,
  ) =>
    invoke<CompanionPairingCompletionView>(
      "agent_wallet_companion_pairing_confirm",
      { confirmation, humanCode },
    ),
  pairingDeliverAck: () =>
    invoke<CompanionPairingAckDeliveryView>(
      "agent_wallet_companion_pairing_deliver_ack",
    ),
  rotationPairingConfirm: (
    confirmation: CompanionPairingConfirmation,
    ticket: SignedRotationPairingTicket,
    humanCode: string,
  ) =>
    invoke<RotationCandidatePairingCompletionView>(
      "agent_wallet_rotation_candidate_pairing_confirm",
      { confirmation, ticket, humanCode },
    ),
  state: () =>
    invoke<CompanionStoredStateView>("agent_wallet_companion_state"),
  connect: () =>
    invoke<CompanionSessionView>("agent_wallet_companion_connect"),
  sync: () =>
    invoke<CompanionStatusSnapshotView>("agent_wallet_companion_sync"),
  decidePayment: (
    commitment: NativeApprovalCommitment,
    decision: "approve" | "reject",
  ) =>
    invoke<CompanionPilotDecisionView>(
      "agent_wallet_companion_decide_payment",
      { request: { commitment, decision } },
    ),
  ping: () => invoke<CompanionPongView>("agent_wallet_companion_ping"),
  disconnect: () =>
    invoke<CompanionDisconnectView>("agent_wallet_companion_disconnect"),
  lifecycle: (event: CompanionLifecycleEvent) =>
    invoke<CompanionLifecycleView>("agent_wallet_companion_lifecycle", {
      request: { event },
    }),
  reset: () =>
    invoke<CompanionResetView>("agent_wallet_companion_reset", {
      request: {
        confirmation: "RESET COMPANION",
        identity: "retain_hardware_identity",
      },
    }),
  rotationStep: () =>
    invoke<CompanionRotationView>("agent_wallet_companion_rotation_step"),
};

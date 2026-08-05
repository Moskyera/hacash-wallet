import { invoke } from "@tauri-apps/api/core";
import { COMPANION_DISCARD_CONSENT_PHRASE } from "./companionHeldConsent";
import type {
  AgentCompanionActivity,
  AgentCompanionIdentityStatus,
  CompanionDiscardConsentView,
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
  CompanionWitnessView,
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
  /**
   * Signs the rollback witness for a payment the owner approved on HPAY Desktop.
   *
   * The arguments are the exact facts the confirmation screen showed, so the
   * native side can record what the owner actually read before it fetches or
   * signs anything. It is not an approval: the payment is already approved, and
   * this phone's signature is the anti-rollback witness over it.
   */
  witnessPending: (operation: AgentCompanionActivity) =>
    invoke<CompanionWitnessView>("agent_wallet_companion_witness_pending", {
      request: {
        operationId: operation.activityId,
        amountUnits: operation.amountUnits,
        recipient: operation.recipient,
        status: operation.status,
      },
    }),
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
  /**
   * Retires a pairing whose Android identity this phone no longer holds.
   *
   * Separate words and a separate choice from the pairing-only reset on
   * purpose. The native side re-reads the Keystore and refuses if the key that
   * pairing is bound to is still live, so this can never be used to erase a
   * working phone's rollback memory.
   */
  retireOrphanedPairing: () =>
    invoke<CompanionResetView>("agent_wallet_companion_reset", {
      request: {
        confirmation: "RETIRE THIS PAIRING",
        identity: "replaced_hardware_identity",
      },
    }),
  /**
   * Ends this phone's intent to sign one exact payment it is still holding.
   *
   * Its own wording, distinct from both resets, because it is a different act:
   * it deletes no pairing and no witness memory, un-signs nothing, and cancels
   * nothing on the desktop. The operation id is the one the screen showed, so
   * the native side can refuse anything else.
   */
  discardHeldConsent: (operationId: string) =>
    invoke<CompanionDiscardConsentView>("agent_wallet_companion_discard_consent", {
      request: {
        confirmation: COMPANION_DISCARD_CONSENT_PHRASE,
        operationId,
      },
    }),
  rotationStep: () =>
    invoke<CompanionRotationView>("agent_wallet_companion_rotation_step"),
};

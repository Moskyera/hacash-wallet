import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  encodeCompanionConfirmation,
  encodeCompanionOffer,
  parseCompanionConfirmation,
  parseCompanionOffer,
  type CompanionPairingOffer,
} from "@hacash/wallet-ui";
import { describe, expect, it } from "vitest";
import {
  WITNESS_PENDING_ACTIVITY_STATUSES,
  authenticatedSnapshot,
  authorizedAgentForApproval,
  pendingWitnessOperation,
  companionSessionExpiryMilliseconds,
  formatCompanionNodeStatus,
  formatHacUnits,
  formatTotalDebit,
  recipientStanding,
  validateCompanionStatusSnapshot,
  validateFreshPairingOffer,
  validatePairingCompletion,
  validatePairingConfirmationFresh,
  validatePairingStart,
  validatePong,
  validatedSession,
  validatedStoredState,
  verifiedAgentApprovalFacts,
} from "./companionView";
import {
  COMPANION_REVOKED_ALTERNATIVE,
  COMPANION_REVOKED_PERMANENCE,
  COMPANION_RETIRE_PAIRING_ACTION,
  COMPANION_REVOKED_ORDER_MATTERS,
  COMPANION_REVOKED_RECOVERY_STEPS,
  COMPANION_REVOKED_RESET_DOES_NOT_HELP,
  COMPANION_REVOKED_ROUTE,
} from "./companionRevokedRecovery";
import {
  COMPANION_DISCARD_CONSENT_EFFECTS,
  COMPANION_DISCARD_CONSENT_PHRASE,
  discardedConsentNotice,
  discardedConsentOverflowNotice,
  heldConsentExplanation,
  heldConsentFacts,
} from "./companionHeldConsent";
import {
  COMPANION_CONNECT_ACTION,
  COMPANION_CREATE_IDENTITY_ACTION,
  COMPANION_EMPTY_FAILURE,
  COMPANION_OPEN_SECURITY_SETUP_ACTION,
  COMPANION_RECHECK_IDENTITY_ACTION,
  COMPANION_REFRESH_ACTION,
  COMPANION_RESET_PAIRING_ACTION,
  COMPANION_REVIEW_APPROVAL_ACTION,
  COMPANION_SCAN_QR_ACTION,
  COMPANION_SEND_CONFIRMATION_ACTION,
  COMPANION_TRY_AGAIN_ACTION,
  COMPANION_TRY_AGAIN_IS_SAFE,
  COMPANION_UNCLASSIFIED_NEXT_STEP,
  companionDesktopRefusedDevice,
  companionFailureText,
  companionPairingStateView,
  companionRevocationSuspected,
  type CompanionPairingStateInput,
} from "./companionStatus";
import {
  COMPANION_CONNECTION_SECTION_TITLE,
  COMPANION_PLATFORM_UNSUPPORTED_BODY,
  COMPANION_PLATFORM_UNSUPPORTED_ROUTE,
  COMPANION_PRIMARY_ACTION_LABELS,
  companionPageLeadsWithOwnContent,
  companionPrimaryAction,
  type AgentCompanionPage,
  type CompanionPrimaryActionInput,
} from "./companionLayout";
import { shouldRenderAgentCompanionRoot } from "./companionWindow";
import {
  COMPANION_ROTATION_PHASES,
  MAX_COMPANION_DISCARDED_CONSENTS,
} from "./types";
import { snapshotBlockedOnlyByExpiredApproval } from "./companionView";
import { scanRefusal } from "./AgentCompanionApp";
import {
  COMPANION_CONFIRM_WITNESS_ACTION,
  connectRoute,
} from "./CompanionReadOnlyPages";
import type {
  CompanionPairingCompletionView,
  CompanionPairingStartView,
  CompanionPongView,
  CompanionSessionView,
  CompanionStatusSnapshotView,
  CompanionStoredStateView,
  NativeApprovalCommitment,
} from "./types";

const AGENT_DIR = dirname(fileURLToPath(import.meta.url));
const MOBILE_SRC = join(AGENT_DIR, "..");
const WORKSPACE_ROOT = join(MOBILE_SRC, "..", "..", "..");
const NOW_SECONDS = 1_100;
const NOW_MILLISECONDS = NOW_SECONDS * 1_000;

function read(relative: string): string {
  return readFileSync(join(MOBILE_SRC, relative), "utf8");
}

function readWorkspace(relative: string): string {
  return readFileSync(join(WORKSPACE_ROOT, relative), "utf8");
}

/**
 * Source with every comment removed.
 *
 * A "this string must be gone" assertion has to look at what the owner sees.
 * The comment that records why a phrase was removed contains that phrase, so
 * without this the fix defeats its own test.
 */
function withoutComments(source: string): string {
  return source
    .replace(/\/\*[\s\S]*?\*\//g, " ")
    .replace(/(^|[^:])\/\/[^\n]*/g, "$1");
}

/** JSX wraps prose across lines, so compare on collapsed whitespace. */
function flatten(source: string): string {
  return source.replace(/\s+/g, " ");
}

/** A paired phone with no live session and no failure, unless overridden. */
function stateInput(
  overrides: Partial<CompanionPairingStateInput> = {},
): CompanionPairingStateInput {
  return {
    configured: true,
    pendingPairingFinalization: false,
    pairingInProgress: false,
    hasSession: false,
    hasTrustedSnapshot: false,
    lastError: "",
    ...overrides,
  };
}

function storedState(
  overrides: Partial<CompanionStoredStateView> = {},
): CompanionStoredStateView {
  return {
    configured: true,
    connected: true,
    agentWalletId: "agent_wallet_1",
    desktopDeviceId: "desktop_1",
    mobileDeviceId: "mobile_1",
    endpoints: ["hpay-lan://192.168.1.8:42492"],
    responseSequence: "4",
    pendingPairingFinalization: false,
    pilotEnabled: false,
    controlledRotationRequired: false,
    rotationPhase: null,
    resetBlockingPhase: null,
    pairingIdentity: "matches",
    hardwareIdentityRetainedOnReset: true,
    pendingConsent: null,
    discardedConsents: [],
    discardedConsentsDropped: "0",
    ...overrides,
  };
}

function session(
  overrides: Partial<CompanionSessionView> = {},
): CompanionSessionView {
  return {
    connected: true,
    sessionId: "session_1",
    localDeviceId: "mobile_1",
    remoteDeviceId: "desktop_1",
    establishedAtUnix: "1000",
    expiresAtUnix: "1200",
    ...overrides,
  };
}

function approval(
  overrides: Partial<NativeApprovalCommitment> = {},
): NativeApprovalCommitment {
  return {
    approval_version: "2",
    approval_id: "approval_1",
    operation_id: "operation_1",
    agent_wallet_id: "agent_wallet_1",
    agent_id: "agent_1",
    desktop_device_id: "desktop_1",
    transaction_commitment: "ab".repeat(32),
    amount_units: "1000000",
    fee_units: "1000",
    wallet_fee_units: "0",
    total_debit_units: "1001000",
    recipient: "1Recipient",
    policy_epoch: "7",
    challenge_nonce: "cd".repeat(16),
    issued_at: "1000",
    expires_at: "1120",
    ...overrides,
  };
}

function pilotBinding(
  overrides: Partial<NonNullable<NativeApprovalCommitment["network_binding"]>> = {},
): NonNullable<NativeApprovalCommitment["network_binding"]> {
  return {
    network_id: "testnet",
    chain_id: 1,
    genesis_identifier: "11".repeat(32),
    node_profile_id: "22".repeat(32),
    transaction_format_version: "2",
    ...overrides,
  };
}

function pilotApproval(
  overrides: Partial<NativeApprovalCommitment> = {},
): NativeApprovalCommitment {
  return approval({
    approval_version: "3",
    network_binding: pilotBinding(),
    ...overrides,
  });
}

function nativeSnapshot(
  overrides: Partial<CompanionStatusSnapshotView> = {},
): CompanionStatusSnapshotView {
  return {
    envelope: {
      messageId: "desktop_session_1_4",
      sessionId: "session_1",
      senderDeviceId: "desktop_1",
      recipientDeviceId: "mobile_1",
      sequence: "4",
      issuedAtUnix: "1099",
      expiresAtUnix: "1150",
    },
    status: {
      agent_wallet_id: "agent_wallet_1",
      address: "1AgentAddress",
      available_units: null,
      node_status: "offline",
      reserved_units: "20",
      spent_today_units: "30",
      spent_month_units: "40",
      paused: false,
      policy_epoch: "7",
    },
    agents: [
      {
        agent_id: "agent_1",
        display_name: "Local Assistant",
        authorization: "authorized",
      },
    ],
    policies: [
      {
        agent_id: "agent_1",
        max_per_payment_units: "5000",
        max_daily_units: "100000",
        max_pending_operations: 2,
        approval_mode: "desktop_manual",
        permissions: ["read_wallet_info"],
        allowed_recipients: ["1Recipient"],
        blocked_recipients: [],
        policy_epoch: "7",
      },
    ],
    approvals: [approval()],
    activity: [
      {
        activity_id: "activity_1",
        description: "AI inference",
        asset: "HAC",
        recipient: "1Recipient",
        amount_units: "2000",
        occurred_at: "1090",
        status: "completed",
      },
    ],
    ...overrides,
  };
}

function offer(): CompanionPairingOffer {
  return {
    protocol_version: "1",
    pairing_id: "pairing_1",
    agent_wallet_id: "agent_wallet_1",
    desktop_device_id: "desktop_1",
    desktop_ephemeral_public_key: "11".repeat(32),
    desktop_identity_public_key: `04${"22".repeat(64)}`,
    desktop_identity_fingerprint: "33".repeat(32),
    lan_endpoints: ["hpay-lan://192.168.1.8:42492"],
    pairing_nonce: "44".repeat(32),
    issued_at: "1000",
    expires_at: "1200",
  };
}

describe("mobile Agent Wallet companion boundary", () => {
  it("binds the native Agent root to its exact webview label and route", () => {
    const search = "?wallet-space=agent";
    expect(
      shouldRenderAgentCompanionRoot({
        search,
        tauriRuntime: true,
        currentWebviewLabel: "main",
      }),
    ).toBe(false);
    expect(
      shouldRenderAgentCompanionRoot({
        search,
        tauriRuntime: true,
        currentWebviewLabel: "agent-companion",
      }),
    ).toBe(true);
  });

  it("opens the Agent boundary through a private Android WebviewWindow Activity", () => {
    const spaces = read("WalletSpacesApp.tsx");
    const agentWindow = read("agent/AgentCompanionWindowApp.tsx");
    const mainCapability = read("../src-tauri/capabilities/default.json");
    const agentCapability = read("../src-tauri/capabilities/agent-companion.json");

    expect(spaces).toContain("new WebviewWindow(AGENT_COMPANION_WEBVIEW_LABEL");
    expect(spaces).toContain('activityName: "AgentCompanionActivity"');
    expect(spaces).toContain('createdByActivityName: "MainActivity"');
    expect(spaces).not.toContain("new Webview(");
    expect(agentWindow).toContain("AGENT_CLOSE_CLEANUP_GRACE_MS");
    expect(agentWindow).toContain("Promise.race");
    expect(agentWindow).toContain("requestBoundedLifecycleCleanup()");
    expect(agentWindow).toContain("agentCompanionApi.closeActivity()");
    expect(agentWindow).not.toContain("getCurrentWindow().close()");
    expect(agentWindow).not.toContain("getCurrentWebviewWindow().close()");
    expect(agentWindow).not.toContain("getCurrentWebview().close()");
    expect(mainCapability).toContain("core:webview:allow-create-webview-window");
    expect(agentCapability).not.toContain("core:window:allow-close");
    expect(agentCapability).not.toContain("allow-main-wallet");
  });

  it("validates the QR offer, native request, confirmation and encrypted ack", () => {
    const currentOffer = validateFreshPairingOffer(
      parseCompanionOffer(encodeCompanionOffer(offer())),
      NOW_MILLISECONDS,
    );
    const start: CompanionPairingStartView = {
      request: {
        protocol_version: "1",
        pairing_id: "pairing_1",
        agent_wallet_id: "agent_wallet_1",
        desktop_device_id: "desktop_1",
        mobile_device_id: "mobile_1",
        mobile_ephemeral_public_key: "55".repeat(32),
        mobile_identity_public_key: `04${"66".repeat(64)}`,
        mobile_identity_fingerprint: "77".repeat(32),
        pairing_nonce: "44".repeat(32),
        mobile_challenge: "88".repeat(32),
        issued_at: "1100",
        expires_at: "1200",
        identity_signature: "99".repeat(64),
      },
      automaticTransport: true,
    };
    expect(
      validatePairingStart(start, currentOffer, NOW_MILLISECONDS).request
        .mobile_device_id,
    ).toBe("mobile_1");

    const encodedConfirmation = encodeCompanionConfirmation({
      protocol_version: "1",
      pairing_id: "pairing_1",
      agent_wallet_id: "agent_wallet_1",
      desktop_device_id: "desktop_1",
      mobile_device_id: "mobile_1",
      desktop_challenge: "aa".repeat(32),
      verification_code: "123456",
      session_id: "pairing_session_1",
      issued_at: "1100",
      expires_at: "1200",
      desktop_identity_signature: "bb".repeat(64),
    });
    const confirmation = parseCompanionConfirmation(encodedConfirmation, {
      walletId: "agent_wallet_1",
      pairingId: "pairing_1",
      desktopDeviceId: "desktop_1",
      mobileDeviceId: "mobile_1",
    });
    expect(
      validatePairingConfirmationFresh(
        confirmation,
        currentOffer,
        "mobile_1",
        NOW_MILLISECONDS,
      ).verification_code,
    ).toBe("123456");

    const completion: CompanionPairingCompletionView = {
      encryptedAck: {
        frame_version: "1",
        session_id: "pairing_session_1",
        sender_device_id: "mobile_1",
        recipient_device_id: "desktop_1",
        sequence: "1",
        issued_at: "1100",
        expires_at: "1150",
        nonce_hex: "cc".repeat(24),
        ciphertext_hex: "dd".repeat(64),
      },
      agentWalletId: "agent_wallet_1",
      desktopDeviceId: "desktop_1",
      mobileDeviceId: "mobile_1",
    };
    expect(
      validatePairingCompletion(
        completion,
        confirmation,
        NOW_MILLISECONDS,
      ).encryptedAck.sequence,
    ).toBe("1");
  });

  it("rejects expired pairing data and cross-wallet confirmation", () => {
    expect(() =>
      validateFreshPairingOffer(offer(), 1_200_000),
    ).toThrow(/expired/i);
    const plusSixty = offer();
    plusSixty.issued_at = "1160";
    plusSixty.expires_at = "1170";
    expect(validateFreshPairingOffer(plusSixty, NOW_MILLISECONDS)).toBe(
      plusSixty,
    );
    const plusSixtyOne = { ...plusSixty, issued_at: "1161" };
    expect(() =>
      validateFreshPairingOffer(plusSixtyOne, NOW_MILLISECONDS),
    ).toThrow(/timestamps/i);
    const wrong = offer();
    wrong.agent_wallet_id = "other_wallet";
    expect(() =>
      validatePairingConfirmationFresh(
        {
          protocol_version: "1",
          pairing_id: "pairing_1",
          agent_wallet_id: "agent_wallet_1",
          desktop_device_id: "desktop_1",
          mobile_device_id: "mobile_1",
          desktop_challenge: "aa",
          verification_code: "123456",
          session_id: "session_1",
          issued_at: "1100",
          expires_at: "1200",
          desktop_identity_signature: "bb",
        },
        wrong,
        "mobile_1",
        NOW_MILLISECONDS,
      ),
    ).toThrow(/does not match/i);
  });

  it("validates state, authenticated session, pong and exact snapshot scope", () => {
    const state = validatedStoredState(storedState());
    const active = validatedSession(session(), state, NOW_MILLISECONDS);
    const snapshot = validateCompanionStatusSnapshot(
      nativeSnapshot(),
      active,
      state,
      NOW_MILLISECONDS,
    );
    expect(snapshot.wallet.availableUnits).toBeNull();
    expect(snapshot.wallet.nodeStatus).toBe("offline");
    expect(formatHacUnits(snapshot.wallet.availableUnits)).toBe("Unavailable");
    expect(authenticatedSnapshot(snapshot, NOW_MILLISECONDS)).toBe(snapshot);
    expect(companionSessionExpiryMilliseconds(snapshot)).toBe(1_120_000);

    const pong: CompanionPongView = {
      envelope: {
        messageId: "desktop_session_1_5",
        sessionId: "session_1",
        senderDeviceId: "desktop_1",
        recipientDeviceId: "mobile_1",
        sequence: "5",
        issuedAtUnix: "1100",
        expiresAtUnix: "1150",
      },
      pong: true,
    };
    expect(validatePong(pong, active, NOW_MILLISECONDS)).toBe(pong);
  });

  it("fails closed for malformed state, stale messages and scope mismatch", () => {
    expect(() =>
      validatedStoredState(
        storedState({ configured: false, connected: false }),
      ),
    ).toThrow(/inconsistent/i);
    expect(() =>
      validatedSession(
        session({ remoteDeviceId: "other_desktop" }),
        storedState(),
        NOW_MILLISECONDS,
      ),
    ).toThrow(/scope/i);
    expect(() =>
      validateCompanionStatusSnapshot(
        nativeSnapshot({
          envelope: {
            ...nativeSnapshot().envelope,
            expiresAtUnix: "1100",
          },
        }),
        session(),
        storedState(),
        NOW_MILLISECONDS,
      ),
    ).toThrow(/expired/i);
    expect(() =>
      validateCompanionStatusSnapshot(
        nativeSnapshot({
          status: {
            ...nativeSnapshot().status,
            agent_wallet_id: "other_wallet",
          },
        }),
        session(),
        storedState(),
        NOW_MILLISECONDS,
      ),
    ).toThrow(/scope/i);
  });

  it("accepts only the exact network fee and rejects every HPAY wallet fee", () => {
    const snapshot = validateCompanionStatusSnapshot(
      nativeSnapshot(),
      session(),
      storedState(),
      NOW_MILLISECONDS,
    );
    expect(
      verifiedAgentApprovalFacts(
        snapshot.pendingApprovals[0],
        snapshot,
        NOW_MILLISECONDS,
      ),
    ).toEqual({
      amountUnits: "1000000",
      networkFeeUnits: "1000",
      walletFeeUnits: "0",
      totalDebitUnits: "1001000",
    });
    expect(formatTotalDebit("1000000", "1000")).toBe("1.001 HAC");
    expect(() =>
      validateCompanionStatusSnapshot(
        nativeSnapshot({
          approvals: [
            approval({ fee_units: "999", total_debit_units: "1000999" }),
          ],
        }),
        session(),
        storedState(),
        NOW_MILLISECONDS,
      ),
    ).toThrow(/exact fee or scope invariants/i);
    expect(() =>
      validateCompanionStatusSnapshot(
        nativeSnapshot({
          approvals: [
            approval({ wallet_fee_units: "1", total_debit_units: "1001001" }),
          ],
        }),
        session(),
        storedState(),
        NOW_MILLISECONDS,
      ),
    ).toThrow(/exact fee or scope invariants/i);
  });

  it("accepts only exact V3 testnet bindings in pilot builds and preserves V2 outside pilot", () => {
    const pilotState = storedState({ pilotEnabled: true });
    const pilotSnapshot = validateCompanionStatusSnapshot(
      nativeSnapshot({ approvals: [pilotApproval()] }),
      session(),
      pilotState,
      NOW_MILLISECONDS,
    );
    expect(pilotSnapshot.pendingApprovals[0].networkBinding).toEqual({
      networkId: "testnet",
      chainId: 1,
      genesisIdentifier: "11".repeat(32),
      nodeProfileId: "22".repeat(32),
      transactionFormatVersion: "2",
    });
    expect(
      verifiedAgentApprovalFacts(
        pilotSnapshot.pendingApprovals[0],
        pilotSnapshot,
        NOW_MILLISECONDS,
      )?.walletFeeUnits,
    ).toBe("0");
    const revokedAgentSnapshot = {
      ...pilotSnapshot,
      agents: pilotSnapshot.agents.map((agent) => ({
        ...agent,
        authorization: "revoked" as const,
      })),
    };
    expect(
      authorizedAgentForApproval(
        pilotSnapshot.pendingApprovals[0],
        revokedAgentSnapshot,
      ),
    ).toBeNull();

    const invalid = [
      pilotApproval({ network_binding: pilotBinding({ network_id: "mainnet" }) }),
      pilotApproval({ network_binding: pilotBinding({ chain_id: 0 }) }),
      pilotApproval({ network_binding: pilotBinding({ chain_id: 1.5 }) }),
      pilotApproval({ network_binding: pilotBinding({ chain_id: 0x1_0000_0000 }) }),
      pilotApproval({
        network_binding: pilotBinding({ genesis_identifier: "AA".repeat(32) }),
      }),
      pilotApproval({
        network_binding: pilotBinding({ genesis_identifier: "11".repeat(31) }),
      }),
      pilotApproval({
        network_binding: pilotBinding({ node_profile_id: "zz".repeat(32) }),
      }),
      pilotApproval({
        network_binding: pilotBinding({ transaction_format_version: "1" }),
      }),
      approval({ approval_version: "3" }),
      approval(),
    ];
    for (const item of invalid) {
      expect(() =>
        validateCompanionStatusSnapshot(
          nativeSnapshot({ approvals: [item] }),
          session(),
          pilotState,
          NOW_MILLISECONDS,
        ),
      ).toThrow();
    }

    expect(() =>
      validateCompanionStatusSnapshot(
        nativeSnapshot({ approvals: [pilotApproval()] }),
        session(),
        storedState(),
        NOW_MILLISECONDS,
      ),
    ).toThrow();
  });
  it("maps protocol node states to stable human labels", () => {
    expect(formatCompanionNodeStatus("network_mismatch")).toBe("Network mismatch");
    expect(formatCompanionNodeStatus("balance_error")).toBe("Balance unavailable");
    expect(formatCompanionNodeStatus("verified; companion_snapshot_limited")).toBe(
      "Verified. Limited companion snapshot",
    );
    expect(formatCompanionNodeStatus("future_status")).toBe(
      "Unrecognized desktop status",
    );
  });
  it("expires read-only data without converting unavailable balances to zero", () => {
    const snapshot = validateCompanionStatusSnapshot(
      nativeSnapshot(),
      session(),
      storedState(),
      NOW_MILLISECONDS,
    );
    expect(authenticatedSnapshot(snapshot, 1_120_000)).toBeNull();
    expect(formatHacUnits(null)).toBe("Unavailable");
    expect(formatHacUnits("0")).toBe("0 HAC");
    expect(formatHacUnits("18446744073709551616")).toBe("Unavailable");
  });

  it("keeps the Agent webview command surface exact and typed", () => {
    const api = read("agent/api.ts");
    const pairingPanel = read("agent/CompanionPairingPanel.tsx");
    expect(pairingPanel).toContain("Cancel pending connection");
    const commands = new Set(
      [...api.matchAll(/"(agent_wallet_companion_[a-z_]+)"/g)].map(
        (match) => match[1],
      ),
    );
    expect(commands).toEqual(
      new Set([
        "agent_wallet_companion_close_activity",
        "agent_wallet_companion_identity_status",
        "agent_wallet_companion_create_identity",
        "agent_wallet_companion_pairing_start",
        "agent_wallet_companion_pairing_retry_request",
        "agent_wallet_companion_pairing_deliver_ack",
        "agent_wallet_companion_pairing_cancel",
        "agent_wallet_companion_pairing_confirm",
        "agent_wallet_companion_state",
        "agent_wallet_companion_connect",
        "agent_wallet_companion_sync",
        "agent_wallet_companion_ping",
        "agent_wallet_companion_disconnect",
        "agent_wallet_companion_lifecycle",
        "agent_wallet_companion_reset",
        "agent_wallet_companion_discard_consent",
        "agent_wallet_companion_pending_fast_pay",
        "agent_wallet_companion_decide_fast_pay",
        "agent_wallet_companion_pending_hvm_fast_pay",
        "agent_wallet_companion_decide_hvm_fast_pay",
        "agent_wallet_companion_decide_payment",
        "agent_wallet_companion_witness_pending",
        "agent_wallet_companion_rotation_step",
      ]),
    );
    for (const forbidden of [
      "wallet_send",
      "wallet_private",
      "export_private",
      "agent_wallet_approve",
      "agent_wallet_reject",
      "agent_wallet_emergency",
      "signApproval",
      "signAdmin",
      "WebSocket",
      "EventSource",
      "fetch(",
      "l2_",
    ]) {
      expect(api).not.toContain(forbidden);
    }
  });

  it("renders dense companion payloads with a standard quiet zone and full-frame QR-only scanner", () => {
    const qr = readWorkspace("packages/wallet-ui/src/CompanionQr.tsx");
    const desktopCss = readWorkspace("apps/desktop/src/agent/agent-wallet.css");
    const mobileCss = read("agent/agent-wallet.css");
    const app = read("agent/AgentCompanionApp.tsx");
    const pairingPanel = read("agent/CompanionPairingPanel.tsx");

    expect(qr).toContain("const QR_RENDER_SIZE = 1024");
    expect(qr).toContain("const QR_QUIET_ZONE_MODULES = 4");
    expect(qr).toContain("Html5QrcodeSupportedFormats.QR_CODE");
    expect(qr).toContain("useBarCodeDetectorIfSupported: false");
    expect(qr).not.toContain("qrbox:");
    expect(qr).toContain("const REAR_CAMERA_CONSTRAINTS: MediaTrackConstraints");
    expect(qr).toContain('width: { ideal: 1920 }');
    expect(qr).toContain('{ facingMode: "environment" },');
    expect(qr).toContain("videoConstraints: REAR_CAMERA_CONSTRAINTS");
    expect(app).toContain("Waiting for Android security approval");
    expect(qr).toContain("maxLength={MAX_COMPANION_QR_TEXT_CHARS}");
    expect(qr).toContain("The pairing payload is too large.");
    expect(qr).toContain("scanFile(file, false)");
    expect(qr).toContain("const MAX_QR_IMAGE_BYTES = 8 * 1024 * 1024");
    expect(qr).toContain("navigator.clipboard.writeText(value)");
    expect(qr).toContain("navigator.share");
    expect(qr).toContain("Camera not available?");
    expect(qr).toContain("Choose a QR image");
    expect(app).toContain("await agentCompanionApi.pairingCancel()");
    expect(app).toContain("setPairing(null)");
    // The expiry copy now says what an owner needs: that nothing was paired,
    // nothing was spent, and exactly where the next code comes from.
    const expiredCopy = flatten(pairingPanel);
    expect(expiredCopy).toContain("This pairing code ran out of time");
    expect(expiredCopy).toContain("nothing was paired and nothing was spent");
    expect(expiredCopy).toContain("run Pair a phone and scan the new QR code");
    expect(pairingPanel).toContain("disabled={busy || expired");
    expect(pairingPanel).toContain("Yes, the codes match");
    expect(qr).toContain('const [scannerError, setScannerError] = useState("")');
    expect(qr).toContain("The camera could not start. Close any other camera app and try again.");
    expect(qr).not.toContain('onError("Camera access is unavailable.');
    expect(desktopCss).toContain(".agent-qr-file-input");
    expect(mobileCss).toContain(".agent-qr-file-input");
    expect(desktopCss).toContain("width: min(420px, 100%)");
    expect(mobileCss).toContain("width: min(330px, 100%)");
  });

  it("keeps connection and safe testnet approval actions discoverable on every mobile tab", () => {
    const app = read("agent/AgentCompanionApp.tsx");
    const session = read("agent/useCompanionSession.ts");
    const panel = read("agent/CompanionPairingPanel.tsx");
    const pages = read("agent/CompanionReadOnlyPages.tsx");
    const css = read("agent/agent-wallet.css");

    // The connection block is built once, for every tab, and placed by
    // companionBlockOrder rather than by the tab that happens to be open.
    expect(app).toContain("const connectionBlock = companion.stored?.configured ? (");
    expect(app).not.toContain('companion.stored?.configured && page === "overview" ? (\n          <CompanionConnectionPanel');
    expect(app).toContain("agent-nav-badge");
    expect(app).toContain('onOpenActivity={() => setPage("activity")}');
    expect(session).toContain("const autoConnectAttempted = useRef(false)");
    expect(session).toContain("void connectAndSync()");
    expect(panel).toContain("Testnet approval phone");
    expect(panel).not.toContain('<span className="agent-state-pill">Read only</span>');
    // The label moved into companionStatus so one string is both the button
    // and whatever copy names it. The button is still there and still reads
    // exactly the same to the owner.
    expect(pages).toContain("{COMPANION_REVIEW_APPROVAL_ACTION}");
    expect(COMPANION_REVIEW_APPROVAL_ACTION).toBe("Review exact request");
    expect(pages).toContain("Approve exact testnet payment");
    expect(pages).toContain("Reject request");
    expect(pages).toContain('value={approval.recipient}');
    expect(pages).toContain('value={requestingAgent.agentId}');
    expect(pages).toContain("authorizedAgentForApproval(approval, snapshot)");
    // The review says outright when the address is one the desktop owner has
    // never vetted, and prints it in full rather than shortened.
    expect(pages).toContain("recipientStanding(approval, snapshot)");
    expect(pages).toContain(
      "New recipient. This address is not on this agent's allowlist.",
    );
    expect(pages).toContain('<code className="agent-exact-address">{approval.recipient}</code>');
    expect(css).toContain(".agent-exact-address");
    expect(pages).toContain("Emergency stop is currently available from HPAY Desktop");
    expect(pages).not.toContain('aria-label="Desktop-only approvals"');
    expect(css).toContain(".agent-nav-badge");
    expect(css).toContain(".agent-approval-review");
  });

  it("names an approval recipient that is not on the requesting agent's allowlist", () => {
    const snapshot = validateCompanionStatusSnapshot(
      nativeSnapshot(),
      session(),
      storedState(),
      NOW_MILLISECONDS,
    );
    expect(snapshot.policies[0].allowedRecipients).toEqual(["1Recipient"]);
    expect(recipientStanding(snapshot.pendingApprovals[0], snapshot)).toBe(
      "allowlisted",
    );

    const unlisted = validateCompanionStatusSnapshot(
      nativeSnapshot({
        approvals: [approval({ recipient: "1NewDeveloper" })],
      }),
      session(),
      storedState(),
      NOW_MILLISECONDS,
    );
    expect(recipientStanding(unlisted.pendingApprovals[0], unlisted)).toBe(
      "not_on_allowlist",
    );

    // A snapshot with no policy for the requesting agent must never read as
    // vetted. It reads as unchecked.
    expect(
      recipientStanding(unlisted.pendingApprovals[0], {
        ...unlisted,
        policies: [],
      }),
    ).toBe("unverified");
  });

  it("keeps the pilot status permanent, accurate and free of mojibake", () => {
    const app = read("agent/AgentCompanionApp.tsx");
    const windowApp = read("agent/AgentCompanionWindowApp.tsx");
    const security = read("agent/CompanionSecurity.tsx");
    expect(app).toContain("Testnet payment pilot active");
    expect(app).toContain("Testnet payment pilot disabled");
    expect(app).toContain("Testnet payment pilot");
    expect(app).toContain('companion.stored?.pilotEnabled ? "Testnet only" : "Disabled"');
    expect(app).toContain("Only exact V3, Type 2 testnet approvals");
    expect(app).toContain('label="Companion health"');
    expect(app).toContain('label="HPAY wallet fee" value="None"');
    expect(security).toContain("No generic wallet sends, arbitrary signing or admin commands");
    expect(security).toContain("controlled desktop");
    expect(security).toContain("stored?.controlledRotationRequired");
    expect(security).toContain("Controlled witness rotation required");
    expect(security).toContain("Check and continue rotation");
    expect(security).toContain('label="Rotation phase"');
    expect(windowApp).toContain('{"\\u2304"}');
    for (const source of [app, windowApp, security]) {
      expect(source).not.toContain(String.fromCodePoint(0xfffd));
      expect(source).not.toContain(String.fromCodePoint(0x00e2));
    }
  });
});

describe("AI Agent Wallet comprehension", () => {
  it("leads a chosen tab with that tab's own content once the phone is paired", () => {
    const app = read("agent/AgentCompanionApp.tsx");

    // The notice, health card, pairing step and connection card are identical on
    // every tab and are about a screen tall. While they came first, the selected
    // page rendered below the fold and switching tabs scrolled back to the top,
    // so Agents, Rules and Activity looked like dead buttons.
    //
    // The rule is now a pure function over every block, checked exhaustively
    // in "the control a state depends on is on the first screen" below. Here
    // we only pin that the shell uses it rather than deciding order inline.
    expect(app).toContain("const blockOrder = companionBlockOrder(layout);");
    expect(app).toContain("companionBlockOrder,");
    expect(app).toContain("{blockOrder.map((id) => renderBlock(id))}");
    // Every block has exactly one rendering position, chosen by the order.
    expect(app.match(/\{blockOrder\.map/g)).toHaveLength(1);

    // The page blocks must exist once, in pageContent, and not also inline.
    expect(app.match(/page === "agents"/g)).toHaveLength(1);
    expect(app.match(/page === "rules"/g)).toHaveLength(1);
    expect(app.match(/page === "activity"/g)).toHaveLength(1);
  });

  it("tells the owner that rules and history are never sent to a phone", () => {
    const pages = read("agent/CompanionReadOnlyPages.tsx");
    const backend = readWorkspace("crates/wallet-tauri-common/src/companion_backend.rs");

    // Spending policies are blanked for every paired device, unconditionally.
    // Activity has exactly one exception, and this pins its shape: it is gated
    // on the rollback-witness permission, restricted to the statuses the
    // desktop will actually hand an anchor for, and capped at a single entry.
    // If any of that changes, the copy below becomes wrong and these
    // assertions are the reminder to rewrite it.
    const filter = backend.slice(
      backend.indexOf("fn filter_snapshot_for_permissions"),
      backend.indexOf("fn validate_inbound"),
    );
    expect(filter).toContain("policies: Vec::new()");
    expect(filter).toContain(
      "activity: witness_pending_disclosure(activity, permissions)",
    );
    expect(filter).toContain(
      "if !permissions.contains(&DevicePermission::WitnessRollbackAnchor) {",
    );
    expect(filter).toContain(
      "agent_wallet_core::WITNESS_PENDING_OPERATION_STATUS_NAMES",
    );
    expect(filter).toContain("if pending.len() == 1 {");

    expect(pages).toContain("Spending rules stay on the desktop");
    expect(pages).toContain("Spending limits are never sent to a phone");
    expect(pages).toContain("Payment history is never sent to a phone");
    expect(pages).toContain("It does not mean no payment was made.");
    // The one payment that is disclosed has its own section, and the empty
    // history note now says so rather than claiming nothing is ever shown.
    expect(pages).toContain("except for the single payment waiting on this phone's own witness");

    // An empty list previously read as "nothing happened here".
    expect(pages).not.toContain("No activity is included in the current authenticated snapshot.");
    expect(pages).not.toContain("Policy summaries are not shared by the current read-only permission set.");
  });

  it("links one owner-facing explanation from both agent interfaces", () => {
    const policy = readWorkspace("packages/wallet-ui/src/securityPolicy.ts");
    const mobileApp = read("agent/AgentCompanionApp.tsx");
    const desktopApp = readWorkspace("apps/desktop/src/agent/AgentWalletApp.tsx");
    const guide = readWorkspace("docs/agent-wallet/HOW-THE-AGENT-WALLET-WORKS.md");

    expect(policy).toContain("export const AGENT_WALLET_HOW_IT_WORKS_URL");
    expect(policy).toContain("docs/agent-wallet/HOW-THE-AGENT-WALLET-WORKS.md");

    expect(mobileApp).toContain("AGENT_WALLET_HOW_IT_WORKS_URL");
    expect(mobileApp).toContain("What is an AI Agent Wallet?");
    expect(desktopApp).toContain("AGENT_WALLET_HOW_IT_WORKS_URL");
    expect(desktopApp).toContain("How the Agent Wallet works");

    // The guide has to answer the questions the interface alone does not, and it
    // follows the plain-ASCII rule the main explanation is held to.
    expect(guide).toContain("cannot spend anything without an explicit approval");
    expect(guide).toContain("plus the network fee");
    expect(guide).toContain("rolling window of the last");
    expect(guide).toContain("Disable All Agent Payments");
    for (const character of guide) {
      expect(character.codePointAt(0)).toBeLessThan(128);
    }
  });

  it("says what an Agent Wallet is before asking the owner to pair one", () => {
    const app = read("agent/AgentCompanionApp.tsx");
    const hero = app.slice(app.indexOf("Connect your AI Agent Wallet"));

    expect(hero).toContain("a software agent can");
    expect(hero).toContain("under limits you set");
    expect(hero).toContain("cannot spend anything without your approval");
  });
});

describe("Protocol v3 policy and emergency wording", () => {
  it("describes the per-request cap as the total debit the core actually checks", () => {
    const pages = read("agent/CompanionReadOnlyPages.tsx");
    const enforcement = readWorkspace("crates/agent-wallet-core/src/service/payment.rs");

    // validate_policy_for_request compares total_debit, not the payment amount.
    expect(enforcement).toContain("if total_debit > policy.max_per_payment_units");
    expect(pages).toContain("Maximum total debit per request");
    expect(pages).toContain("includes the payment amount and the Hacash network");
    expect(pages).not.toContain('label="Maximum per request"');
  });

  it("describes the daily cap as the rolling window the core actually uses", () => {
    const pages = read("agent/CompanionReadOnlyPages.tsx");
    const enforcement = readWorkspace("crates/agent-wallet-core/src/service/payment.rs");

    expect(enforcement).toContain("exposure_for_agent_in_window(state, &agent.agent_id, now, 86_400)");
    expect(pages).toContain("Rolling 24-hour spending limit");
    expect(pages).toContain("rolling window, not a calendar day");
    expect(pages).toContain("pending or reserved payment requests may count toward enforcement");
    expect(pages).not.toContain('label="Maximum per day"');
  });

  it("never draws a remaining allowance Protocol v3 cannot compute", () => {
    const pages = read("agent/CompanionReadOnlyPages.tsx");
    const service = readWorkspace("crates/agent-wallet-core/src/service.rs");

    // The displayed totals are wallet-wide committed spend over rolling windows,
    // which is a different quantity and scope from the enforced per-agent budget.
    expect(service).toContain("spent_today_units: spent_in_window(&state, now, 86_400)?");
    expect(service).toContain("spent_this_month_units: spent_in_window(&state, now, 31 * 86_400)?");

    expect(pages).toContain(
      "Enforceable remaining allowance is calculated on HPAY Desktop and is not",
    );
    expect(pages).toContain("Completed, last 24 hours");
    expect(pages).toContain("Completed, last 31 days");
    expect(pages).toContain("They are not the value the spending limits are");
    // The progress bar compared two different quantities and is gone.
    expect(pages).not.toContain("function BudgetProgress");
    expect(pages).not.toContain("Daily budget used");
    expect(pages).not.toContain('label="Spent today"');
  });

  it("states the real reach of the desktop emergency stop on both platforms", () => {
    const pages = read("agent/CompanionReadOnlyPages.tsx");
    const desktopOverview = readWorkspace("apps/desktop/src/agent/AgentWalletApp.tsx");
    const desktopSecurity = readWorkspace("apps/desktop/src/agent/AgentAdminPages.tsx");

    const sentence = "blocks new agent payment progress and invalidates active permits";
    const limit = "cannot reverse a transaction that has already been submitted to the network";
    // JSX wraps prose across lines, so compare on collapsed whitespace.
    expect(pages.replace(/\s+/g, " ")).toContain(sentence);
    expect(pages.replace(/\s+/g, " ")).toContain(limit);

    // The desktop now renders this warning through a shared constant so the
    // irreversibility table can assert it is never hidden behind a <details>.
    // Follow the constant: check it still says both things, AND that both
    // desktop surfaces actually render it. That is stricter than the old
    // literal scan, which passed on a sentence sitting in dead code.
    const irreversible = readWorkspace(
      "apps/desktop/src/agent/irreversibleActions.ts",
    ).replace(/\s+/g, " ");
    expect(irreversible).toContain(sentence);
    expect(irreversible).toContain(limit);
    for (const source of [desktopOverview, desktopSecurity]) {
      expect(source).toContain("{EMERGENCY_STOP_WARNING}");
    }
    expect(pages).toContain("Emergency stop is currently available from HPAY Desktop");
    // Mobile must not imply it can stop anything itself.
    expect(pages).not.toContain("Mobile Pause");
  });
});

describe("Pending pairing finalization", () => {
  it("does not attempt a connection the desktop is certain to refuse", () => {
    const hook = read("agent/useCompanionSession.ts");

    // Auto connect is suppressed while the desktop holds no admission record.
    const autoConnect = hook.slice(hook.indexOf("autoConnectAttempted.current ||") - 600);
    expect(autoConnect).toContain("stored.pendingPairingFinalization ||");
    expect(hook).toContain("stored?.pendingPairingFinalization]");

    // A manual attempt names the real blocker instead of a transport error, but
    // the explicit retry can override it: the flag is the phone's stale belief,
    // and only a real connection can settle whether the desktop is finished.
    expect(hook).toContain(
      "if (nextStored.pendingPairingFinalization && !options?.ignorePendingFinalization) {",
    );
    expect(hook).toContain("Pairing is not complete on HPAY Desktop.");
  });

  it("offers a retry that waits for the desktop instead of re-pairing", () => {
    const hook = read("agent/useCompanionSession.ts");
    const app = read("agent/AgentCompanionApp.tsx");

    const retry = hook.slice(
      hook.indexOf("const retryAfterDesktopApproval"),
      hook.indexOf("useEffect(() => {", hook.indexOf("const retryAfterDesktopApproval")),
    );
    // The phone's pending flag is its own belief and is cleared only by a
    // successful connection. Refusing the explicit retry on the strength of it
    // deadlocked a desktop that had already finished pairing.
    expect(retry).toContain("connectAndSync({ ignorePendingFinalization: true })");
    // It must not refuse on the stale flag before trying.
    expect(retry).not.toContain("current.pendingPairingFinalization");
    // It must never mint an identity, start a second pairing or clear state.
    expect(retry).not.toContain("createIdentity");
    expect(retry).not.toContain("pairingStart");
    expect(retry).not.toContain("resetCompanion");
    expect(retry).not.toContain("witness");

    expect(app).toContain("COMPANION_RETRY_AFTER_APPROVAL_ACTION");
    expect(hook).toContain("retryAfterDesktopApproval,");
  });

  it("tells the owner the desktop has not finished, and what that blocks", () => {
    const app = read("agent/AgentCompanionApp.tsx");
    const pending = app.slice(app.indexOf("Complete pairing on HPAY Desktop"));

    expect(pending).toContain("HPAY Desktop has not completed");
    // "Connected Devices" is a screen HPAY Desktop does not have. The list is
    // called Authorized mobile devices and it lives inside Pair your phone.
    expect(withoutComments(pending)).not.toContain("Connected Devices");
    expect(pending).toContain("Pair your phone");
    expect(pending).toContain("Authorized mobile devices");
    expect(pending).toContain('label="Desktop approval" value="Required"');
    expect(pending).toContain('label="Transport" value="Not authorized"');
    expect(pending).toContain('label="Witness" value="Not initialized"');
    // The old copy blamed the phone's own confirmation step.
    expect(app).not.toContain("Keep the pairing screen open on the desktop. Send the confirmation,");
  });

  it("explains an empty desktop device list as the cause of a refused phone", () => {
    const panel = readWorkspace("apps/desktop/src/agent/MobileCompanionPanel.tsx");

    // The desktop reworded this on the empty Authorized mobile devices list.
    // The fact being pinned is unchanged: a phone stuck on its pending screen
    // is not authorized here, and its connections are refused until the
    // pairing is finished ON THE DESKTOP. Pinned on the facts, not the
    // sentence, and it must still name the phone-side screens by their labels.
    const flat = panel.replace(/\s+/g, " ");
    expect(flat).toContain("No phone is authorized yet.");
    expect(flat).toContain("One last step");
    expect(flat).toContain("Complete pairing on HPAY Desktop");
    expect(flat).toContain("is not authorized here");
    expect(flat).toContain("will be refused until");
    expect(flat).toContain("is finished on this desktop");
  });
});

describe("Pairing status honesty", () => {
  it("never calls an unfinalized pairing Paired", () => {
    // The desktop holds no admission record until it finalizes, so this phone
    // is not paired in any sense the transport recognises. The health line is
    // now one derived state, so the honesty is checked on the derivation.
    const waiting = companionPairingStateView(
      stateInput({ pendingPairingFinalization: true }),
    );
    expect(waiting.state).toBe("waiting_for_desktop");
    expect(waiting.label).not.toMatch(/^Paired/);
    expect(waiting.label).toMatch(/waiting for the desktop/i);
    expect(waiting.detail).toMatch(/refuses every connection/i);

    // And the panel renders that one derived label rather than a local ternary.
    const app = read("agent/AgentCompanionApp.tsx");
    expect(app).toContain('<Detail label="Companion health" value={pairingState.label} />');
    expect(withoutComments(app)).not.toContain('"Paired, disconnected"');
  });
});

/**
 * Every distinguishable phone-to-desktop state, and the input that produces it.
 *
 * The named defeat was one status string that meant two things. These pin that
 * each state has wording nothing else uses, and that the wording says which
 * situation it is and what to do about it.
 */
describe("one status, one meaning", () => {
  const cases: Array<{
    state: string;
    input: Parameters<typeof companionPairingStateView>[0];
  }> = [
    { state: "not_paired", input: stateInput({ configured: false }) },
    {
      state: "pairing_in_progress",
      input: stateInput({ configured: false, pairingInProgress: true }),
    },
    {
      state: "waiting_for_desktop",
      input: stateInput({ pendingPairingFinalization: true }),
    },
    { state: "paired_not_connected", input: stateInput() },
    {
      state: "refused_by_desktop",
      input: stateInput({
        lastError:
          "the paired desktop closed the connection during device authentication without replying, which means it refused this device.",
      }),
    },
    {
      state: "connected_checking_data",
      input: stateInput({ hasSession: true }),
    },
    {
      state: "connected",
      input: stateInput({ hasSession: true, hasTrustedSnapshot: true }),
    },
  ];

  it("reaches every state, and never two states with one sentence", () => {
    const views = cases.map((entry) => {
      const view = companionPairingStateView(entry.input);
      expect(view.state, `wrong state for ${entry.state}`).toBe(entry.state);
      return view;
    });
    expect(new Set(views.map((view) => view.state)).size).toBe(cases.length);
    // The three strings an owner actually reads must each be unique. "Paired,
    // disconnected" for both a working phone and a never-finalized one is the
    // exact collision that cost two days.
    expect(new Set(views.map((view) => view.label)).size).toBe(cases.length);
    expect(new Set(views.map((view) => view.pill)).size).toBe(cases.length);
    expect(new Set(views.map((view) => view.detail)).size).toBe(cases.length);
  });

  it("gives every unresolved state a next action, and connected states none", () => {
    for (const entry of cases) {
      const view = companionPairingStateView(entry.input);
      if (view.state === "connected" || view.state === "connected_checking_data") {
        expect(view.nextAction, `${view.state} invents work`).toBe("");
        continue;
      }
      expect(view.nextAction.trim().length, `${view.state} has no next step`)
        .toBeGreaterThan(0);
    }
  });

  it("never reports a local fault or a timeout as a desktop refusal", () => {
    // The refusal state is the one that sends an owner to check for revocation,
    // which is permanent. It must fire only on the transport stage that really
    // proves the desktop closed the connection.
    for (const lastError of [
      "companion backend rejected the operation",
      "companion LAN operation timed out",
      "companion LAN I/O failed: connection refused",
      "",
    ]) {
      expect(
        companionPairingStateView(stateInput({ lastError })).state,
        `${lastError} was mistaken for a desktop refusal`,
      ).toBe("paired_not_connected");
    }
    expect(
      companionPairingStateView(
        stateInput({ lastError: "which means it refused this device." }),
      ).state,
    ).toBe("refused_by_desktop");
  });

  it("does not claim revocation the phone cannot possibly know", () => {
    // A revoked phone and a never-finalized phone both get a silent close, so
    // the phone genuinely cannot tell them apart. Asserting either one would be
    // a false instruction, and one of those instructions is irreversible.
    const view = companionPairingStateView(
      stateInput({ lastError: "which means it refused this device." }),
    );
    expect(view.detail).toMatch(/cannot tell/i);
    expect(view.detail).not.toMatch(/this phone was revoked\./i);
    expect(view.nextAction).toMatch(/Authorized mobile devices/);
    expect(view.nextAction).toMatch(/If it is listed as Revoked/);
  });
});

describe("no raw refusal reaches the owner", () => {
  it("replaces the Rust Display strings with a cause and a next action", () => {
    for (const raw of [
      "companion backend rejected the operation",
      "companion device authorization failed",
      "companion LAN I/O failed: early eof",
      "companion LAN operation timed out",
      "plaintext or protocol downgrade received after authentication",
    ]) {
      const text = companionFailureText(raw);
      expect(text, `${raw} was shown verbatim`).not.toBe(raw);
      expect(text.toLowerCase()).not.toContain("early eof");
      expect(text.toLowerCase()).not.toContain("lanruntimeerror");
      // Cause and next action, in a sentence an owner can act on.
      expect(text.length).toBeGreaterThan(80);
    }
  });

  it("says what the flattened backend refusal actually covers", () => {
    // LanRuntimeError::Backend is returned for a missing stored pairing, a
    // stored pairing that no longer validates, a scope mismatch, an identity
    // that will not open and a replay state that cannot be restored. The
    // sentence may name that class, and must not name one cause as the cause.
    const text = companionFailureText("companion backend rejected the operation");
    expect(text).toMatch(/nothing was sent, paid or changed/i);
    expect(text).toMatch(/identity/i);
    expect(text).toMatch(/saved pairing/i);
    expect(text).toContain(COMPANION_RESET_PAIRING_ACTION);
  });

  it("keeps an already owner-facing message and still adds where to look", () => {
    const validation = "The companion session scope is invalid.";
    const text = companionFailureText(validation);
    expect(text).toContain(validation);
    expect(text).toContain(COMPANION_UNCLASSIFIED_NEXT_STEP);
  });

  it("never leaves an empty alert, which reads as a dead button", () => {
    for (const empty of [undefined, null, "", "   ", {}, 7]) {
      expect(companionFailureText(empty)).toBe(COMPANION_EMPTY_FAILURE);
    }
    expect(COMPANION_EMPTY_FAILURE).toMatch(/nothing was paid, signed or changed/i);
  });

  it("routes every phone failure through that one funnel", () => {
    const hook = read("agent/useCompanionSession.ts");
    const app = read("agent/AgentCompanionApp.tsx");
    for (const source of [hook, app]) {
      expect(source).toContain("return companionFailureText(error);");
      // The old passthrough handed the Rust Display straight to the owner.
      expect(source).not.toContain("if (error instanceof Error) return error.message;");
    }
  });
});

describe("every button says what it does and what it costs", () => {
  it("numbers the three competing buttons on the stuck pairing screen", () => {
    const app = read("agent/AgentCompanionApp.tsx");
    const pending = app.slice(
      app.indexOf("Complete pairing on HPAY Desktop"),
      app.indexOf("<CompanionConnectionPanel", app.indexOf("</section>")),
    );
    expect(pending).toContain("<strong>Step 1 on this phone.</strong>");
    expect(pending).toContain("<strong>Step 2 on HPAY Desktop.</strong>");
    expect(pending).toContain("<strong>Step 3, back on this phone.</strong>");
    // In the only order that works, and the send button is first.
    expect(pending.indexOf("{COMPANION_SEND_CONFIRMATION_ACTION}")).toBeLessThan(
      pending.indexOf("{COMPANION_RETRY_AFTER_APPROVAL_ACTION}"),
    );
    // Each says its cost, and neither over-promises what the phone can do.
    const prose = flatten(pending);
    expect(prose).toMatch(/spends no money and signs no payment/i);
    expect(prose).toMatch(/Only the desktop can approve this phone/i);
    expect(prose).toMatch(/cannot approve this phone by itself/i);
  });

  it("names the safe reset instead of hiding it behind a destructive word", () => {
    const security = read("agent/CompanionSecurity.tsx");
    // "Begin companion reset" opened a form whose real choice was the safe one.
    expect(withoutComments(security)).not.toContain("Begin companion reset");
    expect(security).toContain("{COMPANION_RESET_PAIRING_ACTION}");
    expect(COMPANION_RESET_PAIRING_ACTION).toMatch(/pairing only/i);
    // What it keeps, what it removes, and that it cannot be undone, said before
    // the confirmation is typed rather than after the reset has happened.
    const reset = security.slice(security.indexOf("Reset this phone's pairing<"));
    expect(flatten(reset)).toMatch(/keeps this phone's secure identity/i);
    expect(flatten(reset)).toMatch(/moves no money/i);
    expect(reset).toContain("<strong>This cannot be undone.</strong>");
    expect(reset.indexOf("This cannot be undone.")).toBeLessThan(
      reset.lastIndexOf("{COMPANION_RESET_PAIRING_ACTION}"),
    );
  });

  it("says what connecting costs, and never says only Connect and sync", () => {
    const panel = read("agent/CompanionPairingPanel.tsx");
    expect(withoutComments(panel)).not.toContain("Connect and sync");
    expect(panel).toContain("{COMPANION_CONNECT_ACTION}");
    expect(flatten(panel)).toMatch(/It moves no money, signs nothing/);
    // Disconnect used to be a bare verb that could read as "unpair".
    expect(panel).toContain("Close the connection");
    expect(flatten(panel)).toMatch(/this phone stays paired/i);
  });

  it("puts the refusal beside the control that caused it", () => {
    // On a phone the alert at the top of the page is a full screen away from
    // the connect button, so a named refusal there still read as a dead button.
    const panel = read("agent/CompanionPairingPanel.tsx");
    const connection = panel.slice(panel.indexOf("export function CompanionConnectionPanel"));
    expect(connection).toContain('{lastError ? (');
    expect(connection).toContain('<p className="agent-safe-note" role="alert">{lastError}</p>');
    expect(connection.indexOf("{lastError ? (")).toBeLessThan(
      connection.indexOf("{COMPANION_CONNECT_ACTION}"),
    );

    const app = read("agent/AgentCompanionApp.tsx");
    const pending = app.slice(
      app.indexOf("Complete pairing on HPAY Desktop"),
      app.indexOf("<CompanionConnectionPanel", app.indexOf("</section>")),
    );
    expect(pending).toContain('{companion.error ? (');
    expect(pending.indexOf("{COMPANION_SEND_CONFIRMATION_ACTION}")).toBeLessThan(
      pending.indexOf("{companion.error ? ("),
    );
  });

  it("never tells the owner to tap a button the phone does not have", () => {
    const panel = read("agent/CompanionPairingPanel.tsx");
    // "tap Finish" named a desktop control that does not exist. The desktop
    // control is Yes, the codes match.
    expect(withoutComments(panel)).not.toMatch(/tap Finish/);
    expect(flatten(panel)).toMatch(/choose Yes, the codes match/);
  });
});

describe("a phone the desktop revoked", () => {
  it("says on the phone that revocation is permanent and a reset cannot undo it", () => {
    // The Android identity survives a reset on purpose, which is exactly why a
    // revoked phone stays refused. The phone has to say so.
    const commands = readWorkspace(
      "apps/mobile/src-tauri/src/agent_companion/commands.rs",
    );
    expect(commands).toContain("hardware_identity_retained_on_reset");
    expect(commands).toContain("RetainHardwareIdentity");

    expect(COMPANION_REVOKED_PERMANENCE).toMatch(/permanent/i);
    expect(COMPANION_REVOKED_PERMANENCE).toMatch(/survives a factory reset/i);
    expect(COMPANION_REVOKED_RESET_DOES_NOT_HELP).toContain(
      COMPANION_RESET_PAIRING_ACTION,
    );
    expect(COMPANION_REVOKED_RESET_DOES_NOT_HELP).toMatch(/keeps the same Android identity/i);
    expect(COMPANION_REVOKED_ROUTE).toMatch(/new mobile identity/i);
    // Never claim the revoked record itself comes back.
    expect(COMPANION_REVOKED_ROUTE).toMatch(/revoked record stays revoked/i);
  });

  it("gives the one route back in order, and names what step 3 costs", () => {
    const steps = COMPANION_REVOKED_RECOVERY_STEPS;
    expect(steps.length).toBeGreaterThanOrEqual(5);
    for (const step of steps) {
      expect(["Desktop", "Phone"]).toContain(step.where);
      expect(step.action.trim().length).toBeGreaterThan(0);
      expect(step.detail.trim().length).toBeGreaterThan(0);
    }
    // The emergency stop blocks pairing outright, so it comes first.
    expect(steps[0].detail).toMatch(/blocks the phone connection/i);
    // The step that actually replaces the key, and its real price. Enrolling a
    // new biometric invalidates hardware-bound keys, not only this one.
    const biometric = steps.find((step) => /enrol a new fingerprint/i.test(step.action));
    expect(biometric, "no step replaces the identity").toBeDefined();
    expect(biometric?.where).toBe("Phone");
    expect(biometric?.detail).toMatch(/other apps/i);
    // Only then does the app offer to mint one, which is what the code does.
    const create = steps.find((step) => /Create mobile identity/.test(step.action));
    expect(create).toBeDefined();
    expect(steps.indexOf(create!)).toBeGreaterThan(steps.indexOf(biometric!));
    // Finish on the desktop through the ordinary first pairing.
    expect(steps[steps.length - 1].where).toBe("Desktop");
    expect(steps[steps.length - 1].detail).toMatch(/first-pairing/i);
    // A second handset is the fallback; a new Agent Wallet is not a fix.
    expect(COMPANION_REVOKED_ALTERNATIVE).toMatch(/different Android phone/i);
    expect(COMPANION_REVOKED_ALTERNATIVE).toMatch(/not a fix/i);
  });

  it("is reachable on the security screen, and the reset copy no longer points the wrong way", () => {
    const security = read("agent/CompanionSecurity.tsx");
    expect(security).toContain("COMPANION_REVOKED_TITLE");
    expect(security).toContain("COMPANION_REVOKED_PERMANENCE");
    expect(security).toContain("COMPANION_REVOKED_RESET_DOES_NOT_HELP");
    expect(security).toContain("COMPANION_REVOKED_RECOVERY_STEPS.map");
    expect(security).toContain("COMPANION_REVOKED_ALTERNATIVE");
    // Not hidden behind a state the revoked owner may never reach.
    expect(security).toContain("{identity?.platformSupported ? (");
    // The old reset copy said desktop revocation was what makes a retained
    // identity pairable again. It is what makes it permanently unpairable.
    expect(security).not.toContain(
      "may\n            also need explicit desktop revocation before it can be paired again",
    );
    expect(security).not.toMatch(/need explicit desktop revocation before it can be paired again/);
    expect(security).toMatch(/cannot recover a phone the desktop has/);
  });
});

describe("a reconnect the phone's replay guard refused", () => {
  it("names the cause on the desktop instead of drawing the counter at random", () => {
    // Root cause. The phone consumes challenge_sequence as a strictly
    // increasing anti-replay counter for the companion_session_challenge scope
    // (crates/companion-protocol/src/replay.rs). The desktop used to draw an
    // independent random u64 per handshake, so once a handshake landed high,
    // 84.3% of later reconnects were refused until the scope expired.
    const desktop = readWorkspace(
      "crates/agent-wallet-core/src/service/companion/session.rs",
    );
    expect(desktop).not.toContain("random_nonzero_u64()");
    expect(desktop).toContain("next_challenge_sequence");
    expect(desktop).toContain("desktop_challenge_sequence");

    // The shared, strictly increasing source, and the contract it exists for.
    const source = readWorkspace("crates/companion-protocol/src/session/sequence.rs");
    expect(source).toContain("pub struct DesktopChallengeSequence");
    expect(source).toMatch(/strictly increasing/i);
    // The wire is untouched: no new field, no version change.
    expect(source).not.toContain("PROTOCOL_VERSION");
  });

  it("gives the refusal a named reason instead of one catch-all sentence", () => {
    const errors = readWorkspace("crates/companion-lan-runtime/src/error.rs");
    for (const named of [
      "StaleDesktopChallengeSequence",
      "ReusedDesktopChallengeNonce",
      "DesktopChallengeExpired",
      "DesktopChallengeClockOffsetTooLarge",
      "DeviceNoLongerAuthorized",
      "DesktopChallengeSignatureRejected",
      "ChallengeAddressedToAnotherDevice",
      "CompanionIdentityUnavailable",
      "CompanionStatePersistFailed",
      "CompanionScopeMismatch",
      "CompanionStateUnavailable",
      "CompanionNotPaired",
    ]) {
      expect(errors, `${named} is not defined`).toContain(named);
    }
    expect(errors).toContain("from_challenge_refusal");
    expect(errors).toContain("is_retryable_by_the_owner");

    // The phone's own backend must no longer discard the reason. Comments are
    // stripped first, because the comment that records the removed catch-all
    // necessarily quotes it.
    const backend = withoutComments(
      readWorkspace("apps/mobile/src-tauri/src/agent_companion/session.rs"),
    );
    expect(backend).not.toContain("LanRuntimeError::Backend");
    expect(backend).toContain("LanRuntimeError::from_challenge_refusal");
  });

  it("says the pairing is fine and that a reset is the wrong move", () => {
    const stale = companionFailureText(
      new Error(
        "this phone has already accepted a newer session challenge from HPAY Desktop, so this one was refused as a replay.",
      ),
    );
    expect(stale).not.toContain("companion backend rejected the operation");
    expect(stale).toMatch(/pairing is fine/i);
    expect(stale).toContain(COMPANION_TRY_AGAIN_ACTION);
    expect(stale).toMatch(/five minutes/i);
    expect(stale).toMatch(/do not reset/i);
    // Nothing moved, and the owner is told so.
    expect(stale).toMatch(/nothing was paid, signed or changed/i);

    // A refusal that really is permanent must not be dressed up as retryable.
    const revoked = companionFailureText(
      new Error("HPAY Desktop no longer authorizes this phone: its device record was revoked"),
    );
    expect(revoked).toMatch(/no retry can fix this/i);
    expect(revoked).not.toContain(COMPANION_TRY_AGAIN_ACTION);

    // The old advice for this failure was "reset the pairing", which would have
    // destroyed a working pairing to work around a five-minute timer.
    expect(stale).not.toContain(COMPANION_RESET_PAIRING_ACTION);
  });

  it("does not send an owner to their clock when the clock is not the cause", () => {
    // Both of these used to render one sentence, "expired or dated in the
    // future. Check that the date and time on both devices are correct". That
    // was the single mapping of CompanionError::Expired AND
    // CompanionError::InvalidIssuedAt onto LanRuntimeError::DesktopChallengeExpired,
    // and it is what sent a live investigation to two correct clocks.
    const expired = companionFailureText(
      new Error(
        "the session challenge from HPAY Desktop had already expired by the time this phone read it. Nothing about the pairing is wrong. Try connecting again to get a fresh one.",
      ),
    );
    const skewed = companionFailureText(
      new Error(
        "HPAY Desktop's clock is more than a minute ahead of this phone's, so this phone could not confirm the session challenge is still fresh.",
      ),
    );

    expect(expired).not.toEqual(skewed);
    for (const text of [expired, skewed]) {
      expect(text).not.toMatch(/expired or dated in the future/i);
      expect(text).toMatch(/nothing was paid, signed or changed/i);
      expect(text).toMatch(/pairing is fine/i);
      // Neither is a reason to destroy a working pairing.
      expect(text).not.toContain(COMPANION_RESET_PAIRING_ACTION);
      // Each names an action, and each action is one the owner can take.
      expect(text).toContain(COMPANION_TRY_AGAIN_ACTION);
    }

    // An expired request is cleared by asking for a new one. Saying anything
    // about clocks here would be a wrong instruction, not a harmless extra.
    expect(expired).not.toMatch(/date and time/i);
    expect(expired).toMatch(/ask for a fresh one/i);

    // A clock offset is not cleared by retrying alone, so this one names the
    // setting that does clear it and does not claim the request expired.
    expect(skewed).toMatch(/date and time/i);
    expect(skewed).toMatch(/automatically/i);
    expect(skewed).not.toMatch(/expired|ran out/i);
  });

  it("offers the retry in the one state that previously had no button", () => {
    const hook = read("agent/useCompanionSession.ts");
    const app = read("agent/AgentCompanionApp.tsx");

    // Derived from state, never from the wording, so renaming a refusal can
    // never silently remove the retry.
    expect(hook).toContain("const connectRetryAvailable =");
    expect(hook).toContain("setConnectFailed(true);");
    expect(hook).toContain("connectRetryAvailable,");
    const derived = hook.slice(
      hook.indexOf("const connectRetryAvailable ="),
      hook.indexOf("useEffect", hook.indexOf("const connectRetryAvailable =")),
    );
    expect(derived).toContain("connectFailed");
    expect(derived).toContain("stored?.configured");
    // The pending-pairing panel keeps owning its own retry.
    expect(derived).toContain("!stored?.pendingPairingFinalization");

    // The retry moved into the connection block, where the only other connect
    // button already was. Two buttons calling connectAndSync, side by side and
    // both drawn as primary, was the "which one do I need" the owner reported;
    // the surviving button still carries this exact label whenever a failure is
    // on screen, which is what every mapped failure sentence tells them to tap.
    const connectionPanel = read("agent/CompanionPairingPanel.tsx");
    expect(app).toContain("companion.connectRetryAvailable");
    expect(connectionPanel).toContain("COMPANION_TRY_AGAIN_ACTION");
    expect(connectionPanel).toContain("COMPANION_TRY_AGAIN_IS_SAFE");
    expect(COMPANION_TRY_AGAIN_IS_SAFE).toMatch(/safe/i);
    expect(COMPANION_TRY_AGAIN_IS_SAFE).toMatch(/do not need to reset/i);
  });
});

/**
 * Every control the phone actually puts on screen, by its exact label.
 *
 * Built by reading the sources rather than by listing them by hand, so a button
 * that is renamed, moved behind a condition or deleted disappears from this set
 * and every sentence that quotes it fails. That is the whole point: two false
 * instructions in this codebase, each naming a control that was not there,
 * caused a permanent unrecoverable device revocation.
 */
const AGENT_TSX = [
  "agent/AgentCompanionApp.tsx",
  "agent/CompanionPairingPanel.tsx",
  "agent/CompanionReadOnlyPages.tsx",
  "agent/CompanionSecurity.tsx",
] as const;

/** Constant name to the words the owner reads on the control. */
const CONTROL_LABEL_CONSTANTS: Readonly<Record<string, string>> = {
  COMPANION_CONNECT_ACTION,
  COMPANION_CREATE_IDENTITY_ACTION,
  COMPANION_OPEN_SECURITY_SETUP_ACTION,
  COMPANION_RECHECK_IDENTITY_ACTION,
  COMPANION_REFRESH_ACTION,
  COMPANION_RESET_PAIRING_ACTION,
  COMPANION_REVIEW_APPROVAL_ACTION,
  COMPANION_SCAN_QR_ACTION,
  COMPANION_SEND_CONFIRMATION_ACTION,
  COMPANION_TRY_AGAIN_ACTION,
};

/**
 * Labels carried by a real rendered control.
 *
 * Two rendering positions exist in this surface and both are read: the body of
 * a <button>, and the label prop of CompanionQrScanner, which CompanionQr.tsx
 * renders as that button's text. String literals and CONSTANT identifiers are
 * both resolved, so it does not matter which style a button was written in.
 */
function buttonBodies(source: string): string[] {
  const bodies: string[] = [];
  let cursor = source.indexOf("<button");
  while (cursor >= 0) {
    // An onClick arrow contains a ">", so the opening tag cannot be found by
    // scanning to the first one. Walk it with brace depth instead, or a button
    // written with a handler would silently drop out of this set and every
    // sentence quoting its label would pass while naming nothing.
    let depth = 0;
    let index = cursor + "<button".length;
    while (index < source.length) {
      const character = source[index];
      if (character === "{") depth += 1;
      else if (character === "}") depth -= 1;
      else if (character === ">" && depth === 0) break;
      index += 1;
    }
    const end = source.indexOf("</button>", index);
    if (end < 0) break;
    bodies.push(source.slice(index + 1, end));
    cursor = source.indexOf("<button", end);
  }
  return bodies;
}

function renderedControlLabels(): Set<string> {
  const labels = new Set<string>();
  for (const file of AGENT_TSX) {
    const source = withoutComments(read(file));
    for (const body of buttonBodies(source)) {
      for (const [, literal] of body.matchAll(/"([^"]+)"/g)) labels.add(literal);
      for (const [, name] of body.matchAll(/\b([A-Z][A-Z0-9_]{4,})\b/g)) {
        const value = CONTROL_LABEL_CONSTANTS[name];
        if (value) labels.add(value);
      }
      const plain = body.replace(/\{[\s\S]*?\}/g, " ").replace(/\s+/g, " ").trim();
      if (plain) labels.add(plain);
    }
    for (const [, name] of source.matchAll(/\blabel=\{([A-Z][A-Z0-9_]+)\}/g)) {
      const value = CONTROL_LABEL_CONSTANTS[name];
      if (value) labels.add(value);
    }
  }
  return labels;
}

/** Every sentence the phone shows that could quote a control. */
function ownerFacingCopy(): string[] {
  const states: CompanionPairingStateInput[] = [
    stateInput({ configured: false }),
    stateInput({ configured: false, pairingInProgress: true }),
    stateInput({ pendingPairingFinalization: true }),
    stateInput(),
    stateInput({ lastError: "which means it refused this device." }),
    stateInput({ hasSession: true }),
    stateInput({ hasSession: true, hasTrustedSnapshot: true }),
  ];
  const copy: string[] = [];
  for (const input of states) {
    const view = companionPairingStateView(input);
    copy.push(view.detail, view.nextAction);
  }
  for (const raw of [
    "already accepted a newer session challenge",
    "reused a session challenge",
    "clock is more than a minute ahead",
    "had already expired by the time this phone read it",
    "no longer authorizes this phone",
    "was not signed by the desktop this phone is paired with",
    "addressed to a different phone",
    "hardware companion identity is unavailable",
    "could not durably record the companion session",
    "is not the desktop this phone is paired with",
    "stored companion state could not be read",
    "pairing is not complete on hpay desktop",
    "pair this phone before connecting",
    "refused this device",
    "companion backend rejected the operation",
    "companion device authorization failed",
    "closed the connection while confirming the session key",
    "closed the authenticated companion session",
    "early eof",
    "timed out",
    "not a private address",
    "connection or rate limit was reached",
    "downgrade received after authentication",
    "no private-lan endpoint was available",
    "",
  ]) {
    copy.push(companionFailureText(raw));
  }
  copy.push(
    COMPANION_PLATFORM_UNSUPPORTED_BODY,
    COMPANION_PLATFORM_UNSUPPORTED_ROUTE,
  );
  return copy.filter((entry) => entry.trim().length > 0);
}

describe("a chosen tab leads with its own content", () => {
  const TABS: AgentCompanionPage[] = [
    "overview",
    "agents",
    "rules",
    "activity",
    "security",
  ];

  it("leads with the tab whenever the tab has anything of its own to show", () => {
    for (const page of TABS) {
      // Connected: every tab is drawn from the snapshot, so every tab leads.
      expect(
        companionPageLeadsWithOwnContent({
          page,
          configured: true,
          hasTrustedSnapshot: true,
        }),
        `${page} does not lead with its own content when there is data`,
      ).toBe(true);
    }
  });

  it("gives the lead to the connection block only when the tab would be empty", () => {
    for (const page of TABS) {
      const leads = companionPageLeadsWithOwnContent({
        page,
        configured: true,
        hasTrustedSnapshot: false,
      });
      // Security reads this phone's own identity and needs no desktop, so it
      // still leads. The other four would render nothing but an Unavailable
      // card, and the one control that fills them goes first instead.
      expect(leads, `${page} led with an empty tab`).toBe(page === "security");
    }
  });

  it("never reorders the unpaired onboarding, whatever tab is selected", () => {
    for (const page of TABS) {
      expect(
        companionPageLeadsWithOwnContent({
          page,
          configured: false,
          hasTrustedSnapshot: false,
        }),
      ).toBe(false);
    }
  });

  it("renders the shared status as one line, with every fact still inside it", () => {
    const app = withoutComments(read("agent/AgentCompanionApp.tsx"));

    // The notice card and the eighteen-row health card that used to open all
    // five tabs are one summary line and one disclosure.
    expect(app).toContain('<section className="agent-status-strip"');
    const strip = app.slice(
      app.indexOf('<section className="agent-status-strip"'),
      app.indexOf("</section>", app.indexOf('<section className="agent-status-strip"')),
    );
    expect(strip).toContain("<summary>");
    expect(strip).toContain("{pairingState.label}");
    // Not one sentence was dropped: they are inside the disclosure.
    for (const kept of [
      "{pairingState.detail}",
      "{pairingState.nextAction}",
      "Only exact V3, Type 2 testnet approvals",
      '<Detail label="Companion health" value={pairingState.label} />',
      'label="HPAY wallet fee" value="None"',
      'label="Agent private key" value="Not stored on mobile"',
    ]) {
      expect(strip, `${kept} was lost rather than folded`).toContain(kept);
    }
    // And a state with something outstanding opens itself, so a refusal is
    // never hidden from the owner who is stuck in it.
    expect(strip).toContain('open={pairingState.nextAction !== ""}');
    // The standing notice is one line now, and still carries the explanation.
    expect(app).toContain("No wallet key on this phone.");
    expect(app).toContain("What is an AI Agent Wallet?");
    expect(app).not.toContain('<section className="agent-companion-notice"');

    // Order is decided by companionBlockOrder and rendered in one place, so
    // no block can acquire a second position in the tree.
    expect(app).toContain("{blockOrder.map((id) => renderBlock(id))}");
    for (const block of [
      "statusStripBlock",
      "onboardingBlock",
      "pairingBlock",
      "pendingPairingStepBlock",
      "connectionBlock",
      "pageContent",
    ]) {
      expect(
        app.match(new RegExp(`\\{${block}\\}`, "g")),
        `${block} is rendered in more than one position`,
      ).toHaveLength(1);
    }
  });

  it("leads the Activity tab with the decision, not with the empty-by-design list", () => {
    const pages = withoutComments(read("agent/CompanionReadOnlyPages.tsx"));
    const activity = pages.slice(pages.indexOf("export function CompanionActivity"));
    const pending = activity.indexOf('aria-label="Pending testnet approvals"');
    const recent = activity.indexOf('aria-label="Agent Wallet activity"');
    expect(pending).toBeGreaterThan(0);
    expect(recent).toBeGreaterThan(0);
    // Payment history is blanked for every paired device by the desktop, so
    // the list above the only actionable thing in the app was always empty.
    expect(pending).toBeLessThan(recent);
    // JSX wraps prose across lines, so compare on collapsed whitespace.
    expect(flatten(activity)).toContain("Payment history is never sent to a phone");
    expect(flatten(activity)).toContain("Requests waiting for your approval appear above");
  });

  it("stops repeating the same closing paragraphs once per policy card", () => {
    const pages = withoutComments(read("agent/CompanionReadOnlyPages.tsx"));
    const card = pages.slice(
      pages.indexOf("function PolicyCard"),
      pages.indexOf("export function CompanionActivity"),
    );
    // Both sentences survive; neither is printed once per agent any more.
    expect(card).not.toContain("includes the payment amount and the Hacash network");
    expect(pages).toContain("includes the payment amount and the Hacash network");
    expect(pages).toContain("rolling window, not a calendar day");
    expect(pages).toContain("pending or reserved payment requests may count toward enforcement");
  });
});

describe("no instruction names a control that does not exist", () => {
  it("finds a real rendered control for every label the copy can quote", () => {
    const rendered = renderedControlLabels();
    for (const [name, label] of Object.entries(CONTROL_LABEL_CONSTANTS)) {
      expect(
        rendered,
        `${name} ("${label}") is quoted in copy but no button renders it`,
      ).toContain(label);
    }
  });

  it("makes the desktop name the phone's scan control by its real label", () => {
    // The desktop pairing step tells the owner what to tap ON THE PHONE. It
    // said "tap Scan QR"; the phone renders COMPANION_SCAN_QR_ACTION, which is
    // "Scan desktop QR". A label that appears on neither screen is the same
    // defect class as the two false instructions that caused a permanent,
    // unrecoverable device revocation, so it is pinned across both apps.
    const panel = readWorkspace(
      "apps/desktop/src/agent/MobileCompanionPanel.tsx",
    );
    const instruction = panel
      .replace(/\s+/g, " ")
      .match(/Open AI Agent Wallet on the phone, tap [^.]*\./);
    expect(instruction, "the desktop scan instruction was renamed").not.toBeNull();
    expect(instruction?.[0]).toContain(COMPANION_SCAN_QR_ACTION);
  });

  it("quotes only labels that are rendered, in every sentence the phone shows", () => {
    const rendered = renderedControlLabels();
    for (const sentence of ownerFacingCopy()) {
      for (const [name, label] of Object.entries(CONTROL_LABEL_CONSTANTS)) {
        if (!sentence.includes(label)) continue;
        expect(
          rendered,
          `a sentence quotes ${name} but nothing renders it: ${sentence}`,
        ).toContain(label);
      }
    }
  });

  it("no longer tells the owner to tap a Refresh button that never existed", () => {
    // The stale-approval message said "Tap Refresh now". No control anywhere on
    // the phone carried that label, and the one that does the job used to live
    // only inside the connection card on another part of the screen.
    const app = withoutComments(read("agent/AgentCompanionApp.tsx"));
    const pages = withoutComments(read("agent/CompanionReadOnlyPages.tsx"));
    expect(app).not.toContain("Tap Refresh now");
    expect(app).toContain("Tap ${COMPANION_REFRESH_ACTION}");
    expect(COMPANION_REFRESH_ACTION).toBe("Refresh the status now");
    // And Activity carries that button itself, so the instruction resolves on
    // the screen that shows it.
    const activity = pages.slice(pages.indexOf("export function CompanionActivity"));
    expect(activity).toContain("{COMPANION_REFRESH_ACTION}");
    expect(activity).toContain("onClick={onRefresh}");
    expect(app).toContain(
      "onRefresh={companion.session ? () => void companion.syncNow() : undefined}",
    );
  });

  it("stops sending a locked or unsupported phone to Create mobile identity", () => {
    const panel = withoutComments(read("agent/CompanionPairingPanel.tsx"));
    const blocked = panel.slice(
      panel.indexOf("if (!identity) {"),
      panel.indexOf("if (!pairing) {"),
    );

    // An identity status that could not be read at all is its own branch. The
    // Security tab renders only the recheck control in that state, so naming
    // Create mobile identity there named a button that is not on the screen.
    const unknown = blocked.slice(
      0,
      blocked.indexOf("if (!identity.ready) {"),
    );
    expect(unknown).toContain("COMPANION_RECHECK_IDENTITY_ACTION");
    expect(unknown).not.toContain("COMPANION_CREATE_IDENTITY_ACTION");
    expect(unknown).not.toContain("COMPANION_SCAN_QR_ACTION");

    // Create mobile identity is only rendered while the identity does not
    // exist, so naming it for a phone whose key exists but will not open, or
    // for a handset that cannot hold one at all, named a control that was not
    // on the screen. Each branch now names only what that state can reach.
    const unsupported = blocked.slice(
      blocked.indexOf("if (!identity.platformSupported)"),
      blocked.indexOf("if (identity.configured)"),
    );
    expect(unsupported).toContain("COMPANION_PLATFORM_UNSUPPORTED_TITLE");
    expect(unsupported).not.toContain("COMPANION_CREATE_IDENTITY_ACTION");
    expect(unsupported).not.toContain("COMPANION_SCAN_QR_ACTION");

    const locked = blocked.slice(
      blocked.indexOf("if (identity.configured)"),
      blocked.lastIndexOf("return ("),
    );
    expect(locked).toContain("COMPANION_RECHECK_IDENTITY_ACTION");
    expect(locked).not.toContain("COMPANION_CREATE_IDENTITY_ACTION");

    // And the control that branch names is now rendered in every state where
    // the identity can be read at all, not only when it cannot be read.
    const security = withoutComments(read("agent/CompanionSecurity.tsx"));
    expect(security).toContain("{COMPANION_RECHECK_IDENTITY_ACTION}");
    expect(security).toContain("{identity && !identity.platformSupported ? null : (");
  });

  it("says plainly that nothing on an unsupported handset can proceed", () => {
    const security = withoutComments(read("agent/CompanionSecurity.tsx"));
    expect(security).toContain("{identity && !identity.platformSupported ? (");
    expect(security).toContain("COMPANION_PLATFORM_UNSUPPORTED_BODY");
    expect(security).toContain("COMPANION_PLATFORM_UNSUPPORTED_ROUTE");
    // The one true route, and no invented control.
    expect(COMPANION_PLATFORM_UNSUPPORTED_ROUTE).toMatch(/different Android phone/i);
    expect(COMPANION_PLATFORM_UNSUPPORTED_ROUTE).toMatch(/no setting on this phone/i);
    expect(COMPANION_PLATFORM_UNSUPPORTED_BODY).toMatch(/nothing here was changed/i);
    for (const label of Object.values(CONTROL_LABEL_CONSTANTS)) {
      expect(
        `${COMPANION_PLATFORM_UNSUPPORTED_BODY} ${COMPANION_PLATFORM_UNSUPPORTED_ROUTE}`,
      ).not.toContain(label);
    }
  });

  it("names the phone half of a controlled rotation, and that half now exists in every build", () => {
    const security = withoutComments(read("agent/CompanionSecurity.tsx"));
    // The blocker names Check and continue rotation. That control used to exist
    // only in a pilot build, so a read-only handset was told to use a control
    // it did not have, could not reset, and was stuck for good. The panel is
    // now rendered whenever the reset is blocked, in any build.
    expect(security).toContain("Controlled witness rotation required");
    const blocker = security.slice(
      security.indexOf("Controlled witness rotation required"),
      security.indexOf(") : !resetConfirm ? ("),
    );
    expect(blocker).toContain("Check and continue rotation");
    expect(blocker).not.toMatch(/no rotation control on the phone/i);
    expect(security).toContain("(stored.pilotEnabled || resetBlocked)");
    // And the native command it calls is no longer refused outright in a
    // read-only build: only the replacement phone's half still is.
    const pilot = readWorkspace(
      "apps/mobile/src-tauri/src/agent_companion/pilot.rs",
    );
    const step = pilot.slice(
      pilot.indexOf("pub async fn agent_wallet_companion_rotation_step"),
    );
    expect(step).not.toContain(
      "require_agent_companion_webview(&webview)?;\n    require_pilot_enabled()?;",
    );
    expect(step).toContain("require_pilot_enabled()?;");
  });

  it("points a stopped wallet at the desktop control that clears it", () => {
    const pages = withoutComments(read("agent/CompanionReadOnlyPages.tsx"));
    const core = readWorkspace(
      "crates/agent-wallet-core/src/service/companion/snapshot.rs",
    );
    const desktop = readWorkspace("apps/desktop/src/agent/AgentWalletApp.tsx");

    // paused is payments_suspended, and the desktop control that clears it is
    // Enable locally inside Payment control. Both are checked at the source so
    // this sentence cannot quietly become false.
    expect(core).toContain("paused: overview.payments_suspended");
    expect(desktop).toContain("Payment control");
    expect(desktop).toContain("Enable locally");

    expect(pages).toContain("{snapshot.wallet.paused ? (");
    const paused = pages.slice(pages.indexOf("{snapshot.wallet.paused ? ("));
    expect(paused).toContain("find Payment control and use Enable locally");
    // And it does not pretend the phone can clear it.
    expect(paused).toMatch(/No button on this phone can clear it/i);
  });
});

describe("one primary action per screen", () => {
  function primaryInput(
    overrides: Partial<CompanionPrimaryActionInput> = {},
  ): CompanionPrimaryActionInput {
    return {
      page: "overview",
      platformSupported: true,
      identityConfigured: true,
      configured: true,
      pairingInProgress: false,
      pendingPairingFinalization: false,
      hasSession: true,
      connectRetryAvailable: false,
      pendingApprovals: 0,
      ...overrides,
    };
  }

  const cases: Array<{
    what: string;
    input: CompanionPrimaryActionInput;
    id: string;
  }> = [
    {
      what: "a handset that cannot hold the identity",
      input: primaryInput({
        platformSupported: false,
        configured: false,
        identityConfigured: false,
      }),
      id: "none",
    },
    {
      what: "no identity yet, on any tab but Security",
      input: primaryInput({
        configured: false,
        identityConfigured: false,
        page: "overview",
      }),
      id: "open_security_setup",
    },
    {
      what: "no identity yet, on the Security tab",
      input: primaryInput({
        configured: false,
        identityConfigured: false,
        page: "security",
      }),
      id: "create_identity",
    },
    {
      what: "identity ready, nothing paired",
      input: primaryInput({ configured: false }),
      id: "scan_desktop_qr",
    },
    {
      what: "a pairing ceremony already open",
      input: primaryInput({ configured: false, pairingInProgress: true }),
      id: "none",
    },
    {
      what: "the desktop has not approved this phone",
      input: primaryInput({ pendingPairingFinalization: true, hasSession: false }),
      id: "send_confirmation",
    },
    {
      what: "paired, no connection, nothing refused yet",
      input: primaryInput({ hasSession: false }),
      id: "connect",
    },
    {
      what: "paired, and the last attempt was refused",
      input: primaryInput({ hasSession: false, connectRetryAvailable: true }),
      id: "try_again",
    },
    {
      what: "connected, with a payment waiting",
      input: primaryInput({ pendingApprovals: 2 }),
      id: "review_approval",
    },
    { what: "connected, nothing outstanding", input: primaryInput(), id: "none" },
  ];

  it("names exactly one action for every reachable state", () => {
    for (const entry of cases) {
      const action = companionPrimaryAction(entry.input);
      expect(action.id, `wrong primary for ${entry.what}`).toBe(entry.id);
    }
  });

  it("only ever names a control that is really on the screen", () => {
    const rendered = renderedControlLabels();
    for (const entry of cases) {
      const action = companionPrimaryAction(entry.input);
      if (action.id === "none") {
        // A connected phone with nothing pending has no outstanding work, and
        // a handset that cannot hold the identity has no action that helps.
        // Inventing one is the same defect as naming a missing button.
        expect(action.label).toBe("");
        continue;
      }
      expect(action.label).toBe(COMPANION_PRIMARY_ACTION_LABELS[action.id]);
      expect(
        rendered,
        `the primary for ${entry.what} is "${action.label}", which nothing renders`,
      ).toContain(action.label);
    }
  });

  it("blocks in the order the states really block on each other", () => {
    // Pairing cannot start before the identity exists, the desktop cannot be
    // connected before it has finalized the pairing, and no approval can be
    // reviewed without a connection. A state that is blocked twice must return
    // the earlier blocker, or the owner is sent to a control that will refuse.
    expect(
      companionPrimaryAction(
        primaryInput({
          configured: false,
          identityConfigured: false,
          pendingApprovals: 3,
          hasSession: false,
        }),
      ).id,
    ).toBe("open_security_setup");
    expect(
      companionPrimaryAction(
        primaryInput({
          pendingPairingFinalization: true,
          hasSession: false,
          pendingApprovals: 3,
        }),
      ).id,
    ).toBe("send_confirmation");
    expect(
      companionPrimaryAction(primaryInput({ hasSession: false, pendingApprovals: 3 })).id,
    ).toBe("connect");
  });

  it("keeps one connect button instead of two that call the same thing", () => {
    const app = withoutComments(read("agent/AgentCompanionApp.tsx"));
    const panel = withoutComments(read("agent/CompanionPairingPanel.tsx"));

    // The error card used to carry a primary "Try connecting again" while the
    // connection card carried a primary "Connect to the desktop", both wired to
    // connectAndSync, drawn identically, a screen apart.
    const errorCard = app.slice(
      app.indexOf("{companion.error ? ("),
      app.indexOf("{actionNotice ? ("),
    );
    expect(errorCard).toContain("{companion.error}");
    expect(errorCard).not.toContain("agent-primary-action");
    expect(errorCard).not.toContain("connectAndSync");

    // One button, and its label is whatever the copy on screen is calling it.
    const connection = panel.slice(
      panel.indexOf("export function CompanionConnectionPanel"),
    );
    expect(connection).toContain("COMPANION_TRY_AGAIN_ACTION");
    expect(connection).toContain("COMPANION_CONNECT_ACTION");
    expect(connection).toContain(
      "const retryWording = Boolean(lastError) || retryAvailable;",
    );
    expect(connection.match(/onClick=\{onConnect\}/g)).toHaveLength(1);
    // The refusal still renders before the control that produced it.
    expect(connection.indexOf("{lastError ? (")).toBeLessThan(
      connection.indexOf("onClick={onConnect}"),
    );
    // And the button is withheld in the one state where pressing it is certain
    // to be refused, with the control that does apply named instead.
    expect(connection).toContain(
      'primaryActionId === "connect" || primaryActionId === "try_again"',
    );
    expect(connection).toContain("{COMPANION_SEND_CONFIRMATION_ACTION} in the pairing step");
  });

  it("makes the destructive choice look different from the safe one", () => {
    const security = withoutComments(read("agent/CompanionSecurity.tsx"));
    const confirm = security.slice(security.indexOf("Type RESET COMPANION"));
    // The reset confirm and its "Keep this phone paired" sibling were styled
    // identically, so the pair read as two equal options.
    expect(confirm).toContain("agent-danger-action");
    expect(confirm).toContain("agent-primary-action");
    expect(confirm.indexOf("Keep this phone paired")).toBeLessThan(
      confirm.indexOf("agent-danger-action"),
    );
    // The typed confirmation still gates it, and the warning still precedes it.
    expect(confirm).toContain('disabled={busy || resetText !== "RESET COMPANION"}');

    // Three buttons of equal weight sat under the exact payment figures, one of
    // which signs. Approve is the only primary; leaving is quiet and says so.
    const pages = withoutComments(read("agent/CompanionReadOnlyPages.tsx"));
    const actions = pages.slice(
      pages.indexOf('<div className="agent-approval-actions">'),
      pages.indexOf(
        "</div>",
        pages.indexOf('<div className="agent-approval-actions">'),
      ),
    );
    expect(actions.match(/agent-primary-action/g)).toHaveLength(1);
    expect(actions).toContain("agent-danger-action");
    expect(actions).toContain("agent-quiet-action");
    expect(actions).toContain("Close without deciding");
    // Approve stays last, below the figures it applies to.
    expect(actions.indexOf("Reject request")).toBeLessThan(
      actions.indexOf("Approve exact testnet payment"),
    );
    expect(read("agent/agent-wallet.css")).toContain(".agent-quiet-action");
  });
});

describe("the revocation reference stops shouting at healthy phones", () => {
  it("folds the longest block in the app away, without losing a word of it", () => {
    const security = withoutComments(read("agent/CompanionSecurity.tsx"));
    const block = security.slice(
      security.indexOf("{identity?.platformSupported ? ("),
      security.indexOf("{stored?.configured && stored.pilotEnabled ? ("),
    );
    // A summary line instead of three hundred and seventy-four words on every
    // phone that has never been revoked.
    expect(block).toContain("<details");
    expect(block).toContain("<summary>{COMPANION_REVOKED_TITLE}</summary>");
    // Every part is still there.
    for (const kept of [
      "COMPANION_REVOKED_PERMANENCE",
      "COMPANION_REVOKED_RESET_DOES_NOT_HELP",
      "COMPANION_REVOKED_ROUTE",
      "COMPANION_REVOKED_RECOVERY_STEPS.map",
      "COMPANION_REVOKED_ALTERNATIVE",
    ]) {
      expect(block, `${kept} was lost rather than folded`).toContain(kept);
    }
    // And it opens itself for the owner who needs it.
    expect(block).toContain("open={revocationSuspected}");
    expect(read("agent/AgentCompanionApp.tsx")).toContain(
      "revocationSuspected={companionRevocationSuspected(companion.error)}",
    );
  });

  it("opens for a real refusal and stays shut for a healthy phone", () => {
    expect(companionRevocationSuspected("")).toBe(false);
    expect(companionRevocationSuspected("HPAY Desktop did not answer in time")).toBe(false);
    expect(
      companionRevocationSuspected(
        companionFailureText("HPAY Desktop no longer authorizes this phone: revoked"),
      ),
    ).toBe(true);
    expect(
      companionRevocationSuspected(
        companionFailureText("the paired desktop refused this device"),
      ),
    ).toBe(true);
  });

  it("recognises the refusal after it has been rewritten for the owner", () => {
    // The hole. Everything the phone stores in its error state has already been
    // through companionFailureText, and the owner-facing sentence says "refused
    // this phone" while the marker said "device". So the "Desktop refused"
    // status - the one that sends an owner to look for a revoked record rather
    // than retrying forever - could never appear in the running app at all.
    const owner = companionFailureText(
      new Error(
        "the paired desktop closed the connection during device authentication without replying, which means it refused this device.",
      ),
    );
    expect(owner).not.toContain("refused this device");
    expect(companionDesktopRefusedDevice(owner)).toBe(true);
    expect(companionPairingStateView(stateInput({ lastError: owner })).state).toBe(
      "refused_by_desktop",
    );

    // Still narrow: nothing else is promoted to a refusal.
    for (const other of [
      "companion backend rejected the operation",
      "companion LAN operation timed out",
      "companion LAN I/O failed: connection refused",
    ]) {
      expect(
        companionPairingStateView(
          stateInput({ lastError: companionFailureText(other) }),
        ).state,
        `${other} was mistaken for a desktop refusal`,
      ).toBe("paired_not_connected");
    }
  });
});


/* -------------------------------------------------------------------------- */
/* Closures pinned by the condition that makes them true                       */
/* -------------------------------------------------------------------------- */

/** Every phase name the Rust enum serialises to, read from the source. */
function rustRotationPhases(): string[] {
  const source = readWorkspace("crates/companion-protocol/src/rotation.rs");
  const body = source.split("pub enum WitnessRotationPhase {")[1].split("}")[0];
  return body
    .split("\n")
    .map((line) => line.trim().replace(/,$/, ""))
    .filter((line) => /^[A-Z][A-Za-z]*$/.test(line))
    .map((variant) => variant.replace(/([a-z0-9])([A-Z])/g, "$1_$2").toLowerCase());
}

/** How deep inside <details> a given index sits. 0 means always visible. */
function disclosureDepth(source: string, index: number): number {
  const before = source.slice(0, index);
  return before.split("<details").length - before.split("</details>").length;
}

describe("a rotation in progress never makes a paired phone report itself unpaired", () => {
  it("accepts every phase the native side can actually persist", () => {
    // The runtime whitelist listed twelve names against the protocol enum's
    // twenty, and four of the twelve did not exist in Rust at all. A phase
    // outside it threw from validatedStoredState, so stored AND identity both
    // stayed null, the phone showed "Not paired with a desktop", and every
    // escape - the connection block, the reset section, the create-identity
    // button - is gated on one of those two.
    const fromRust = rustRotationPhases();
    expect(fromRust.length).toBe(20);
    expect([...COMPANION_ROTATION_PHASES].sort()).toEqual([...fromRust].sort());

    for (const phase of fromRust) {
      const state = storedState({
        rotationPhase: phase as NonNullable<CompanionStoredStateView["rotationPhase"]>,
      });
      expect(() => validatedStoredState(state), `${phase} is unreadable`).not.toThrow();
      expect(validatedStoredState(state).configured).toBe(true);
    }
  });

  it("covers the phases the phone writes itself, by name", () => {
    // Written by apps/mobile/src-tauri/src/agent_companion/{pairing,pilot}.rs.
    for (const phase of [
      "candidate_paired_restricted",
      "awaiting_candidate_pairing",
      "candidate_baseline_verified",
      "awaiting_completion_anchor",
    ] as const) {
      expect(COMPANION_ROTATION_PHASES).toContain(phase);
      expect(() =>
        validatedStoredState(storedState({ rotationPhase: phase })),
      ).not.toThrow();
    }
  });

  it("still refuses a phase name that is not in the protocol at all", () => {
    expect(() =>
      validatedStoredState(
        storedState({
          rotationPhase: "not_a_phase" as NonNullable<
            CompanionStoredStateView["rotationPhase"]
          >,
        }),
      ),
    ).toThrow(/rotation phase is invalid/i);
  });

  it("reads the identity even when the stored state cannot be read", () => {
    // useCompanionSession computed the identity and the state inside one try,
    // identity first and state second, so a state that failed validation threw
    // before setIdentity ran and removed the Security tab as well.
    const hook = withoutComments(read("agent/useCompanionSession.ts"));
    expect(hook).toContain("Promise.allSettled([");
    expect(hook).toContain("setIdentity(validatedIdentityStatus(identityResult.value))");
    const app = withoutComments(read("agent/AgentCompanionApp.tsx"));
    expect(app).toContain("void Promise.allSettled([");
  });

  it("names the version mismatch instead of the desktop's revoke list", () => {
    const text = companionFailureText(
      new Error("The companion rotation phase is invalid."),
    );
    expect(text).not.toContain(COMPANION_UNCLASSIFIED_NEXT_STEP);
    expect(text).toContain("still paired");
    expect(text).toContain("different releases");
  });
});

describe("a successful pairing can never wedge on a false fingerprint banner", () => {
  it("catches the state read that runs after the pairing has succeeded", () => {
    // The read sat outside every catch, so its rejection escaped into
    // `void confirmPairing()`, setPairingBusy(false) never ran, and the app
    // showed "Waiting for Android security approval" for good with no error.
    const app = withoutComments(read("agent/AgentCompanionApp.tsx"));
    const after = app.slice(
      app.indexOf("ackDelivered: Boolean(pairing.rotationTicket),"),
      app.indexOf("if (!pairing.rotationTicket) {"),
    );
    expect(after).toContain("try {");
    expect(after).toContain("await companion.refreshStoredState();");
    expect(after).toContain("} catch (reason) {");
    expect(after).toContain("companion.setError(");
  });
});

describe("no press on this phone lands and vanishes", () => {
  it("names which guard refused a scanned pairing offer", () => {
    // The scanner fires onValue once and then closes the camera, so a bare
    // return here is the confirmed historical defect verbatim.
    expect(
      scanRefusal({ busy: false, configured: true, identityReady: true }),
    ).toContain("already paired");
    expect(
      scanRefusal({ busy: false, configured: false, identityReady: false }),
    ).toContain("secure identity is not ready");
    expect(
      scanRefusal({ busy: true, configured: false, identityReady: true }),
    ).toContain("still finishing the last step");
    // And it stays out of the way when the scan will be used.
    expect(
      scanRefusal({ busy: false, configured: false, identityReady: true }),
    ).toBe("");
  });

  it("leaves no bare return on a control the owner can press", () => {
    const app = withoutComments(read("agent/AgentCompanionApp.tsx"));
    for (const guard of [
      "if (!pairing || !pairing.automaticTransport) return;",
      "if (!pairing) return;",
    ]) {
      expect(app).toContain(guard);
    }
    // Every busy refusal now says so.
    expect(app.split("companion.setError(BUSY_REFUSAL);").length - 1).toBeGreaterThanOrEqual(5);
    expect(app).not.toContain("if (busy) return;");
    expect(app).not.toContain("|| busy) return;");
  });

  it("disables the refresh control while the heartbeat owns the read", () => {
    // syncNow returns immediately while heartbeatInFlight is set, and that ref
    // never reached render, so the button was enabled and the press did
    // nothing at all - on the very control the stale-request message names.
    const hook = withoutComments(read("agent/useCompanionSession.ts"));
    expect(hook).toContain("const [syncInFlight, setSyncInFlight] = useState(false);");
    expect(hook).toContain("setSyncInFlight(true);");
    expect(hook).toContain("syncInFlight,");

    const app = withoutComments(read("agent/AgentCompanionApp.tsx"));
    expect(app).toContain("busy={busy || companion.syncInFlight}");
    expect(app).toContain("syncBusy={busy || companion.syncInFlight}");
    const panel = withoutComments(read("agent/CompanionPairingPanel.tsx"));
    expect(panel).toContain("<button type=\"button\" disabled={syncBusy} onClick={onSync}>");
  });
});

describe("the waiting banner names the step the owner is actually in", () => {
  it("gives every call site its own reason", () => {
    const app = withoutComments(read("agent/AgentCompanionApp.tsx"));
    // pairingBusy is set by pairing, sending the confirmation, cancelling,
    // deciding a payment and continuing a rotation. Only one is pairing.
    for (const reason of [
      "pairing",
      "send_confirmation",
      "cancel",
      "decision",
      "rotation",
    ]) {
      expect(app).toContain(`setPairingBusy("${reason}")`);
      expect(app).toContain(`  ${reason}:`);
    }
    expect(app).toContain("{NATIVE_WAIT_TEXT[nativeWait]}");
    expect(app).not.toContain(
      "<p>Complete or cancel the fingerprint prompt to continue pairing.</p>",
    );
  });
});

describe("a status strip never names a control the state does not render", () => {
  it("stops naming Create mobile identity when the identity cannot be read", () => {
    // CompanionSecurity gates that button on identity?.platformSupported, so
    // with identity null the tab renders only the recheck control.
    const view = companionPairingStateView(
      stateInput({ configured: false, identityKnown: false }),
    );
    expect(view.nextAction).not.toContain(COMPANION_CREATE_IDENTITY_ACTION);
    expect(view.nextAction).toContain(COMPANION_RECHECK_IDENTITY_ACTION);
  });

  it("names no button at all on a handset that cannot host the identity", () => {
    const view = companionPairingStateView(
      stateInput({ configured: false, platformSupported: false }),
    );
    for (const label of [
      COMPANION_CREATE_IDENTITY_ACTION,
      COMPANION_SCAN_QR_ACTION,
      COMPANION_RECHECK_IDENTITY_ACTION,
    ]) {
      expect(view.nextAction).not.toContain(label);
    }
    expect(view.nextAction).toContain("No control on this phone can change this");
  });

  it("keeps naming the create control where it really is rendered", () => {
    const view = companionPairingStateView(stateInput({ configured: false }));
    expect(view.nextAction).toContain(COMPANION_CREATE_IDENTITY_ACTION);
    expect(view.nextAction).toContain(COMPANION_SCAN_QR_ACTION);
  });

  it("skips the create control once the identity already exists", () => {
    const view = companionPairingStateView(
      stateInput({ configured: false, identityConfigured: true }),
    );
    expect(view.nextAction).not.toContain(COMPANION_CREATE_IDENTITY_ACTION);
    expect(view.nextAction).toContain(COMPANION_SCAN_QR_ACTION);
  });

  it("does not name the scanner while the identity is locked", () => {
    // CompanionPairingPanel gates the scanner on identity.ready, not on
    // identity.configured. With the identity created but locked it renders
    // "This phone's secure identity is locked" and no scanner at all, so
    // naming Scan desktop QR here is a button that is not on the screen.
    const view = companionPairingStateView(
      stateInput({
        configured: false,
        identityConfigured: true,
        identityReady: false,
      }),
    );
    expect(view.nextAction).not.toContain(COMPANION_SCAN_QR_ACTION);
    expect(view.nextAction).toContain(COMPANION_RECHECK_IDENTITY_ACTION);
  });

  it("still names the create control first when nothing is ready yet", () => {
    const view = companionPairingStateView(
      stateInput({
        configured: false,
        identityConfigured: false,
        identityReady: false,
      }),
    );
    expect(view.nextAction).toContain(COMPANION_CREATE_IDENTITY_ACTION);
    expect(view.nextAction).toContain(COMPANION_SCAN_QR_ACTION);
  });

  it("feeds the strip the facts the Security tab is gated on", () => {
    const app = withoutComments(read("agent/AgentCompanionApp.tsx"));
    expect(app).toContain("identityKnown: companion.identity !== null,");
    expect(app).toContain(
      "platformSupported: companion.identity?.platformSupported !== false,",
    );
    // The scanner is gated on ready, so the strip has to be told about ready.
    expect(app).toContain("identityReady: companion.identity?.ready,");
  });

  it("gives the unreadable identity its own pairing screen", () => {
    const panel = withoutComments(read("agent/CompanionPairingPanel.tsx"));
    const branch = panel.slice(
      panel.indexOf("if (!identity) {"),
      panel.indexOf("if (!identity.ready) {"),
    );
    expect(branch).toContain("COMPANION_RECHECK_IDENTITY_ACTION");
    expect(branch).not.toContain("COMPANION_CREATE_IDENTITY_ACTION");
    expect(branch).not.toContain("COMPANION_SCAN_QR_ACTION");
  });
});

describe("an expired request is not reported as a failing connection", () => {
  it("tells the two causes of a missing trusted snapshot apart", () => {
    // authenticatedSnapshot nulls the WHOLE snapshot if any single approval
    // fails, and a timer re-renders at exactly that instant, so everything
    // vanished at once while the header still said connected.
    const native = nativeSnapshot({
      approvals: [approval({ expires_at: "1090" })],
    });
    const expiredSnapshot = validateCompanionStatusSnapshot(
      native,
      session(),
      storedState(),
      1_050 * 1_000,
    );
    expect(
      authenticatedSnapshot(expiredSnapshot, NOW_MILLISECONDS),
    ).toBeNull();
    expect(
      snapshotBlockedOnlyByExpiredApproval(expiredSnapshot, NOW_MILLISECONDS),
    ).toBe(true);

    // A healthy snapshot is neither null nor blamed on an expiry.
    const healthy = validateCompanionStatusSnapshot(
      nativeSnapshot(),
      session(),
      storedState(),
      NOW_MILLISECONDS,
    );
    expect(authenticatedSnapshot(healthy, NOW_MILLISECONDS)).not.toBeNull();
    expect(
      snapshotBlockedOnlyByExpiredApproval(healthy, NOW_MILLISECONDS),
    ).toBe(false);
    expect(snapshotBlockedOnlyByExpiredApproval(null)).toBe(false);
  });

  it("says what happened and that the next refresh clears it", () => {
    const expired = companionPairingStateView(
      stateInput({ hasSession: true, approvalExpiredThisTick: true }),
    );
    const checking = companionPairingStateView(stateInput({ hasSession: true }));
    expect(expired.label).not.toBe(checking.label);
    expect(expired.pill).not.toBe(checking.pill);
    expect(expired.label).toContain("ran out of time");
    expect(expired.detail).toContain("nothing is wrong with it");
    // The state used to offer nothing at all for up to eight seconds.
    expect(checking.nextAction).toBe("");
    expect(expired.nextAction).toContain(COMPANION_REFRESH_ACTION);
  });
});

describe("a read-only build says so instead of raising a verification alarm", () => {
  it("branches on the build before claiming anything failed a check", () => {
    // canReview requires snapshot.pilotEnabled, which is false by construction
    // in a read-only build, so the verification sentence fired for every
    // request and read as an alarm about that exact one.
    const pages = withoutComments(read("agent/CompanionReadOnlyPages.tsx"));
    const index = pages.indexOf(") : !snapshot.pilotEnabled ? (");
    expect(index).toBeGreaterThan(0);
    expect(
      pages.indexOf("Approval is disabled because the request"),
    ).toBeGreaterThan(index);
    expect(flatten(pages)).toContain(
      "This build is read-only. Approve and Reject are on HPAY Desktop",
    );
  });

  it("says the same thing when the decision itself is refused", () => {
    const app = flatten(withoutComments(read("agent/AgentCompanionApp.tsx")));
    expect(app).toContain("snapshot && !snapshot.pilotEnabled");
    expect(app).toContain("This build of the phone app is read-only");
  });
});

describe("the read-only tabs point at a control that is on the screen", () => {
  it("stops naming a connect button once the connection is open", () => {
    // With a live session the connection block renders its connected form,
    // which has no connect control at all.
    expect(connectRoute(false)).toContain("connect button");
    expect(connectRoute(true)).not.toContain("connect button");
    expect(connectRoute(true)).toContain(COMPANION_REFRESH_ACTION);
    expect(connectRoute(true)).toContain(COMPANION_CONNECTION_SECTION_TITLE);
  });

  it("opens the block that owns that control while the data is missing", () => {
    // It was inside a <details> that is collapsed by default, which is the
    // same defect as not rendering it.
    const panel = withoutComments(read("agent/CompanionPairingPanel.tsx"));
    expect(panel).toContain('<details className="agent-disclosure" open={!hasTrustedSnapshot}>');
    const app = withoutComments(read("agent/AgentCompanionApp.tsx"));
    expect(app).toContain("hasTrustedSnapshot={companion.trustedSnapshot !== null}");
  });

  it("renders Activity's own refresh in the state that names it", () => {
    // The `if (!snapshot)` early return used to swallow the tab's own button.
    const pages = withoutComments(read("agent/CompanionReadOnlyPages.tsx"));
    const unavailable = pages.slice(
      pages.indexOf('title="Activity unavailable"'),
      pages.indexOf('title="Activity unavailable"') + 400,
    );
    expect(unavailable).toContain("action={onRefresh ? COMPANION_REFRESH_ACTION : undefined}");
    expect(unavailable).toContain("onAction={onRefresh}");
  });
});

describe("every reachable native refusal names its own cause", () => {
  const cases: Array<[string, string[], string[]]> = [
    [
      "A Class 3 biometric must be enrolled before creating the Agent companion identity",
      ["fingerprint or face unlock", "Android Settings"],
      ["Authorized mobile devices"],
    ],
    [
      "Agent companion identity is temporarily unavailable; no key was replaced",
      ["left exactly as it was", COMPANION_RECHECK_IDENTITY_ACTION],
      ["Authorized mobile devices"],
    ],
    [
      "Companion reset is blocked after pilot approval or witness initialization; controlled desktop/mobile witness rotation is required",
      ["the pairing was not deleted", "cannot be run again"],
      ["Authorized mobile devices"],
    ],
    [
      "The approval summary contains missing or unknown fields.",
      ["different releases", "update the older one"],
      ["Authorized mobile devices"],
    ],
  ];

  it.each(cases)("rewrites %s", (raw, expected, forbidden) => {
    const text = companionFailureText(new Error(raw));
    // The unclassified tail sent every one of these to the desktop's revoke
    // list, which is the wrong cause and the wrong screen for all of them.
    expect(text).not.toContain(COMPANION_UNCLASSIFIED_NEXT_STEP);
    expect(text).not.toBe(`${raw} ${COMPANION_UNCLASSIFIED_NEXT_STEP}`);
    for (const needle of expected) expect(text).toContain(needle);
    for (const needle of forbidden) expect(text).not.toContain(needle);
  });

  it("keeps the tail for a cause that genuinely is not classified", () => {
    expect(companionFailureText(new Error("something entirely new"))).toContain(
      COMPANION_UNCLASSIFIED_NEXT_STEP,
    );
  });
});

describe("a reset that may lock the phone instead warns before the press", () => {
  it("puts both outcomes in the confirm block, above the button", () => {
    // reset_before_witness_rotation refuses whenever a pending approval or any
    // witness record exists, and durably rewrites the rotation phase before
    // returning the refusal, so the press permanently removes the section.
    const security = withoutComments(read("agent/CompanionSecurity.tsx"));
    const warning = security.indexOf("It may do something else instead");
    const button = security.lastIndexOf("{COMPANION_RESET_PAIRING_ACTION}");
    expect(warning).toBeGreaterThan(0);
    expect(warning).toBeLessThan(button);
    expect(disclosureDepth(security, warning)).toBe(0);
    expect(flatten(security)).toContain(
      "this section is then replaced for good by Controlled witness rotation required",
    );
  });

  it("no longer offers the reset at all when the native side would refuse it", () => {
    // Dead end 2. controlledRotationRequired only reads rotation_phase, but
    // reset_before_witness_rotation refuses on the wider
    // rotation_blocking_phase(), which also covers a pending pilot approval and
    // any witness record. The phone could not see those two facts, so it
    // offered a button that could only refuse - and the refusal permanently
    // replaced the section.
    const security = withoutComments(read("agent/CompanionSecurity.tsx"));
    expect(security).toContain("stored?.resetBlockingPhase");
    // The blocked branch now splits on what is actually holding the reset: a
    // held consent record is not a rotation matter, and the rotation copy is
    // still exactly what a witness-bearing phone gets.
    expect(security).toContain("{resetBlocked && heldConsent ? (");
    expect(security).toContain(") : resetBlocked ? (");
    const commands = readWorkspace(
      "apps/mobile/src-tauri/src/agent_companion/commands.rs",
    );
    expect(commands).toContain("reset_blocking_phase");
    expect(commands).toContain("rotation_blocking_phase()");
    // And the marker no longer outlives its own cause.
    const pilot = readWorkspace(
      "apps/mobile/src-tauri/src/agent_companion/pilot.rs",
    );
    expect(pilot).toContain("next.clear_pending_approval_for(operation_id)?");
    const storage = readWorkspace(
      "apps/mobile/src-tauri/src/agent_companion/storage.rs",
    );
    const rewind = storage.slice(
      storage.indexOf("fn rewind_reset_refusal_marker"),
    );
    expect(rewind).toContain("WitnessRotationPhase::BlockedByPendingApproval");
    // The same rewind now covers the witness marker, so the approval and the
    // confirmation cannot drift into two different lifecycles again.
    expect(rewind).toContain(
      "WitnessRotationPhase::BlockedByUnresolvedSignedOperation",
    );
    expect(rewind).toContain("WitnessRotationPhase::Stable");
  });
});

describe("a phone whose secure identity is gone can retire its pairing", () => {
  it("offers the escape only when the pairing is orphaned, under its own words", () => {
    // Dead end 4. The pairing-only reset is refused forever once witness state
    // exists, so a revoked phone following the recovery guide was finished.
    const security = withoutComments(read("agent/CompanionSecurity.tsx"));
    expect(security).toContain('stored?.pairingIdentity === "replaced"');
    expect(security).toContain('stored?.pairingIdentity === "absent"');
    expect(security).toContain("{pairingOrphaned ? (");
    expect(security).toContain("COMPANION_RETIRE_PAIRING_ACTION");
    // Distinct words from the ordinary reset, so one can never be pressed for
    // the other.
    expect(security).toContain("RETIRE THIS PAIRING");
    expect(security).toContain('retireText !== "RETIRE THIS PAIRING"');
    // The cost is stated before the press and is not behind a disclosure.
    const warning = security.indexOf("together with the record of which wallet");
    expect(warning).toBeGreaterThan(0);
    expect(disclosureDepth(security, warning)).toBe(0);
    expect(flatten(security)).toContain(
      "together with the record of which wallet states it has already witnessed",
    );
  });

  it("is refused by the native side whenever the paired key is still live", () => {
    const storage = readWorkspace(
      "apps/mobile/src-tauri/src/agent_companion/storage.rs",
    );
    const retire = storage.slice(
      storage.indexOf("pub(super) async fn reset_orphaned_pairing"),
    );
    // The invariant is checked against the durable state, not taken from the UI.
    expect(retire).toContain(
      "live_device_id == Some(&current.mobile_device_id)",
    );
    const commands = readWorkspace(
      "apps/mobile/src-tauri/src/agent_companion/commands.rs",
    );
    // The Keystore is re-read in the command, and a failed read is an error
    // rather than a licence to erase.
    expect(commands).toContain("live_companion_device_id(app).await?");
    expect(commands).toContain("Err(_) => PairingIdentityState::Unknown");
    expect(commands).toContain("ORPHANED_RESET_CONFIRMATION");
  });

  it("gives the recovery guide an order the code actually accepts", () => {
    // The guide used to say: run the pairing-only reset, then replace the
    // identity. The first of those is refused for exactly the phone the guide
    // is written for, and being refused permanently replaces the reset section.
    const steps = COMPANION_REVOKED_RECOVERY_STEPS;
    const biometric = steps.findIndex((step) =>
      /enrol a new fingerprint/i.test(step.action),
    );
    const retire = steps.findIndex((step) =>
      step.action.includes(COMPANION_RETIRE_PAIRING_ACTION),
    );
    expect(biometric).toBeGreaterThanOrEqual(0);
    expect(retire).toBeGreaterThan(biometric);
    expect(
      steps.some((step) =>
        new RegExp(`Run ${COMPANION_RESET_PAIRING_ACTION}`, "i").test(
          step.action,
        ),
      ),
      "the guide must not instruct a reset the code refuses",
    ).toBe(false);
    expect(COMPANION_REVOKED_ORDER_MATTERS).toMatch(/in order/i);
    expect(COMPANION_REVOKED_ORDER_MATTERS).toMatch(/refused/i);
  });
});

describe("the rotation acknowledgement QR is not offered as a step to hide", () => {
  it("warns that it cannot be shown again, and relabels the button", () => {
    // It is the only delivery path for step 4 of the desktop flow, is held in
    // React state alone, and the pairing block stops rendering once the
    // durable state is installed - so dismissing it destroys the only copy.
    const panel = withoutComments(read("agent/CompanionPairingPanel.tsx"));
    const rotation = panel.slice(
      panel.indexOf("hpay_rotation_candidate_ack_v1"),
      panel.indexOf("</section>", panel.indexOf("hpay_rotation_candidate_ack_v1")),
    );
    expect(flatten(rotation)).toContain("This QR code cannot be shown again");
    expect(rotation).toContain('automaticPairing ? "" : "agent-danger-action"');
    expect(rotation).toContain('"Discard this rotation QR permanently"');
    expect(disclosureDepth(panel, panel.indexOf("This QR code cannot be shown again"))).toBe(0);
  });
});

describe("the phone rotation control the desktop quotes really exists", () => {
  it("renders the exact label WitnessRotationPanel names", () => {
    const desktop = readWorkspace(
      "apps/desktop/src/agent/WitnessRotationPanel.tsx",
    );
    const label = desktop
      .split('const COMPANION_PHONE_ROTATION_ACTION = "')[1]
      .split('"')[0];
    const security = withoutComments(read("agent/CompanionSecurity.tsx"));
    expect(security).toContain(`>\n            ${label}\n          </button>`);
    // And the section heading the desktop sends the owner to.
    expect(security).toContain("<h2>Approval phone rotation</h2>");
    // The retired instruction may never come back.
    expect(withoutComments(desktop)).not.toContain("Continue witness rotation");
  });
});

describe("a payment approved on the desktop, witnessed on the phone", () => {
  function withActivity(
    entries: Array<Record<string, string>>,
  ) {
    const state = validatedStoredState(storedState());
    const active = validatedSession(session(), state, NOW_MILLISECONDS);
    return validateCompanionStatusSnapshot(
      nativeSnapshot({ activity: entries as never }),
      active,
      state,
      NOW_MILLISECONDS,
    );
  }

  function entry(overrides: Record<string, string> = {}) {
    return {
      activity_id: "operation_awaiting_witness",
      description: "AI inference",
      asset: "HAC",
      recipient: "1NewDeveloper",
      amount_units: "50000000",
      occurred_at: "1090",
      status: "signed_awaiting_witness",
      ...overrides,
    };
  }

  it("finds the one payment that cannot proceed without this phone", () => {
    for (const status of WITNESS_PENDING_ACTIVITY_STATUSES) {
      const snapshot = withActivity([entry({ status })]);
      const waiting = pendingWitnessOperation(snapshot);
      expect(waiting?.activityId).toBe("operation_awaiting_witness");
      expect(waiting?.status).toBe(status);
      expect(waiting?.amountUnits).toBe("50000000");
      expect(waiting?.recipient).toBe("1NewDeveloper");
    }
  });

  it("offers nothing for a status this phone could not witness anyway", () => {
    for (const status of [
      "committed",
      "cancelled",
      "rejected",
      "failed",
      "approval_requested",
      "signed",
      "witnessed_awaiting_broadcast",
      "broadcast_submitted",
      "reconciliation_required",
      "recovery_required",
    ]) {
      expect(pendingWitnessOperation(withActivity([entry({ status })]))).toBeNull();
    }
    expect(pendingWitnessOperation(withActivity([]))).toBeNull();
    expect(pendingWitnessOperation(null)).toBeNull();
  });

  it("fails closed rather than pick when two payments claim to be waiting", () => {
    const snapshot = withActivity([
      entry(),
      entry({
        activity_id: "operation_two",
        status: "broadcast_uncertain",
        recipient: "1Other",
      }),
    ]);
    expect(pendingWitnessOperation(snapshot)).toBeNull();
  });

  it("names the second act as a witness, never as a second approval", () => {
    const pages = read("agent/CompanionReadOnlyPages.tsx");
    const app = read("agent/AgentCompanionApp.tsx");
    const api = read("agent/api.ts");

    // The owner is shown the amount and recipient they are consenting to, not
    // an opaque operation id.
    expect(pages).toContain("Waiting for your witness");
    expect(pages).toContain("Already approved on HPAY Desktop");
    expect(pages).toContain("formatHacUnits(awaitingWitness.amountUnits)");
    expect(pages).toContain("shortValue(awaitingWitness.recipient)");
    expect(pages).toContain(
      "This is not a second approval and it cannot change the amount or",
    );
    expect(COMPANION_CONFIRM_WITNESS_ACTION).toBe("Confirm and sign witness");
    expect(COMPANION_CONFIRM_WITNESS_ACTION).not.toMatch(/approve/i);

    // A read-only build renders no signing control at all.
    expect(pages).toContain("onWitness && snapshot.pilotEnabled");

    // The webview cannot name a payment of its own: the handler re-derives the
    // waiting operation from the current snapshot and refuses on any drift.
    expect(app).toContain("const current = pendingWitnessOperation(snapshot);");
    expect(app).toContain("current.activityId !== operation.activityId");
    expect(app).toContain("current.amountUnits !== operation.amountUnits");
    expect(app).toContain("current.recipient !== operation.recipient");
    expect(api).toContain('"agent_wallet_companion_witness_pending"');
  });

  it("keeps a real witness signature between approval and broadcast", () => {
    const pilot = readWorkspace(
      "apps/mobile/src-tauri/src/agent_companion/pilot.rs",
    );
    const witness = readWorkspace("crates/companion-protocol/src/witness.rs");
    const payment = readWorkspace(
      "crates/agent-wallet-core/src/service/payment.rs",
    );

    // The desktop-approved path is a second branch beside the pending approval,
    // never a removal of the requirement.
    expect(pilot).toContain("(None, Some(pending)) => {");
    expect(pilot).toContain(
      "No exact pilot approval or witness confirmation is pending for this anchor",
    );
    // Consent is durable before anything is fetched or signed.
    expect(pilot).toContain(
      "// Durable owner consent first, before a single byte is fetched.",
    );
    expect(pilot).toContain("confirmation.validate()?;");
    expect(pilot).toContain("self.shared.persist_locked(&next)?;");

    // The anchor is still a desktop signature this phone verifies, and the
    // network fields are still bound - now to the phone's own durable pins.
    expect(witness).toContain("let anchor_hash = proposal.verify(registry, now)?;");
    expect(witness).toContain(".is_some_and(|pinned| pinned != anchor.node_profile_id)");
    expect(witness).toContain(
      ".is_some_and(|pinned| pinned != anchor.transaction_format_version)",
    );
    expect(witness).toContain(".is_some_and(|pinned| anchor.policy_epoch < pinned)");

    // Broadcast still requires the witness receipt.
    expect(payment).toContain("WitnessedAwaitingBroadcast");
  });
});

describe("a phone can let go of a payment it is holding", () => {
  const heldRecord = {
    kind: "witness_confirmation" as const,
    operationId: "operation_one",
    amountUnits: "50000000",
    recipient: "1NewDeveloper",
    recordedAtUnix: "1000",
  };
  const discardedRecord = {
    ...heldRecord,
    discardedAtUnix: "2000",
    reason: "desktop_no_longer_awaits_this_phone",
  };

  /**
   * The headline stranding path, from the screen's side.
   *
   * A confirmation the desktop stopped offering blocked the reset, blocked
   * pairing and blocked every other payment - and the only screen that could
   * reach it, the witness card, had disappeared with the operation. The
   * security screen now shows what is held.
   */
  it("names the exact payment it is holding before offering any way out", () => {
    const security = withoutComments(read("agent/CompanionSecurity.tsx"));
    expect(security).toContain("stored?.pendingConsent ?? null");
    expect(security).toContain("heldConsentFacts(heldConsent)");
    expect(security).toContain("heldConsentExplanation(heldConsent)");
    const facts = heldConsentFacts(heldRecord);
    expect(facts.map((fact) => fact.label)).toEqual([
      "Amount",
      "To",
      "Payment",
      "Held since",
    ]);
    expect(facts[0].value).toBe(formatHacUnits("50000000"));
    expect(facts[1].value).toBe("1NewDeveloper");
    expect(facts[2].value).toBe("operation_one");
    // And it says why the phone is stuck, and that syncing is the better route
    // whenever the desktop is still there.
    const explanation = heldConsentExplanation(heldRecord);
    expect(explanation).toContain("cannot be reset");
    expect(explanation).toContain("cannot approve or witness any other payment");
    expect(explanation).toContain("connect and sync instead");
  });

  /**
   * What it costs is stated before the press, and the one thing it must never
   * be mistaken for is stated outright.
   */
  it("states what discarding does and does not do before the confirmation", () => {
    const security = withoutComments(read("agent/CompanionSecurity.tsx"));
    const effects = security.indexOf("COMPANION_DISCARD_CONSENT_EFFECTS");
    const confirm = security.indexOf(
      "discardText !== COMPANION_DISCARD_CONSENT_PHRASE",
    );
    expect(effects).toBeGreaterThan(-1);
    expect(effects).toBeLessThan(confirm);
    const stated = COMPANION_DISCARD_CONSENT_EFFECTS.join(" ");
    expect(stated).toContain("does not cancel the payment");
    expect(stated).toContain("does not un-sign anything");
    expect(stated).toContain("does not mark the payment as witnessed");
    expect(stated).toContain("deletes no pairing");
  });

  /** Three acts, three sentences. None can ever be pressed for another. */
  it("uses its own words, distinct from both resets", () => {
    expect(COMPANION_DISCARD_CONSENT_PHRASE).toBe("DISCARD THIS CONFIRMATION");
    expect(COMPANION_DISCARD_CONSENT_PHRASE).not.toBe("RESET COMPANION");
    expect(COMPANION_DISCARD_CONSENT_PHRASE).not.toBe(
      COMPANION_RETIRE_PAIRING_ACTION,
    );
    expect(COMPANION_DISCARD_CONSENT_PHRASE).not.toBe("RETIRE THIS PAIRING");
    const security = withoutComments(read("agent/CompanionSecurity.tsx"));
    expect(security).toContain(
      "discardText !== COMPANION_DISCARD_CONSENT_PHRASE",
    );
    const app = withoutComments(read("agent/AgentCompanionApp.tsx"));
    expect(app).toContain("discardText !== COMPANION_DISCARD_CONSENT_PHRASE");
    // The press can only ever discard the payment the screen showed: the id
    // comes from the native record, never from the button.
    expect(app).toContain("companion.stored?.pendingConsent");
    expect(app).toContain(".discardHeldConsent(held.operationId)");
  });

  /**
   * Dead end 5, from the screen's side: a held record is not a rotation
   * problem, and telling the owner to run one is what made it permanent.
   */
  it("does not send an owner holding a confirmation into a rotation", () => {
    const security = withoutComments(read("agent/CompanionSecurity.tsx"));
    const heldBranch = security.indexOf("{resetBlocked && heldConsent ? (");
    const rotationBranch = security.indexOf(") : resetBlocked ? (");
    expect(heldBranch).toBeGreaterThan(-1);
    expect(rotationBranch).toBeGreaterThan(heldBranch);
    // The rotation copy still exists, for the phone it is actually true of.
    expect(security).toContain("Controlled witness rotation required");
    // And the native refusal names the real blocker rather than a rotation.
    const storage = readWorkspace(
      "apps/mobile/src-tauri/src/agent_companion/storage.rs",
    );
    expect(storage).toContain("fn reset_refusal_message");
    expect(storage).toContain("holding your confirmation");
    expect(storage).toContain("Running a witness rotation does not clear it.");
    // A refusal must not overwrite a rotation the owner already finished.
    expect(storage).toContain(
      "if current.rotation_phase != WitnessRotationPhase::Completed",
    );
  });

  /** A discard is never silent, and never claims the payment succeeded. */
  it("shows a receipt afterwards that claims nothing about the payment", () => {
    const notice = discardedConsentNotice(discardedRecord);
    expect(notice.body).toContain("no longer waiting on this phone");
    expect(notice.body).toContain(
      "does not tell you whether the payment went through",
    );
    expect(notice.facts.map((fact) => fact.label)).toEqual([
      "Amount",
      "To",
      "Payment",
      "Stopped holding",
    ]);
    expect(
      discardedConsentNotice({
        ...discardedRecord,
        reason: "aged_out_on_this_phone",
      }).body,
    ).toContain("No desktop confirmed anything about this payment for a day");
    expect(
      discardedConsentNotice({ ...discardedRecord, reason: "owner_discarded" })
        .body,
    ).toContain("You discarded this on this phone");
    const security = withoutComments(read("agent/CompanionSecurity.tsx"));
    // Every receipt is rendered, not only the newest one.
    expect(security).toContain("stored?.discardedConsents ?? []");
    expect(security).toContain("{discardedConsents.length > 0 ? (");
    expect(security).toContain("discardedConsents.map((record, index) => {");
    expect(security).toContain("discardedConsentNotice(record)");
  });

  /**
   * The defect this history exists to fix, from the screen's side.
   *
   * `discardedConsent` was one slot, last-write-wins: discard the confirmation
   * for one payment, then hold and discard another, and the first receipt was
   * gone with nothing said. Evidence loss is the whole thing the receipt is
   * for. Both receipts now reach the screen, newest first, and both are
   * rendered rather than the last one alone.
   */
  it("keeps every receipt when a second payment is discarded after the first", () => {
    const first = discardedRecord;
    const second = {
      ...discardedRecord,
      operationId: "operation_two",
      discardedAtUnix: "3000",
      reason: "owner_discarded",
    };
    // Newest first, the order the native side reports.
    const state = validatedStoredState(
      storedState({ discardedConsents: [second, first] }),
    );
    expect(state.discardedConsents).toHaveLength(2);
    const notices = state.discardedConsents.map(discardedConsentNotice);
    expect(notices.map((notice) => notice.facts[2]?.value)).toEqual([
      "operation_two",
      "operation_one",
    ]);
    // The older receipt is still readable in full, not just counted.
    expect(notices[1]?.body).toContain("no longer waiting on this phone");
    // Nothing was dropped, so the phone says nothing about a cap.
    expect(discardedConsentOverflowNotice(state.discardedConsentsDropped)).toBeNull();
  });

  /**
   * Bounded, and never silently so.
   *
   * The history is capped, because an unbounded list on a handset is its own
   * defect. Dropping the oldest without a word would be the same defect as the
   * single slot, so the count is carried across the boundary and stated on the
   * screen in the owner's words.
   */
  it("says how many receipts the cap dropped instead of quietly losing them", () => {
    const full = Array.from(
      { length: MAX_COMPANION_DISCARDED_CONSENTS },
      (_unused, index) => ({
        ...discardedRecord,
        operationId: `operation_${index}`,
      }),
    );
    const state = validatedStoredState(
      storedState({ discardedConsents: full, discardedConsentsDropped: "4" }),
    );
    const overflow = discardedConsentOverflowNotice(
      state.discardedConsentsDropped,
    );
    expect(overflow).toContain("4 older receipts");
    expect(overflow).toContain(`last ${MAX_COMPANION_DISCARDED_CONSENTS}`);
    expect(overflow).toContain("HPAY Desktop");
    expect(discardedConsentOverflowNotice("1")).toContain("1 older receipt is");
    // The screen renders it, rather than the count living only in the state.
    const security = withoutComments(read("agent/CompanionSecurity.tsx"));
    expect(security).toContain("discardedConsentOverflowNotice(");
    expect(security).toContain("{discardOverflow ? (");

    // A history longer than the native cap, or a drop count on a history that
    // is not full, is a state the phone could not have written.
    expect(() =>
      validatedStoredState(
        storedState({ discardedConsents: [...full, discardedRecord] }),
      ),
    ).toThrow();
    expect(() =>
      validatedStoredState(
        storedState({
          discardedConsents: [discardedRecord],
          discardedConsentsDropped: "1",
        }),
      ),
    ).toThrow();

    // And the native side caps it at the same number this screen assumes.
    const storage = readWorkspace(
      "apps/mobile/src-tauri/src/agent_companion/storage.rs",
    );
    expect(storage).toContain(
      `pub(super) const MAX_DISCARDED_CONSENTS: usize = ${MAX_COMPANION_DISCARDED_CONSENTS};`,
    );
    expect(storage).toContain("fn push_discard_bounded(");
  });

  /**
   * Most of the escape is not a button at all.
   *
   * The desktop's own authenticated snapshot says which operations are still
   * waiting on this phone, and a record naming anything else is retired on the
   * next sync. A transport failure states nothing and retires nothing.
   */
  it("clears itself from the desktop's own statement rather than from a press", () => {
    const commands = readWorkspace(
      "apps/mobile/src-tauri/src/agent_companion/commands.rs",
    );
    expect(commands).toContain("witness_pending_operation_ids(&view.activity)");
    expect(commands).toContain("state.sweep_obsolete_consent(Some(&awaiting))");
    const storage = readWorkspace(
      "apps/mobile/src-tauri/src/agent_companion/storage.rs",
    );
    expect(storage).toContain("fn obsolete_consent");
    expect(storage).toContain("CONSENT_DESKTOP_SILENCE_GRACE_SECS");
    expect(storage).toContain("CONSENT_MAX_AGE_SECS");
    // The sweep never runs over a flow that is using the record.
    const mod = readWorkspace(
      "apps/mobile/src-tauri/src/agent_companion/mod.rs",
    );
    expect(mod).toContain("self.consent_flow.try_lock()");
    const pilot = readWorkspace(
      "apps/mobile/src-tauri/src/agent_companion/pilot.rs",
    );
    expect(pilot).toContain("let _flow = state.consent_flow.lock().await;");
    // And the headline path: any accepted acknowledgement retires the record,
    // not only the committed one.
    expect(pilot).toContain(
      "fn witness_ack_retires_consent(accepted: bool, detail: &str)",
    );
    expect(pilot).toContain(
      "if witness_ack_retires_consent(accepted, &detail) {",
    );
  });

  /** Consent records cross the native boundary, so they are checked like it. */
  it("refuses a malformed consent record rather than rendering a blank one", () => {
    validatedStoredState(
      storedState({
        pendingConsent: heldRecord,
        discardedConsents: [discardedRecord],
      }),
    );
    for (const brokenHistory of [
      [{ ...discardedRecord, reason: "" }],
      [{ ...discardedRecord, discardedAtUnix: "later" }],
      [{ ...discardedRecord, extra: "field" }],
      [null],
      discardedRecord as never,
    ]) {
      expect(() =>
        validatedStoredState(
          storedState({ discardedConsents: brokenHistory as never }),
        ),
      ).toThrow();
    }
    for (const broken of [
      { ...heldRecord, kind: "something_else" },
      { ...heldRecord, amountUnits: "not a number" },
      { ...heldRecord, recipient: "" },
      { ...heldRecord, operationId: "" },
      { ...heldRecord, extra: "field" },
    ]) {
      expect(() =>
        validatedStoredState(storedState({ pendingConsent: broken as never })),
      ).toThrow();
    }
    // A phone with no pairing holds no payment and has discarded none.
    expect(() =>
      validatedStoredState(
        storedState({
          configured: false,
          connected: false,
          agentWalletId: null,
          desktopDeviceId: null,
          mobileDeviceId: null,
          endpoints: [],
          responseSequence: null,
          pairingIdentity: "not_paired",
          pendingConsent: heldRecord,
        }),
      ),
    ).toThrow();
  });

  /** An owner holding nothing sees none of this. */
  it("shows nothing at all to a phone that is holding nothing", () => {
    const clean = validatedStoredState(storedState());
    expect(clean.pendingConsent).toBeNull();
    expect(clean.discardedConsents).toEqual([]);
    expect(clean.discardedConsentsDropped).toBe("0");
    // No history, so no heading, no cap sentence and no receipt card.
    expect(discardedConsentOverflowNotice(clean.discardedConsentsDropped)).toBeNull();
    // And a phone that never discarded anything writes no new durable key.
    const storage = readWorkspace(
      "apps/mobile/src-tauri/src/agent_companion/storage.rs",
    );
    expect(storage).toContain(
      'skip_serializing_if = "is_decimal_zero"',
    );
    expect(storage).toContain(
      '#[serde(default, skip_serializing_if = "Vec::is_empty")]\n    discarded_consents: Vec<MobileDiscardedConsent>,',
    );
  });
});

describe("Agent Fast Pay mobile approval boundary", () => {
  it("shows exact zero-fee facts and never sends WebView commitment data to native", () => {
    const card = read("agent/AgentFastPayApprovalCard.tsx");
    const app = read("agent/AgentCompanionApp.tsx");
    const api = read("agent/api.ts");
    expect(card).toContain('label="Amount"');
    expect(card).toContain('label="To"');
    expect(card).toContain('label="HPAY wallet fee" value="None"');
    expect(card).toContain('label="Hub fee" value="None"');
    expect(card).toContain("This phone never receives the Agent Wallet key");
    expect(card).toContain("Approve Fast Pay");
    expect(card).toContain("Reject");
    expect(app).toContain("agentCompanionApi.decideFastPay(");
    expect(app).toContain("approval.operation_id");
    expect(api).toContain('"agent_wallet_companion_pending_fast_pay"');
    expect(api).toContain('"agent_wallet_companion_decide_fast_pay"');
    expect(api).not.toContain("decideFastPay: (commitment");
  });

  it("persists one exact biometric signature before transport and retries no other bytes", () => {
    const pilot = readWorkspace(
      "apps/mobile/src-tauri/src/agent_companion/pilot.rs",
    );
    const session = readWorkspace(
      "apps/mobile/src-tauri/src/agent_companion/session.rs",
    );
    const storage = readWorkspace(
      "apps/mobile/src-tauri/src/agent_companion/storage.rs",
    );
    expect(pilot).toContain("SignedAgentFastPayApprovalDecision::sign(");
    expect(pilot).toContain("pending.signed_decision = Some(signed.clone());");
    expect(pilot).toContain("// The exact signature bytes are durable before transport.");
    expect(pilot).toContain("PreparedAgentFastPayDecision::Signed(signed)");
    expect(session).toContain("OutboundKind::AgentFastPayApprovalPoll { .. }");
    expect(session).toContain("OutboundKind::AgentFastPayApprovalDecision(signed)");
    expect(storage).toContain("pending_agent_fast_pay_approval");
    expect(storage).toContain("Only one mobile payment consent may be pending");
  });
});

describe("Agent HVM Fast Pay mobile approval boundary", () => {
  it("shows the exact contract, 18-lease and zero-fee facts", () => {
    const card = read("agent/AgentHvmApprovalCard.tsx");
    const app = read("agent/AgentCompanionApp.tsx");
    const api = read("agent/api.ts");
    expect(card).toContain('label="Amount"');
    expect(card).toContain('label="To"');
    expect(card).toContain('label="Contract"');
    expect(card).toContain('label="Contract leases" value="18 bound and verified"');
    expect(card).toContain('label="HPAY wallet fee" value="None"');
    expect(card).toContain('label="Hub fee" value="None"');
    expect(card).toContain("The Agent");
    expect(card).toContain("key and your Personal Wallet key never enter this phone");
    expect(app).toContain("agentCompanionApi.decideHvmFastPay(");
    expect(app).toContain("approval.operation_id");
    expect(api).toContain('"agent_wallet_companion_pending_hvm_fast_pay"');
    expect(api).toContain('"agent_wallet_companion_decide_hvm_fast_pay"');
    expect(api).not.toContain("decideHvmFastPay: (commitment");
  });

  it("persists one exact HVM biometric signature before transport", () => {
    const pilot = readWorkspace(
      "apps/mobile/src-tauri/src/agent_companion/pilot.rs",
    );
    const session = readWorkspace(
      "apps/mobile/src-tauri/src/agent_companion/session.rs",
    );
    const storage = readWorkspace(
      "apps/mobile/src-tauri/src/agent_companion/storage.rs",
    );
    expect(pilot).toContain("SignedAgentHvmApprovalDecision::sign(");
    expect(pilot).toContain("PreparedAgentHvmDecision::Signed(signed)");
    expect(session).toContain("OutboundKind::AgentHvmApprovalPoll { .. }");
    expect(session).toContain("OutboundKind::AgentHvmApprovalDecision(signed)");
    expect(storage).toContain("pending_agent_hvm_approval");
    expect(storage).toContain("network_fee_zhu != 0");
    expect(storage).toContain("wallet_fee_zhu != 0");
    expect(storage).toContain("hub_fee_zhu != 0");
  });
});

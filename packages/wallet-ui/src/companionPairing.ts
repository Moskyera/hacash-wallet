export type CompanionPairingOffer = {
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

export type CompanionPairingRequest = {
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

export type CompanionPairingConfirmation = {
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

export type CompanionEncryptedFrame = {
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

const OFFER_PREFIX = "hpay:companion:offer:v1:";
const REQUEST_PREFIX = "hpay:companion:request:v1:";
const CONFIRMATION_PREFIX = "hpay:companion:confirmation:v1:";
const ACK_PREFIX = "hpay:companion:ack:v1:";
const MAX_QR_PAYLOAD_BYTES = 256 * 1024;

export const MAX_COMPANION_QR_TEXT_CHARS = MAX_QR_PAYLOAD_BYTES + 128;

const OFFER_FIELDS = [
  "protocol_version",
  "pairing_id",
  "agent_wallet_id",
  "desktop_device_id",
  "desktop_ephemeral_public_key",
  "desktop_identity_public_key",
  "desktop_identity_fingerprint",
  "lan_endpoints",
  "pairing_nonce",
  "issued_at",
  "expires_at",
] as const;

const REQUEST_FIELDS = [
  "protocol_version",
  "pairing_id",
  "agent_wallet_id",
  "desktop_device_id",
  "mobile_device_id",
  "mobile_ephemeral_public_key",
  "mobile_identity_public_key",
  "mobile_identity_fingerprint",
  "pairing_nonce",
  "mobile_challenge",
  "issued_at",
  "expires_at",
  "identity_signature",
] as const;

const CONFIRMATION_FIELDS = [
  "protocol_version",
  "pairing_id",
  "agent_wallet_id",
  "desktop_device_id",
  "mobile_device_id",
  "desktop_challenge",
  "verification_code",
  "session_id",
  "issued_at",
  "expires_at",
  "desktop_identity_signature",
] as const;

const FRAME_FIELDS = [
  "frame_version",
  "session_id",
  "sender_device_id",
  "recipient_device_id",
  "sequence",
  "issued_at",
  "expires_at",
  "nonce_hex",
  "ciphertext_hex",
] as const;

export function encodeCompanionOffer(value: CompanionPairingOffer): string {
  return OFFER_PREFIX + JSON.stringify(value);
}

export function parseCompanionOffer(raw: string): CompanionPairingOffer {
  const value = parseObject(raw, OFFER_PREFIX);
  requireExactFields(value, OFFER_FIELDS);
  requireStringArray(value, "lan_endpoints");
  requireDecimalString(value, "protocol_version");
  requireDecimalString(value, "issued_at");
  requireDecimalString(value, "expires_at");
  if (value.protocol_version !== "1") {
    throw new Error("The pairing offer uses an unsupported version.");
  }
  return value as CompanionPairingOffer;
}

export function encodeCompanionRequest(value: CompanionPairingRequest): string {
  return REQUEST_PREFIX + JSON.stringify(value);
}

export function parseCompanionRequest(
  raw: string,
  expectedWalletId: string,
  expectedPairingId: string,
): CompanionPairingRequest {
  const value = parseObject(raw, REQUEST_PREFIX);
  requireExactStringFields(value, REQUEST_FIELDS);
  requireDecimalString(value, "protocol_version");
  requireDecimalString(value, "issued_at");
  requireDecimalString(value, "expires_at");
  if (
    value.protocol_version !== "1" ||
    value.agent_wallet_id !== expectedWalletId ||
    value.pairing_id !== expectedPairingId
  ) {
    throw new Error(
      "The mobile request belongs to a different pairing or Agent Wallet.",
    );
  }
  return value as CompanionPairingRequest;
}

export function encodeCompanionConfirmation(
  value: CompanionPairingConfirmation,
): string {
  return CONFIRMATION_PREFIX + JSON.stringify(value);
}

export function parseCompanionConfirmation(
  raw: string,
  expected: {
    walletId: string;
    pairingId: string;
    desktopDeviceId: string;
    mobileDeviceId: string;
  },
): CompanionPairingConfirmation {
  const value = parseObject(raw, CONFIRMATION_PREFIX);
  requireExactStringFields(value, CONFIRMATION_FIELDS);
  requireDecimalString(value, "protocol_version");
  requireDecimalString(value, "issued_at");
  requireDecimalString(value, "expires_at");
  if (
    value.protocol_version !== "1" ||
    value.agent_wallet_id !== expected.walletId ||
    value.pairing_id !== expected.pairingId ||
    value.desktop_device_id !== expected.desktopDeviceId ||
    value.mobile_device_id !== expected.mobileDeviceId
  ) {
    throw new Error("The desktop confirmation does not match this pairing.");
  }
  return value as CompanionPairingConfirmation;
}

export function encodeCompanionAck(value: CompanionEncryptedFrame): string {
  return ACK_PREFIX + JSON.stringify(value);
}

export function parseCompanionAck(
  raw: string,
  expectedSessionId: string,
  expectedMobileDeviceId: string,
  expectedDesktopDeviceId: string,
): CompanionEncryptedFrame {
  const value = parseObject(raw, ACK_PREFIX);
  requireExactStringFields(value, FRAME_FIELDS);
  requireDecimalString(value, "frame_version");
  requireDecimalString(value, "sequence");
  requireDecimalString(value, "issued_at");
  requireDecimalString(value, "expires_at");
  if (
    value.frame_version !== "1" ||
    value.session_id !== expectedSessionId ||
    value.sender_device_id !== expectedMobileDeviceId ||
    value.recipient_device_id !== expectedDesktopDeviceId
  ) {
    throw new Error("The encrypted acknowledgement does not match this pairing.");
  }
  return value as CompanionEncryptedFrame;
}

function parseObject(raw: string, prefix: string): Record<string, unknown> {
  const normalized = raw.trim();
  if (!normalized.startsWith(prefix)) {
    throw new Error("This is not the expected HPAY companion pairing payload.");
  }
  const json = normalized.slice(prefix.length);
  if (!json || new TextEncoder().encode(json).length > MAX_QR_PAYLOAD_BYTES) {
    throw new Error("The pairing payload is empty or too large.");
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(json);
  } catch {
    throw new Error("The pairing payload is not valid JSON.");
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("The pairing payload has an invalid shape.");
  }
  return parsed as Record<string, unknown>;
}

function requireExactFields(
  value: Record<string, unknown>,
  expected: readonly string[],
): void {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (
    actual.length !== wanted.length ||
    actual.some((field, index) => field !== wanted[index])
  ) {
    throw new Error("The pairing payload contains missing or unknown fields.");
  }
}

function requireExactStringFields(
  value: Record<string, unknown>,
  expected: readonly string[],
): void {
  requireExactFields(value, expected);
  for (const field of expected) {
    if (typeof value[field] !== "string" || value[field].length === 0) {
      throw new Error(`The pairing field ${field} is invalid.`);
    }
  }
}

function requireStringArray(
  value: Record<string, unknown>,
  field: string,
): void {
  const items = value[field];
  if (
    !Array.isArray(items) ||
    items.length === 0 ||
    items.some((item) => typeof item !== "string" || item.length === 0)
  ) {
    throw new Error(`The pairing field ${field} is invalid.`);
  }
  for (const [name, item] of Object.entries(value)) {
    if (name !== field && (typeof item !== "string" || item.length === 0)) {
      throw new Error(`The pairing field ${name} is invalid.`);
    }
  }
}

function requireDecimalString(
  value: Record<string, unknown>,
  field: string,
): void {
  const raw = value[field];
  if (typeof raw !== "string" || !/^(0|[1-9]\d{0,19})$/.test(raw)) {
    throw new Error(`The pairing field ${field} is invalid.`);
  }
}

export const companionPairingPrefixes = {
  offer: OFFER_PREFIX,
  request: REQUEST_PREFIX,
  confirmation: CONFIRMATION_PREFIX,
  acknowledgement: ACK_PREFIX,
} as const;

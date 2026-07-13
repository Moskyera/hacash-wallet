export const PRIVATE_KEY_HEX_LEN = 64;
export const PRIVATE_KEY_QR_PREFIX = "hacash:pk:v1:";

export function normalizePrivateKeyHex(raw: string): string | null {
  const trimmed = raw.trim().toLowerCase();
  if (/^[0-9a-f]{64}$/.test(trimmed)) {
    return trimmed;
  }
  return null;
}

export function encodePrivateKeyQr(hex: string): string {
  const normalized = normalizePrivateKeyHex(hex);
  if (!normalized) {
    throw new Error(`Private key must be ${PRIVATE_KEY_HEX_LEN} hexadecimal characters`);
  }
  return `${PRIVATE_KEY_QR_PREFIX}${normalized}`;
}

export function parsePrivateKeyQr(payload: string): string | null {
  const trimmed = payload.trim();
  if (!trimmed) return null;

  if (trimmed.toLowerCase().startsWith(PRIVATE_KEY_QR_PREFIX)) {
    return normalizePrivateKeyHex(trimmed.slice(PRIVATE_KEY_QR_PREFIX.length));
  }

  return normalizePrivateKeyHex(trimmed);
}
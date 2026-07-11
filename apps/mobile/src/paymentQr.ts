/** Hacash payment QR / URI helpers (BIP21-style). */

export type PaymentQrPayload = {
  address: string;
  amount_mei?: number;
  label?: string;
};

const HACASH_ADDRESS_RE = /^1[1-9A-HJ-NP-Za-km-z]{25,45}$/;

export function isValidHacashAddress(address: string): boolean {
  return HACASH_ADDRESS_RE.test(address.trim());
}

export function encodePaymentUri(
  address: string,
  amountMei?: number,
  label?: string,
): string {
  const addr = address.trim();
  if (!isValidHacashAddress(addr)) {
    throw new Error("Invalid Hacash address");
  }
  const params = new URLSearchParams();
  if (amountMei != null && amountMei > 0) {
    params.set("amount", String(amountMei));
  }
  if (label?.trim()) {
    params.set("label", label.trim());
  }
  const query = params.toString();
  return query ? `hacash:${addr}?${query}` : `hacash:${addr}`;
}

function parseAmount(value: string | null | undefined): number | undefined {
  if (value == null || value === "") return undefined;
  const n = Number(value);
  if (!Number.isFinite(n) || n <= 0) return undefined;
  return n;
}

export function parsePaymentQr(raw: string): PaymentQrPayload | null {
  const text = raw.trim();
  if (!text) return null;

  if (text.startsWith("{")) {
    try {
      const json = JSON.parse(text) as Record<string, unknown>;
      const address =
        typeof json.address === "string"
          ? json.address.trim()
          : typeof json.to === "string"
            ? json.to.trim()
            : "";
      if (!isValidHacashAddress(address)) return null;
      const amountRaw = json.amount_mei ?? json.amount;
      const amount_mei =
        typeof amountRaw === "number"
          ? amountRaw
          : typeof amountRaw === "string"
            ? parseAmount(amountRaw)
            : undefined;
      const label = typeof json.label === "string" ? json.label : undefined;
      return { address, amount_mei, label };
    } catch {
      return null;
    }
  }

  const lower = text.toLowerCase();
  if (lower.startsWith("hacash:")) {
    const rest = text.slice(7);
    const qIndex = rest.indexOf("?");
    const addrPart = (qIndex >= 0 ? rest.slice(0, qIndex) : rest).trim();
    const address = decodeURIComponent(addrPart);
    if (!isValidHacashAddress(address)) return null;
    let amount_mei: number | undefined;
    let label: string | undefined;
    if (qIndex >= 0) {
      const params = new URLSearchParams(rest.slice(qIndex + 1));
      amount_mei = parseAmount(params.get("amount"));
      label = params.get("label") ?? undefined;
    }
    return { address, amount_mei, label };
  }

  if (isValidHacashAddress(text)) {
    return { address: text };
  }

  return null;
}
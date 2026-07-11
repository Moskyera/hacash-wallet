import { isValidHacashAddress, parsePaymentQr, type PaymentQrPayload } from "../paymentQr";

let pendingDeepLinkUrls: string[] = [];

export function stashDeepLinkUrl(url: string) {
  const trimmed = url.trim();
  if (trimmed) pendingDeepLinkUrls.push(trimmed);
}

export function takePendingDeepLinkUrl(): string | null {
  return pendingDeepLinkUrls.shift() ?? null;
}

export function clearPendingDeepLinks() {
  pendingDeepLinkUrls = [];
}

function parseNativeScheme(href: string): PaymentQrPayload | null {
  const trimmed = href.trim();
  const lower = trimmed.toLowerCase();
  if (lower.startsWith("hacash:") || lower.startsWith("hacd:")) {
    const schemeLen = lower.startsWith("hacash:") ? "hacash:".length : "hacd:".length;
    const rest = trimmed.slice(schemeLen).replace(/^\/+/, "");
    return parsePaymentQr(`hacash:${rest}`);
  }
  return null;
}

function parseAddressQuery(text: string): PaymentQrPayload | null {
  const trimmed = text.trim();
  const direct = parsePaymentQr(trimmed);
  if (direct) return direct;
  const qIndex = trimmed.indexOf("?");
  const address = (qIndex >= 0 ? trimmed.slice(0, qIndex) : trimmed).trim();
  if (!isValidHacashAddress(address)) return null;
  let amount_mei: number | undefined;
  let label: string | undefined;
  if (qIndex >= 0) {
    const params = new URLSearchParams(trimmed.slice(qIndex + 1));
    const amount = params.get("amount");
    amount_mei = amount ? Number(amount) : undefined;
    label = params.get("label") ?? undefined;
  }
  return { address, amount_mei, label };
}

export function parseUrlPay(href: string): PaymentQrPayload | null {
  const native = parseNativeScheme(href);
  if (native) return native;

  try {
    const url = new URL(href);
    const payParam = url.searchParams.get("pay");
    if (payParam) {
      const payload = parseAddressQuery(decodeURIComponent(payParam));
      if (payload) return payload;
    }
    const hash = url.hash.replace(/^#/, "");
    if (hash.startsWith("pay=")) {
      return parsePaymentQr(decodeURIComponent(hash.slice(4)));
    }
    if (hash) {
      return parsePaymentQr(decodeURIComponent(hash));
    }
  } catch {
    /* not a full URL — fall through */
  }

  return parsePaymentQr(href);
}

export function parseDeepLinkPay(): PaymentQrPayload | null {
  const pending = takePendingDeepLinkUrl();
  if (pending) return parseUrlPay(pending);

  const native = parseNativeScheme(window.location.href);
  if (native) return native;

  const params = new URLSearchParams(window.location.search);
  const payParam = params.get("pay");
  if (payParam) {
    const payload = parseAddressQuery(decodeURIComponent(payParam));
    if (payload) return payload;
  }
  const hash = window.location.hash.replace(/^#/, "");
  if (!hash) return null;
  if (hash.startsWith("pay=")) {
    return parsePaymentQr(decodeURIComponent(hash.slice(4)));
  }
  return parsePaymentQr(decodeURIComponent(hash));
}

export function clearDeepLink() {
  clearPendingDeepLinks();
  const url = new URL(window.location.href);
  url.searchParams.delete("pay");
  url.hash = "";
  window.history.replaceState({}, "", url.pathname + url.search);
}
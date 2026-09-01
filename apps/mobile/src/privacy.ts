import type { PrivacySettings } from "./api";

export function maskAddress(address: string | null | undefined, hide: boolean): string {
  if (!address) return "N/A";
  if (!hide) return address;
  if (address.length <= 10) return "••••••••";
  return `${address.slice(0, 6)}…${address.slice(-4)}`;
}

export function formatHacMei(value: number | null | undefined): string {
  if (value == null || Number.isNaN(value)) return "N/A";
  if (value === 0) return "0";
  if (value >= 0.001) {
    return value
      .toFixed(3)
      .replace(/(\.\d*?)0+$/, "$1")
      .replace(/\.$/, "");
  }
  return value
    .toFixed(6)
    .replace(/(\.\d*?)0+$/, "$1")
    .replace(/\.$/, "");
}

export function maskBalance(value: number | null | undefined, hide: boolean): string {
  if (hide) return "••••";
  if (value == null) return "N/A";
  return formatHacMei(value);
}

export function formatBtcFromSatoshi(satoshi: number): string {
  return (satoshi / 100_000_000).toFixed(8);
}

export function maskAssetCount(count: number | null | undefined, hide: boolean): string {
  if (hide) return "••••";
  if (count == null) return "N/A";
  return String(count);
}

export function maskBtcFromSatoshi(satoshi: number | null | undefined, hide: boolean): string {
  if (hide) return "••••";
  if (satoshi == null) return "N/A";
  return formatBtcFromSatoshi(satoshi);
}

type ClipboardWriter = Pick<Clipboard, "writeText">;

let walletClipboardGeneration = 0;
let activeWalletClipboardGeneration: number | null = null;

function defaultClipboard(): ClipboardWriter | null {
  return typeof navigator === "undefined" ? null : navigator.clipboard;
}

export async function clearSensitiveClipboard(
  clipboard: ClipboardWriter | null = defaultClipboard(),
): Promise<boolean> {
  if (activeWalletClipboardGeneration == null || !clipboard) return false;
  activeWalletClipboardGeneration = null;
  try {
    await clipboard.writeText("");
    return true;
  } catch {
    return false;
  }
}

export async function copyWithPrivacyClear(
  text: string,
  clipboardClearSecs: number,
  clipboard: ClipboardWriter | null = defaultClipboard(),
): Promise<void> {
  if (!clipboard) throw new Error("Clipboard is unavailable");
  await clipboard.writeText(text);
  const generation = ++walletClipboardGeneration;
  activeWalletClipboardGeneration = generation;
  if (clipboardClearSecs > 0) {
    globalThis.setTimeout(() => {
      if (activeWalletClipboardGeneration !== generation) return;
      void clearSensitiveClipboard(clipboard);
    }, clipboardClearSecs * 1000);
  }
}

/**
 * Copy something, and always tell the person what happened.
 *
 * `copyWithPrivacyClear` throws when the writer is missing and otherwise lets
 * `clipboard.writeText` reject. Six call sites awaited it and then toasted
 * success with no try/catch, and every button fired them as
 * `onClick={() => void copyHacd()}`. A failed write became an unhandled
 * rejection: no success toast, no error toast, a button that looks broken and
 * says nothing. "Copy address" twice on Receive, "Copy HACD receive code",
 * "Copy Hacash address for BTC", the payment URI, and the quantum address.
 *
 * Owning the outcome in one place is the point: a call site cannot forget the
 * catch again, because there is no longer a version of this that throws.
 *
 * Returns whether the copy landed, so a caller that wants to do something more
 * on success still can. It never rejects.
 */
export async function copyAndReport(
  text: string,
  clipboardClearSecs: number,
  onToast: (msg: string, kind: "success" | "info" | "error") => void,
  successMessage: string,
  clipboard: ClipboardWriter | null = defaultClipboard(),
): Promise<boolean> {
  try {
    await copyWithPrivacyClear(text, clipboardClearSecs, clipboard);
  } catch (error) {
    onToast(
      `Nothing was copied: ${error instanceof Error ? error.message : String(error)}`,
      "error",
    );
    return false;
  }
  onToast(successMessage, "success");
  return true;
}

export const DEFAULT_PRIVACY: PrivacySettings = {
  hide_balances: false,
  hide_addresses: false,
  screen_privacy: true,
  store_tx_history: true,
  clipboard_clear_secs: 30,
  pause_auto_lock_dapp: true,
};
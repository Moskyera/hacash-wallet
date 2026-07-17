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

export async function copyWithPrivacyClear(
  text: string,
  clipboardClearSecs: number,
): Promise<void> {
  await navigator.clipboard.writeText(text);
  if (clipboardClearSecs > 0) {
    window.setTimeout(() => {
      navigator.clipboard.writeText("").catch(() => undefined);
    }, clipboardClearSecs * 1000);
  }
}

export const DEFAULT_PRIVACY: PrivacySettings = {
  hide_balances: false,
  hide_addresses: false,
  screen_privacy: true,
  store_tx_history: true,
  clipboard_clear_secs: 30,
  pause_auto_lock_dapp: true,
};
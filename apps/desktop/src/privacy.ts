import type { DustWhisperSettings, PrivacySettings } from "./api";

export function maskAddress(address: string | null | undefined, hide: boolean): string {
  if (!address) return "—";
  if (!hide) return address;
  if (address.length <= 10) return "••••••••";
  return `${address.slice(0, 6)}…${address.slice(-4)}`;
}

export function maskHash(hash: string, hide: boolean): string {
  if (!hide) return hash;
  if (hash.length <= 12) return "••••••••";
  return `${hash.slice(0, 8)}…${hash.slice(-6)}`;
}

export function maskBalance(value: number | null | undefined, hide: boolean): string {
  if (hide) return "••••";
  if (value == null) return "—";
  return value.toFixed(3);
}

export function formatBtcFromSatoshi(satoshi: number): string {
  return (satoshi / 100_000_000).toFixed(8);
}

export function maskBtcFromSatoshi(satoshi: number | null | undefined, hide: boolean): string {
  if (hide) return "••••";
  if (satoshi == null) return "—";
  return formatBtcFromSatoshi(satoshi);
}

export function maskAssetCount(count: number | null | undefined, hide: boolean): string {
  if (hide) return "••••";
  if (count == null) return "—";
  return String(count);
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

export const DEFAULT_DUST_WHISPER: DustWhisperSettings = {
  enabled: false,
  relay_urls: [],
  fallback_direct: true,
  auto_start_relay: true,
};
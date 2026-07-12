import type { DustWhisperSettings } from "./api";

export const DEFAULT_DUST_WHISPER: DustWhisperSettings = {
  enabled: false,
  relay_urls: [],
  fallback_direct: true,
  auto_start_relay: true,
};

export function resolveDustWhisper(
  settings?: DustWhisperSettings | null,
  status?: DustWhisperSettings | null,
): DustWhisperSettings {
  return settings ?? status ?? DEFAULT_DUST_WHISPER;
}

export function hasWhisperRelays(dw: DustWhisperSettings): boolean {
  return dw.relay_urls.some((u) => u.trim().length > 0);
}
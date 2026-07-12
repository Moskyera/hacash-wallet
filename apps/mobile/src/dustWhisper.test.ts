import { describe, expect, it } from "vitest";
import { DEFAULT_DUST_WHISPER, hasWhisperRelays, resolveDustWhisper } from "./dustWhisper";

describe("dustWhisper helpers", () => {
  it("resolves settings over status over default", () => {
    const fromSettings = { ...DEFAULT_DUST_WHISPER, enabled: true, relay_urls: ["http://a"] };
    const fromStatus = { ...DEFAULT_DUST_WHISPER, enabled: true, relay_urls: ["http://b"] };
    expect(resolveDustWhisper(fromSettings, fromStatus).relay_urls[0]).toBe("http://a");
    expect(resolveDustWhisper(null, fromStatus).relay_urls[0]).toBe("http://b");
    expect(resolveDustWhisper(null, null).enabled).toBe(false);
  });

  it("detects configured relay URLs", () => {
    expect(hasWhisperRelays(DEFAULT_DUST_WHISPER)).toBe(false);
    expect(hasWhisperRelays({ ...DEFAULT_DUST_WHISPER, relay_urls: ["  "] })).toBe(false);
    expect(hasWhisperRelays({ ...DEFAULT_DUST_WHISPER, relay_urls: ["http://127.0.0.1:8787"] })).toBe(
      true,
    );
  });
});
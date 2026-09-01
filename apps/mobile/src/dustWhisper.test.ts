import { readFileSync } from "node:fs";
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
/**
 * THE TWO SENTENCES THAT DRIFTED BETWEEN THE SHELLS.
 *
 * Mobile's relay box really is empty on a new wallet, because mobile does not
 * prefill it: a phone cannot host a relay, so there is no own-relay line to put
 * there. The desktop's box IS prefilled and its copy used to claim otherwise.
 * These hold the mobile half to the two things that make its copy honest, so
 * the pair cannot drift again in the other direction.
 */
describe("what the phone's relay box says", () => {
  const source = readFileSync(new URL("./components/WhisperScreen.tsx", import.meta.url), "utf8");

  it("does not prefill the box it says is empty", () => {
    expect(source).toContain("This box is empty on a new wallet");
    // The state the box is built from, which is the wallet's own list and
    // nothing substituted for it.
    expect(source).toMatch(/useState\(\(initial\?\.relay_urls \?\? \[\]\)\.join/);
    expect(source).not.toContain("DEFAULT_DUST_WHISPER.relay_urls");
  });

  it("shows an example in the shape a host actually hands over", () => {
    // The placeholder used to be an https web address while the paragraph
    // beside it tells the reader to paste a plain http LAN address, so the
    // right answer looked wrong against the field's own example.
    expect(source).toMatch(/RELAY_PLACEHOLDER = "http:\/\/\d+\.\d+\.\d+\.\d+:\d+"/);
  });

  it("says what the order of the list does, because only one direction breaks", () => {
    expect(source).toMatch(/stops at the first relay in this list that accepts/i);
    expect(source).toMatch(/checking\s*\n?\s*for new mail tries all of them/i);
    expect(source).toMatch(/replies keep arriving/i);
  });
});

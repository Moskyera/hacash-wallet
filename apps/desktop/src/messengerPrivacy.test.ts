import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { privacyNotice, sealedLabel } from "./messengerPrivacy";

const HERE = dirname(fileURLToPath(import.meta.url));

describe("what the privacy banner is allowed to say", () => {
  it("says nothing at all when the wallet did not answer", () => {
    expect(privacyNotice(null)).toBeNull();
    expect(privacyNotice(undefined)).toBeNull();
  });

  it("warns plainly when the wallet holds no key for the contact", () => {
    const notice = privacyNotice({ sends_sealed: false, unsealed_messages: 0 });
    expect(notice?.tone).toBe("warn");
    expect(notice?.text).toMatch(/relay operator can read/i);
  });

  it("does not let a sealed next message vouch for the messages above it", () => {
    const notice = privacyNotice({ sends_sealed: true, unsealed_messages: 4 });
    expect(notice?.tone).toBe("warn");
    expect(notice?.text).toMatch(/4 message\(s\)/);
    expect(notice?.text).toMatch(/not known to have been/i);
  });

  it("keeps the claim to the next message even when the whole thread is sealed", () => {
    const notice = privacyNotice({ sends_sealed: true, unsealed_messages: 0 });
    expect(notice?.tone).toBe("ok");
    expect(notice?.text).toMatch(/sealed to this contact's own key/i);
  });

  it("never claims the relay sees only the ciphertext", () => {
    // The envelope carries `to`, `from`, `from_pubkey` and `sent_at` in clear
    // beside the body (crates/dust-whisper/src/protocol.rs), so every wording
    // that is shown has to admit it.
    for (const security of [
      { sends_sealed: false, unsealed_messages: 0 },
      { sends_sealed: true, unsealed_messages: 2 },
      { sends_sealed: true, unsealed_messages: 0 },
    ]) {
      const text = privacyNotice(security)?.text ?? "";
      expect(text).not.toMatch(/ciphertext only/i);
      expect(text).not.toMatch(/carries the ciphertext/i);
    }
    expect(privacyNotice({ sends_sealed: true, unsealed_messages: 0 })?.text).toMatch(
      /sees both addresses and the time/i,
    );
  });

  it("marks a message only when the record says which way it travelled", () => {
    expect(sealedLabel(true)).toBe("Sealed to their key");
    expect(sealedLabel(false)).toBe("Not sealed");
    expect(sealedLabel(null)).toBeNull();
    expect(sealedLabel(undefined)).toBeNull();
  });

  it("is what both shipped screens actually call", () => {
    const mobile = readFileSync(
      join(HERE, "../../mobile/src/components/MessengerScreen.tsx"),
      "utf8",
    );
    const desktop = readFileSync(
      join(HERE, "screens/MessagesScreen.tsx"),
      "utf8",
    );
    for (const source of [mobile, desktop]) {
      expect(source).toMatch(/privacyNotice\(/);
      expect(source).toMatch(/messengerApi\.peerSecurity\(/);
    }
    // The sentence that stood over messages nobody had authenticated.
    expect(mobile).not.toMatch(/End-to-end encrypted to this contact's key/);
    expect(mobile).not.toMatch(/relay carries the\s*\n?\s*ciphertext only/);
  });
});

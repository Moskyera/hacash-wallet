import { describe, expect, it } from "vitest";
import type {
  EncryptedCompanionFrame,
  MobilePairingRequest,
} from "./api";
import {
  companionPairingPrefixes,
  parseAck,
  parseRequest,
} from "./companionPairing";

function request(): MobilePairingRequest {
  return {
    protocol_version: "1",
    pairing_id: "pair_one",
    agent_wallet_id: "aw_one",
    desktop_device_id: "desktop_one",
    mobile_device_id: "mobile_one",
    mobile_ephemeral_public_key: "11".repeat(32),
    mobile_identity_public_key: `04${"22".repeat(64)}`,
    mobile_identity_fingerprint: "33".repeat(32),
    pairing_nonce: "44".repeat(32),
    mobile_challenge: "55".repeat(32),
    issued_at: "100",
    expires_at: "200",
    identity_signature: "66".repeat(64),
  };
}

function acknowledgement(): EncryptedCompanionFrame {
  return {
    frame_version: "1",
    session_id: "session_one",
    sender_device_id: "mobile_one",
    recipient_device_id: "desktop_one",
    sequence: "1",
    issued_at: "110",
    expires_at: "200",
    nonce_hex: "77".repeat(12),
    ciphertext_hex: "88".repeat(48),
  };
}

describe("desktop mobile-companion QR boundary", () => {
  it("accepts exact typed request and acknowledgement scopes", () => {
    const parsedRequest = parseRequest(
      companionPairingPrefixes.request + JSON.stringify(request()),
      "aw_one",
      "pair_one",
    );
    expect(parsedRequest.mobile_device_id).toBe("mobile_one");

    const parsedAck = parseAck(
      companionPairingPrefixes.acknowledgement +
        JSON.stringify(acknowledgement()),
      "session_one",
      "mobile_one",
      "desktop_one",
    );
    expect(parsedAck.sequence).toBe("1");
  });

  it("rejects cross-wallet, numeric u64 and unknown fields before IPC", () => {
    const crossWallet = request();
    crossWallet.agent_wallet_id = "aw_other";
    expect(() =>
      parseRequest(
        companionPairingPrefixes.request + JSON.stringify(crossWallet),
        "aw_one",
        "pair_one",
      ),
    ).toThrow(/different pairing or Agent Wallet/);

    const numeric = { ...request(), issued_at: 100 };
    expect(() =>
      parseRequest(
        companionPairingPrefixes.request + JSON.stringify(numeric),
        "aw_one",
        "pair_one",
      ),
    ).toThrow(/issued_at/);

    const extra = { ...acknowledgement(), plaintext: "forbidden" };
    expect(() =>
      parseAck(
        companionPairingPrefixes.acknowledgement + JSON.stringify(extra),
        "session_one",
        "mobile_one",
        "desktop_one",
      ),
    ).toThrow(/missing or unknown/);
  });
});

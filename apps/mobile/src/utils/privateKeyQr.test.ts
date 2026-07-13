import { describe, expect, it } from "vitest";
import { encodePrivateKeyQr, parsePrivateKeyQr } from "./privateKeyQr";

const SAMPLE = "a".repeat(64);

describe("privateKeyQr", () => {
  it("round-trips via QR prefix", () => {
    const qr = encodePrivateKeyQr(SAMPLE);
    expect(qr).toBe(`hacash:pk:v1:${SAMPLE}`);
    expect(parsePrivateKeyQr(qr)).toBe(SAMPLE);
  });

  it("accepts raw 64-char hex", () => {
    expect(parsePrivateKeyQr(SAMPLE.toUpperCase())).toBe(SAMPLE);
  });

  it("rejects invalid hex", () => {
    expect(parsePrivateKeyQr("abc")).toBeNull();
    expect(parsePrivateKeyQr("g".repeat(64))).toBeNull();
  });
});
import { describe, expect, it } from "vitest";
import type { HacashL2ProtocolProbe } from "./api";
import { canConfirmL2ProviderPin, PROVIDER_BLOCKER_LABEL } from "./providerTrust";

const fingerprint = "ab".repeat(32);
const probe = (overrides: Partial<HacashL2ProtocolProbe> = {}): HacashL2ProtocolProbe => ({
  protocol: "hacash-agent-pay/1",
  version: "1.0",
  provider_id: "operator-one",
  base_url: "https://hub.example",
  read_only_compatible: true,
  mainnet_spending_ready: false,
  finality: "hub_coordinated_not_l1",
  provider_pin_status: "unpinned",
  provider_identity: {
    provider_id: "operator-one",
    base_url: "https://hub.example",
    mesh_protocol_version: "2.0",
    identity_address: "1Provider",
    identity_pubkey_hex: "02" + "11".repeat(32),
    fingerprint_sha3_hex: fingerprint,
    verified_at_unix: 1,
  },
  blockers: ["provider_identity_unpinned"],
  ...overrides,
});

describe("Hacash L2 provider owner confirmation", () => {
  it("requires all 64 trusted fingerprint characters", () => {
    expect(canConfirmL2ProviderPin(probe(), fingerprint.slice(0, 63))).toBe(false);
    expect(canConfirmL2ProviderPin(probe(), fingerprint)).toBe(true);
    expect(canConfirmL2ProviderPin(probe(), fingerprint.toUpperCase())).toBe(true);
  });

  it("never offers pinning for unverified, changed or incompatible providers", () => {
    expect(canConfirmL2ProviderPin(probe({ provider_pin_status: "unverified" }), fingerprint)).toBe(false);
    expect(canConfirmL2ProviderPin(probe({ provider_pin_status: "mismatch" }), fingerprint)).toBe(false);
    expect(canConfirmL2ProviderPin(probe({ read_only_compatible: false }), fingerprint)).toBe(false);
    expect(canConfirmL2ProviderPin(probe({ provider_identity: undefined }), fingerprint)).toBe(false);
  });

  it("has honest owner-facing copy for every blocker", () => {
    expect(Object.keys(PROVIDER_BLOCKER_LABEL)).toHaveLength(10);
    expect(PROVIDER_BLOCKER_LABEL.unilateral_l1_exit_unverified).toContain("not verified");
  });
});
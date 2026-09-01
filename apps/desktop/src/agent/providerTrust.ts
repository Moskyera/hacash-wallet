import type {
  HacashL2ProtocolProbe,
  HacashL2ProviderPinStatus,
  HacashL2ReadinessBlocker,
} from "./api";

export function canConfirmL2ProviderPin(
  probe: HacashL2ProtocolProbe | null,
  confirmation: string,
): boolean {
  const identity = probe?.provider_identity;
  return Boolean(
    probe?.read_only_compatible &&
      probe.provider_pin_status === "unpinned" &&
      identity &&
      /^[0-9a-f]{64}$/i.test(confirmation.trim()) &&
      confirmation.trim().toLowerCase() === identity.fingerprint_sha3_hex.toLowerCase(),
  );
}

export const PROVIDER_PIN_LABEL: Record<HacashL2ProviderPinStatus, string> = {
  unverified: "Identity not verified",
  unpinned: "Verified, owner confirmation required",
  matched: "Verified and pinned",
  mismatch: "Identity changed, connection blocked",
};

export const PROVIDER_BLOCKER_LABEL: Record<HacashL2ReadinessBlocker, string> = {
  protocol_mismatch: "The hub does not report the hacash-agent-pay/1 protocol.",
  manifest_origin_mismatch: "The manifest origin does not match the URL you entered.",
  provider_identity_missing: "The manifest has no valid provider identity label.",
  provider_identity_unverified: "The hub did not provide a fresh, valid signed identity.",
  provider_identity_unpinned: "Compare and confirm the complete SHA3-256 fingerprint.",
  provider_identity_changed: "The signed identity differs from this Agent Wallet's saved pin.",
  required_endpoint_missing: "One or more required read-only/payment lifecycle endpoints are missing.",
  signing_contract_mismatch: "The hub reports an incompatible signing contract.",
  unilateral_l1_exit_unverified: "Independent unilateral L1 exit recovery is not verified yet.",
  independent_protocol_audit_required: "An independent protocol security audit is still required.",
};
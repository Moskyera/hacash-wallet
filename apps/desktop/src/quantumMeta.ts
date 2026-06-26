import type { QuantumAccountInfo, QuantumSettings } from "./api";

/** Resolve kind + version from keystore metadata (never guess from address prefix). */
export function resolveQuantumMeta(
  s: Pick<QuantumSettings, "kind" | "address_version" | "active_address">,
): { kind: string; address_version: number } | null {
  if (!s.active_address) return null;

  let kind = s.kind ?? null;
  let version = s.address_version ?? null;

  if (kind === "hybrid") {
    version = 7;
  } else if (kind === "pqckey") {
    version = 6;
  } else if (version === 7) {
    kind = "hybrid";
  } else if (version === 6) {
    kind = "pqckey";
  }

  if (!kind || (version !== 6 && version !== 7)) {
    return null;
  }
  return { kind, address_version: version };
}

export function accountFromSettings(s: QuantumSettings): QuantumAccountInfo | null {
  const meta = resolveQuantumMeta(s);
  if (!meta || !s.active_address) return null;
  return {
    address: s.active_address,
    kind: meta.kind,
    address_version: meta.address_version,
    alg_id: 3,
    mldsa_pubkey: "",
    secp_pubkey: "",
  };
}

export function badgeVersion(kind?: string | null, version?: number | null): number {
  if (version === 6 || version === 7) return version;
  if (kind === "hybrid") return 7;
  if (kind === "pqckey") return 6;
  return 0;
}

export function kindLabel(kind: string): string {
  if (kind === "hybrid") return "Hybrid";
  if (kind === "pqckey") return "PQC";
  return kind;
}

export const REPLACE_KEYSTORE_WARNING =
  "Creating a new quantum account replaces the stored keystore. " +
  "Funds on the previous on-chain address remain there — export a backup first if you still need them.";
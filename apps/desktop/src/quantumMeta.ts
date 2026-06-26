import type { QuantumAccountInfo, QuantumAccountSummary, QuantumSettings } from "./api";

/** Map fully-resolved settings from the wallet core (no client-side reconciliation). */
export function accountSummaryFromSettings(s: QuantumSettings): QuantumAccountSummary | null {
  const { active_address, kind, address_version } = s;
  if (!active_address || !kind || (address_version !== 6 && address_version !== 7)) {
    return null;
  }
  return { address: active_address, kind, address_version };
}

export function summaryFromAccountInfo(a: QuantumAccountInfo): QuantumAccountSummary {
  return {
    address: a.address,
    kind: a.kind,
    address_version: a.address_version,
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
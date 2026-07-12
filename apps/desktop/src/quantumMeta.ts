import type { QuantumAccountInfo, QuantumAccountSummary, QuantumSettings } from "./api";

/** Map fully-resolved settings from the wallet core (no client-side reconciliation). */
export function accountSummaryFromSettings(s: QuantumSettings): QuantumAccountSummary | null {
  return s.active_account ?? null;
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

/** Type 4 send is available for PQC (v6) and Hybrid (v7) quantum accounts. */
export function canSendType4(account: QuantumAccountSummary | null): boolean {
  if (!account) return false;
  return (
    (account.kind === "pqckey" && account.address_version === 6) ||
    (account.kind === "hybrid" && account.address_version === 7)
  );
}

export const PQC_TYPE4_HINT =
  "PQC (v6) signs Type 4 with ML-DSA only. Hybrid (v7) adds secp256k1 binding and is recommended for legacy-linked setups. Network fee is ~0.004 HAC (not 40 HAC).";

export const REPLACE_KEYSTORE_WARNING =
  "Creating a new quantum account replaces the stored keystore. " +
  "Funds on the previous on-chain address remain there — export a backup first if you still need them.";
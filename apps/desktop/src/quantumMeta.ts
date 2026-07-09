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

/** Type 4 on-chain send requires Hybrid (v7) per HIP-23 wallet policy. */
export function canSendType4(account: QuantumAccountSummary | null): boolean {
  return account?.kind === "hybrid" && account.address_version === 7;
}

export const PQC_SEND_BLOCKED_MSG =
  "Type 4 send requires a Hybrid (v7) account. PQC-only (v6) can receive funds but cannot sign Type 4 transfers yet.";

export const REPLACE_KEYSTORE_WARNING =
  "Creating a new quantum account replaces the stored keystore. " +
  "Funds on the previous on-chain address remain there — export a backup first if you still need them.";
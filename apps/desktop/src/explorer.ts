export const HACASH_EXPLORER_BASE = "https://explorer.hacash.org";

/** 64-char hex tx hash as returned by the node for on-chain transactions. */
export function isExplorerTxHash(hash: string): boolean {
  const h = hash.trim().toLowerCase();
  return /^[0-9a-f]{64}$/.test(h);
}

export function explorerTxUrl(txHash: string): string {
  return `${HACASH_EXPLORER_BASE}/tx/${txHash.trim().toLowerCase()}`;
}

export function canOpenTxInExplorer(rail: string, txHash: string): boolean {
  if (!isExplorerTxHash(txHash)) return false;
  return rail === "L1OnChain" || rail === "QuantumType4";
}
import { open } from "@tauri-apps/plugin-shell";
import type { TxRecord, TxStatus } from "./api";
import { canOpenTxInExplorer, explorerTxUrl } from "./explorer";

export function normalizeTxStatus(status?: string): TxStatus {
  if (status === "pending" || status === "failed") return status;
  return "confirmed";
}

export async function openTxInExplorer(
  row: TxRecord,
  onNotify?: (msg: string, kind: "error" | "info" | "success") => void,
): Promise<void> {
  const status = normalizeTxStatus(row.status);
  if (status === "pending") {
    onNotify?.("Transaction still processing.", "info");
    return;
  }
  if (status === "failed") {
    onNotify?.("Transaction failed.", "error");
    return;
  }
  if (!canOpenTxInExplorer(row.rail, row.tx_hash)) {
    onNotify?.("Off-chain payment — not on the block explorer.", "info");
    return;
  }
  try {
    await open(explorerTxUrl(row.tx_hash));
  } catch (e) {
    onNotify?.(String(e), "error");
  }
}
import { openUrl } from "@tauri-apps/plugin-opener";
import type { TxRecord, TxStatus } from "./api";
import { canOpenTxInExplorer, explorerTxUrl } from "./explorer";

export function normalizeTxStatus(status?: string): TxStatus {
  if (status === "pending" || status === "failed") return status;
  return "confirmed";
}

export async function openTxInExplorer(
  row: TxRecord,
  onToast: (msg: string, kind: "success" | "info" | "error") => void,
): Promise<void> {
  const status = normalizeTxStatus(row.status);
  if (status === "pending") {
    onToast("Transaction still processing.", "info");
    return;
  }
  if (status === "failed") {
    onToast("Transaction failed.", "error");
    return;
  }
  if (canOpenTxInExplorer(row.rail, row.tx_hash)) {
    try {
      await openUrl(explorerTxUrl(row.tx_hash));
    } catch (e) {
      onToast(String(e), "error");
    }
    return;
  }
  onToast("Off-chain payment. not on the block explorer.", "info");
}
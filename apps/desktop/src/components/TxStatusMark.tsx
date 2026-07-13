import type { TxStatus } from "../api";
import { normalizeTxStatus } from "../txHistory";

type Props = {
  status?: string;
};

export default function TxStatusMark({ status }: Props) {
  const s: TxStatus = normalizeTxStatus(status);
  if (s === "pending") {
    return <span className="tx-status tx-status-pending" title="Processing">●</span>;
  }
  if (s === "failed") {
    return <span className="tx-status tx-status-failed" title="Failed">✕</span>;
  }
  return <span className="tx-status tx-status-confirmed" title="Completed">✓</span>;
}
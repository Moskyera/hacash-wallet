import { useState } from "react";
import type { BillSummary } from "../api";
import { formatInvokeError } from "../formatInvokeError";
import { copyWithPrivacyClear } from "../privacy";

type Props = {
  bill: BillSummary | null;
  clipboardClearSecs: number;
  onClose: () => void;
  onExportJson: (paymentId: string) => Promise<string>;
  onGetHex: (paymentId: string) => Promise<string>;
};

export default function BillDetailModal({
  bill,
  clipboardClearSecs,
  onClose,
  onExportJson,
  onGetHex,
}: Props) {
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState("");

  if (!bill) return null;

  async function copyHex() {
    setBusy(true);
    setMsg("");
    try {
      const hex = await onGetHex(bill!.payment_id);
      await copyWithPrivacyClear(hex, clipboardClearSecs);
      setMsg("Bill hex copied.");
    } catch (e) {
      setMsg(formatInvokeError(e));
    } finally {
      setBusy(false);
    }
  }

  async function exportOne() {
    setBusy(true);
    setMsg("");
    try {
      const json = await onExportJson(bill!.payment_id);
      const blob = new Blob([json], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `bill-${bill!.payment_id.slice(0, 8)}.json`;
      a.click();
      URL.revokeObjectURL(url);
      setMsg("Bill JSON downloaded.");
    } catch (e) {
      setMsg(formatInvokeError(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal-sheet" onClick={(e) => e.stopPropagation()}>
        <h2>Bill receipt</h2>
        <p className="muted">{bill.timestamp_utc}</p>
        <div className="detail-grid">
          <div>
            <span className="label">Payment ID</span>
            <code>{bill.payment_id}</code>
          </div>
          <div>
            <span className="label">Status</span>
            <span className={bill.dispute_ready ? "badge badge-ok" : "badge badge-warn"}>
              {bill.dispute_ready ? "Dispute ready" : "Incomplete"}
            </span>
          </div>
          <div>
            <span className="label">Channel legs</span>
            <span>{bill.channel_legs}</span>
          </div>
          <div>
            <span className="label">Size</span>
            <span>{bill.hex_byte_length} bytes</span>
          </div>
        </div>
        <ul className="sig-list">
          {bill.signatures.map((s) => (
            <li key={s.address}>
              <code>{s.address.slice(0, 10)}…</code>{" "}
              {s.verified ? "✓ verified" : s.filled ? "filled" : "missing"}
            </li>
          ))}
        </ul>
        <div className="row-btns">
          <button type="button" disabled={busy} onClick={() => void copyHex()}>
            Copy hex
          </button>
          <button type="button" className="primary" disabled={busy} onClick={() => void exportOne()}>
            Export JSON
          </button>
        </div>
        {msg && <p className="muted">{msg}</p>}
        <button type="button" className="ghost" onClick={onClose}>
          Close
        </button>
      </div>
    </div>
  );
}
import { Fragment, useCallback, useEffect, useState } from "react";
import { api, BillSummary } from "../api";
import { copyWithPrivacyClear } from "../privacy";
import { formatInvokeError } from "../formatInvokeError";

function downloadText(filename: string, content: string, mime = "application/json") {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

type Props = {
  hideAddresses: boolean;
  onError: (msg: string) => void;
  onInfo: (msg: string) => void;
};

export default function BillsPanel({ hideAddresses, onError, onInfo }: Props) {
  const [bills, setBills] = useState<BillSummary[]>([]);
  const [loading, setLoading] = useState(false);
  const [expanded, setExpanded] = useState<string | null>(null);
  const [busyId, setBusyId] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    setLoading(true);
    try {
      const rows = await api.listBillSummaries();
      setBills(rows);
    } catch (e) {
      onError(formatInvokeError(e));
    } finally {
      setLoading(false);
    }
  }, [onError]);

  useEffect(() => {
    const id = window.setTimeout(() => void refresh(), 0);
    return () => window.clearTimeout(id);
  }, [refresh]);

  const handleExportAll = async () => {
    try {
      const json = await api.exportAllBillsJson();
      downloadText(`hacash-l2-bills-${Date.now()}.json`, json);
      onInfo("Exported all bills as JSON.");
    } catch (e) {
      onError(formatInvokeError(e));
    }
  };

  const handleExportOne = async (paymentId: string) => {
    setBusyId(paymentId);
    try {
      const json = await api.exportBillJson(paymentId);
      downloadText(`hacash-bill-${paymentId.slice(0, 8)}.json`, json);
      onInfo("Bill exported.");
    } catch (e) {
      onError(formatInvokeError(e));
    } finally {
      setBusyId(null);
    }
  };

  const handleCopyHex = async (paymentId: string) => {
    setBusyId(paymentId);
    try {
      const hex = await api.getBillHex(paymentId);
      await copyWithPrivacyClear(hex, 30);
      onInfo("Bill hex copied to clipboard.");
    } catch (e) {
      onError(formatInvokeError(e));
    } finally {
      setBusyId(null);
    }
  };

  const maskAddr = (addr: string) =>
    hideAddresses ? `${addr.slice(0, 6)}…${addr.slice(-4)}` : addr;

  return (
    <div className="bills-panel">
      <div className="bills-panel-header">
        <div>
          <h3>Dispute bills</h3>
          <p className="muted">
            Signed Fast Pay receipts stored on this device. Export and keep them safe — you need
            them if a channel payment is disputed on-chain.
          </p>
        </div>
        <div className="bills-panel-actions">
          <button type="button" onClick={() => void refresh()} disabled={loading}>
            Refresh
          </button>
          <button
            type="button"
            className="primary"
            onClick={() => void handleExportAll()}
            disabled={bills.length === 0}
          >
            Export all JSON
          </button>
        </div>
      </div>

      {loading && bills.length === 0 ? (
        <p className="muted">Loading bills…</p>
      ) : bills.length === 0 ? (
        <p className="muted">No Fast Pay bills yet. They appear here after instant sends.</p>
      ) : (
        <div className="table-wrap">
          <table className="data-table bills-table">
            <thead>
              <tr>
                <th>Payment</th>
                <th>Time (UTC)</th>
                <th>Legs</th>
                <th>Signatures</th>
                <th>Dispute</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {bills.map((bill) => {
                const sigOk = bill.signatures.filter((s) => s.verified).length;
                const sigTotal = bill.signatures.length;
                const isOpen = expanded === bill.payment_id;
                return (
                  <Fragment key={bill.payment_id}>
                    <tr>
                      <td>
                        <code>{bill.payment_id.slice(0, 8)}…</code>
                      </td>
                      <td>{bill.timestamp_utc.replace("T", " ").replace("Z", "")}</td>
                      <td>{bill.channel_legs}</td>
                      <td>
                        {sigOk}/{sigTotal} verified
                      </td>
                      <td>
                        <span
                          className={
                            bill.dispute_ready ? "bill-badge bill-ok" : "bill-badge bill-warn"
                          }
                        >
                          {bill.dispute_ready ? "Ready" : "Incomplete"}
                        </span>
                      </td>
                      <td className="bills-row-actions">
                        <button type="button" onClick={() => setExpanded(isOpen ? null : bill.payment_id)}>
                          {isOpen ? "Hide" : "Details"}
                        </button>
                        <button
                          type="button"
                          disabled={busyId === bill.payment_id}
                          onClick={() => void handleCopyHex(bill.payment_id)}
                        >
                          Copy hex
                        </button>
                        <button
                          type="button"
                          disabled={busyId === bill.payment_id}
                          onClick={() => void handleExportOne(bill.payment_id)}
                        >
                          Export
                        </button>
                      </td>
                    </tr>
                    {isOpen && (
                      <tr className="bills-detail-row">
                        <td colSpan={6}>
                          <div className="bills-detail">
                            <p>
                              <strong>Size:</strong> {bill.hex_byte_length} bytes wire ·{" "}
                              <strong>Bill #:</strong>{" "}
                              {bill.prove_bodies.map((p) => p.bill_auto_number).join(", ")}
                            </p>
                            {bill.prove_bodies.map((p, i) => (
                              <div key={i} className="bills-prove-card">
                                <div>
                                  Channel <code>{p.channel_id_hex.slice(0, 16)}…</code>
                                </div>
                                <div>
                                  Pay {p.pay_amount_mei} HAC ({p.pay_direction}) · balances L{" "}
                                  {p.left_balance_mei} / R {p.right_balance_mei}
                                </div>
                                <div className="muted">
                                  {maskAddr(p.left_address)} → {maskAddr(p.right_address)}
                                </div>
                              </div>
                            ))}
                            <ul className="bills-sig-list">
                              {bill.signatures.map((s) => (
                                <li key={s.address}>
                                  {maskAddr(s.address)} —{" "}
                                  {s.verified ? "verified" : s.filled ? "invalid" : "missing"}
                                </li>
                              ))}
                            </ul>
                            {!bill.dispute_ready && (
                              <p className="bill-warn-text">
                                Missing or invalid signatures — this bill may not be accepted in a
                                channel challenge. Re-export after hub co-sign is available.
                              </p>
                            )}
                          </div>
                        </td>
                      </tr>
                    )}
                  </Fragment>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
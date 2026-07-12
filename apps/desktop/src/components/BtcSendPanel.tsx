import { useState } from "react";
import PaymentQrScanner from "./PaymentQrScanner";
import { useBtcSend } from "../hooks/useBtcSend";
import { maskBtcFromSatoshi, maskAddress } from "../privacy";

type Props = {
  active: boolean;
  busy: boolean;
  setBusy: (b: boolean) => void;
  nativeBioAvailable: boolean;
  hideAddresses: boolean;
  hideBalances: boolean;
  btcSatoshi: number | null;
  watchOnly: boolean;
  onNotify: (msg: string, kind: "success" | "info" | "error") => void;
  onSent: () => Promise<void>;
};

export default function BtcSendPanel({
  active,
  busy,
  setBusy,
  nativeBioAvailable,
  hideAddresses,
  hideBalances,
  btcSatoshi,
  watchOnly,
  onNotify,
  onSent,
}: Props) {
  const [recipientScanOpen, setRecipientScanOpen] = useState(false);

  const btc = useBtcSend({
    active,
    nativeBioAvailable,
    setBusy,
    onNotify,
    onSent,
  });

  if (watchOnly) {
    return (
      <div className="info-box">
        <p>Watch-only wallet cannot send BTC.</p>
      </div>
    );
  }

  return (
    <div className="send-asset-panel">
      <div className="send-asset-balance">
        <div>
          <span className="label">Available BTC</span>
          <span className="value">{maskBtcFromSatoshi(btcSatoshi, hideBalances)}</span>
        </div>
      </div>

      <p className="muted small-note">
        On-chain BTC on the Hacash network. Recipient must be a Hacash address (1…). Network fee is
        paid in HAC (estimated at preview).
      </p>

      <div className="send-section">
        <label>Recipient Hacash address</label>
        <button
          type="button"
          className="collapse-toggle"
          onClick={() => setRecipientScanOpen((v) => !v)}
        >
          {recipientScanOpen ? "▾" : "▸"} Scan recipient QR
        </button>
        {recipientScanOpen && (
          <PaymentQrScanner
            mountId="btc-recipient-qr-reader"
            disabled={busy}
            onDetected={(payload) => {
              btc.setRecipient(payload.address);
              btc.resetPreview();
            }}
            onError={(msg) => onNotify(msg, "error")}
          />
        )}
        <input
          placeholder="1ABC…"
          value={btc.recipient}
          onChange={(e) => {
            btc.setRecipient(e.target.value);
            btc.resetPreview();
          }}
        />
      </div>

      <div className="send-section">
        <label>Amount (BTC)</label>
        <input
          type="number"
          min="0"
          step="0.00000001"
          placeholder="0.00000000"
          value={btc.btcAmount}
          onChange={(e) => {
            btc.setBtcAmount(e.target.value);
            btc.resetPreview();
          }}
        />
        <button
          className="primary"
          disabled={busy || !btc.recipient.trim() || !btc.btcAmount || Number(btc.btcAmount) <= 0}
          onClick={() => void btc.handlePreview()}
        >
          Preview BTC send
        </button>
      </div>

      {btc.preview && (
        <div className="preview-card">
          <h3>Review and confirm</h3>
          <div className="badge badge-rail">On-chain (L1)</div>
          <p>
            <strong>{btc.preview.btc_amount.toFixed(8)} BTC</strong> ({btc.preview.satoshi} sat) →{" "}
            <code>{maskAddress(btc.preview.to, hideAddresses)}</code>
          </p>
          <p className="muted">Network fee: {btc.preview.fee_mei.toFixed(3)} HAC</p>
          {btc.preview.hip23.errors.length > 0 && (
            <div className="alert">
              <strong>HIP-23 errors</strong>
              <ul>
                {btc.preview.hip23.errors.map((e) => (
                  <li key={e}>{e}</li>
                ))}
              </ul>
            </div>
          )}
          {nativeBioAvailable && (
            <p className="muted">Biometric confirmation will be required.</p>
          )}
          <button
            className="primary"
            disabled={busy || !btc.preview.hip23.ok}
            onClick={() => void btc.handleConfirm()}
          >
            {busy ? "Sending…" : "Confirm and send BTC"}
          </button>
        </div>
      )}
    </div>
  );
}
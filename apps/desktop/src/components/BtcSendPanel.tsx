import PaymentQrScanner from "./PaymentQrScanner";
import { useBtcSend } from "../hooks/useBtcSend";
import { maskAddress } from "../privacy";

type Props = {
  active: boolean;
  busy: boolean;
  setBusy: (b: boolean) => void;
  nativeBioAvailable: boolean;
  hideAddresses: boolean;
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
  watchOnly,
  onNotify,
  onSent,
}: Props) {
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
    <>
      <p className="muted small-note">
        On-chain BTC balance on the Hacash network. Recipient must be a Hacash address (1…). Network
        fee is paid in HAC.
      </p>
      <label>Recipient Hacash address</label>
      <PaymentQrScanner
        mountId="btc-recipient-qr-reader"
        disabled={busy}
        onDetected={(payload) => {
          btc.setRecipient(payload.address);
          btc.resetPreview();
        }}
        onError={(msg) => onNotify(msg, "error")}
      />
      <input
        placeholder="1ABC…"
        value={btc.recipient}
        onChange={(e) => {
          btc.setRecipient(e.target.value);
          btc.resetPreview();
        }}
      />
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
      {btc.preview && (
        <div className="preview-card">
          <h3>Review & confirm</h3>
          <div className="badge badge-rail">On-chain (L1)</div>
          <p>
            <strong>{btc.preview.btc_amount.toFixed(8)} BTC</strong> ({btc.preview.satoshi} sat) →{" "}
            <code>{maskAddress(btc.preview.to, hideAddresses)}</code>
          </p>
          <p className="muted">Network fee: {btc.preview.fee_mei.toFixed(3)} HAC</p>
          {btc.preview.hip23.errors.length > 0 && (
            <div className="alert">
              <ul>
                {btc.preview.hip23.errors.map((e) => (
                  <li key={e}>{e}</li>
                ))}
              </ul>
            </div>
          )}
          <button
            className="primary"
            disabled={busy || !btc.preview.hip23.ok}
            onClick={() => void btc.handleConfirm()}
          >
            {busy ? "Sending…" : "Confirm & send BTC"}
          </button>
        </div>
      )}
    </>
  );
}
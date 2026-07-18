import { useState } from "react";
import HacdDiamondVisual from "./HacdDiamondVisual";
import PaymentQrScanner from "./PaymentQrScanner";
import { useHacdSend } from "../hooks/useHacdSend";
import { maskAddress, maskAssetCount } from "../privacy";
import { normalizeHacdName } from "@hacash/wallet-ui";

type Props = {
  active: boolean;
  busy: boolean;
  setBusy: (b: boolean) => void;
  nativeBioAvailable: boolean;
  hideAddresses: boolean;
  hideBalances: boolean;
  hacdCount: number | null;
  watchOnly: boolean;
  onNotify: (msg: string, kind: "success" | "info" | "error") => void;
  onSent: () => Promise<void>;
};

export default function HacdSendPanel({
  active,
  busy,
  setBusy,
  nativeBioAvailable,
  hideAddresses,
  hideBalances,
  hacdCount,
  watchOnly,
  onNotify,
  onSent,
}: Props) {
  const [hacdDisplay, setHacdDisplay] = useState<"name" | "visual">("visual");
  const [manualHacd, setManualHacd] = useState("");

  const hacd = useHacdSend({
    active,
    nativeBioAvailable,
    setBusy,
    onNotify,
    onSent,
  });

  const primaryHacd = hacd.selected[0] ?? normalizeHacdName(manualHacd);

  function applyManualHacd(raw: string) {
    const norm = normalizeHacdName(raw);
    setManualHacd(norm);
    if (norm.length >= 4) {
      hacd.setSingleDiamond(norm);
      hacd.resetPreview();
    }
  }

  if (watchOnly) {
    return (
      <div className="info-box">
        <p>Watch-only wallet cannot send HACD. Import a signing wallet or use a hardware device.</p>
      </div>
    );
  }

  return (
    <div className="send-asset-panel">
      <div className="send-asset-balance">
        <div>
          <span className="label">HACD owned</span>
          <span className="value">{maskAssetCount(hacdCount, hideBalances)}</span>
        </div>
      </div>

      <div className="send-section">
        <div className="display-toggle">
          <button
            type="button"
            className={hacdDisplay === "name" ? "selected" : ""}
            onClick={() => setHacdDisplay("name")}
          >
            Name
          </button>
          <button
            type="button"
            className={hacdDisplay === "visual" ? "selected" : ""}
            onClick={() => setHacdDisplay("visual")}
          >
            Metadata card
          </button>
        </div>

        <label className="check-row hacd-batch-row">
          <input
            type="checkbox"
            checked={hacd.batchMode}
            onChange={(e) => {
              hacd.setBatchMode(e.target.checked);
              if (!e.target.checked && hacd.selected.length > 1) {
                hacd.setSingleDiamond(hacd.selected[0] ?? "");
              }
              hacd.resetPreview();
            }}
          />
          Batch send multiple HACD
        </label>

        <label>{hacd.batchMode ? "Select HACD to send" : "HACD to send"}</label>
        {hacd.owned.length > 0 && (
          <div className="chip-row">
            {hacd.owned.slice(0, 16).map((name) => (
              <button
                key={name}
                type="button"
                className={`chip ${hacd.selected.includes(name) ? "selected" : ""}`}
                onClick={() => {
                  hacd.toggleDiamond(name);
                  setManualHacd(name);
                  hacd.resetPreview();
                }}
              >
                {name}
              </button>
            ))}
          </div>
        )}
        <input
          placeholder="e.g. ZAKXMI"
          value={manualHacd}
          onChange={(e) => applyManualHacd(e.target.value.toUpperCase())}
          maxLength={6}
        />
        {hacd.batchMode && hacd.selected.length > 0 && (
          <p className="muted small-note">Selected: {hacd.selected.join(", ")}</p>
        )}
        {hacd.owned.length === 0 && (
          <p className="muted small-note">
            No verified HACD found on the configured node. Metadata search may still show read-only
            mainnet information.
          </p>
        )}
        {hacdDisplay === "visual" && primaryHacd && <HacdDiamondVisual name={primaryHacd} />}
      </div>

      <div className="send-section">
        <label>Recipient Hacash address</label>
        <button
          type="button"
          className="collapse-toggle"
          onClick={() => hacd.setRecipientScanOpen((v) => !v)}
        >
          {hacd.recipientScanOpen ? "▾" : "▸"} Scan recipient QR
        </button>
        {hacd.recipientScanOpen && (
          <PaymentQrScanner
            mountId="hacd-recipient-qr-reader"
            disabled={busy}
            onDetected={(payload) => hacd.applyRecipientAddress(payload.address)}
            onError={(msg) => onNotify(msg, "error")}
          />
        )}
        <input
          placeholder="1ABC…"
          value={hacd.recipient}
          onChange={(e) => {
            hacd.setRecipient(e.target.value);
            hacd.resetPreview();
          }}
        />
        <p className="muted small-note">On-chain L1. Network fee is estimated from the node at preview.</p>
        <button
          className="primary"
          disabled={busy || hacd.selected.length === 0 || !hacd.recipient.trim()}
          onClick={() => void hacd.handlePreview()}
        >
          Preview HACD send
        </button>
      </div>

      {hacd.preview && (
        <div className="preview-card">
          <h3>Review and confirm</h3>
          <div className="badge badge-rail">On-chain (L1)</div>
          <p>
            {hacd.preview.diamond_count === 1 ? (
              <>
                <strong>{hacd.preview.diamond_name}</strong>
                {hacd.preview.diamond_number != null && (
                  <span className="muted"> #{hacd.preview.diamond_number}</span>
                )}
              </>
            ) : (
              <strong>
                {hacd.preview.diamond_count} HACD ({hacd.preview.diamond_names.slice(0, 3).join(", ")}
                {hacd.preview.diamond_count > 3 ? "…" : ""})
              </strong>
            )}{" "}
            → <code>{maskAddress(hacd.preview.to, hideAddresses)}</code>
          </p>
          <p className="muted">Network fee: {hacd.preview.fee_mei.toFixed(3)} HAC</p>
          <p className="muted">
            Wallet fee: {hacd.preview.service_fee_mei.toFixed(3)} HAC · total HAC debit{" "}
            {hacd.preview.total_hac_debit_mei.toFixed(3)}
          </p>
          {hacd.preview.hip23.errors.length > 0 && (
            <div className="alert">
              <strong>HIP-23 errors</strong>
              <ul>
                {hacd.preview.hip23.errors.map((e) => (
                  <li key={e}>{e}</li>
                ))}
              </ul>
            </div>
          )}
          {nativeBioAvailable && <p className="muted">Biometric confirmation will be required.</p>}
          <button
            className="primary"
            disabled={busy || !hacd.preview.hip23.ok}
            onClick={() => void hacd.handleConfirm()}
          >
            {busy ? "Sending…" : "Confirm and send HACD"}
          </button>
        </div>
      )}
    </div>
  );
}

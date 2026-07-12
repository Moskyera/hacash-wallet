import { useState } from "react";
import { AssetSummary, SendPreview, WalletStatus } from "../api";
import type { PaymentQrPayload } from "../paymentQr";
import BtcSendPanel from "../components/BtcSendPanel";
import HacdSendPanel from "../components/HacdSendPanel";
import PaymentQrScanner from "../components/PaymentQrScanner";
import { HubFeePayer } from "../api";
import { maskAddress } from "../privacy";
import { railBadgeClass } from "../fastPayUi";
import type { PaymentAsset } from "../utils/paymentAssets";
import type { Screen } from "./types";

type Props = {
  active: boolean;
  status: WalletStatus | null;
  assets: AssetSummary | null;
  hideBalances: boolean;
  hideAddresses: boolean;
  fastPayReady: boolean;
  nativeBioAvailable: boolean;
  busy: boolean;
  setBusy: (b: boolean) => void;
  sendTo: string;
  setSendTo: (v: string) => void;
  sendAmount: string;
  setSendAmount: (v: string) => void;
  sendHubFeePayer: HubFeePayer;
  setSendHubFeePayer: (v: HubFeePayer) => void;
  sendForceL1: boolean;
  setSendForceL1: (v: boolean) => void;
  showSendOptions: boolean;
  setShowSendOptions: (v: boolean | ((prev: boolean) => boolean)) => void;
  sendQrScanOpen: boolean;
  setSendQrScanOpen: (v: boolean | ((prev: boolean) => boolean)) => void;
  preview: SendPreview | null;
  clearPreview: () => void;
  persistSendPreferences: (hubFeePayer: HubFeePayer, forceL1: boolean) => Promise<void>;
  onPaymentQr: (payload: PaymentQrPayload) => void;
  onPreviewSend: () => void;
  onConfirmSend: () => void;
  onNavigate: (screen: Screen) => void;
  onNotify: (msg: string, kind: "error" | "info" | "success") => void;
  onSent: () => Promise<void>;
};

export default function SendScreen({
  active,
  status,
  assets,
  hideBalances,
  hideAddresses,
  fastPayReady,
  nativeBioAvailable,
  busy,
  setBusy,
  sendTo,
  setSendTo,
  sendAmount,
  setSendAmount,
  sendHubFeePayer,
  setSendHubFeePayer,
  sendForceL1,
  setSendForceL1,
  showSendOptions,
  setShowSendOptions,
  sendQrScanOpen,
  setSendQrScanOpen,
  preview,
  clearPreview,
  persistSendPreferences,
  onPaymentQr,
  onPreviewSend,
  onConfirmSend,
  onNavigate,
  onNotify,
  onSent,
}: Props) {
  const [sendAsset, setSendAsset] = useState<PaymentAsset>("HAC");

  return (
    <section className="panel">
      <h2>Send</h2>
      <div className="display-toggle send-asset-toggle">
        <button
          type="button"
          className={sendAsset === "HAC" ? "selected" : ""}
          onClick={() => {
            setSendAsset("HAC");
            clearPreview();
          }}
        >
          HAC
        </button>
        <button
          type="button"
          className={sendAsset === "HACD" ? "selected" : ""}
          onClick={() => {
            setSendAsset("HACD");
            clearPreview();
          }}
        >
          HACD
        </button>
        <button
          type="button"
          className={sendAsset === "BTC" ? "selected" : ""}
          onClick={() => {
            setSendAsset("BTC");
            clearPreview();
          }}
        >
          BTC
        </button>
      </div>

      {sendAsset === "BTC" ? (
        <BtcSendPanel
          active={active && sendAsset === "BTC"}
          busy={busy}
          setBusy={setBusy}
          nativeBioAvailable={nativeBioAvailable}
          hideAddresses={hideAddresses}
          watchOnly={!!status?.watch_only}
          btcSatoshi={assets?.btc_wallet_satoshi ?? null}
          hideBalances={hideBalances}
          onNotify={onNotify}
          onSent={onSent}
        />
      ) : sendAsset === "HACD" ? (
        <HacdSendPanel
          active={active && sendAsset === "HACD"}
          busy={busy}
          setBusy={setBusy}
          nativeBioAvailable={nativeBioAvailable}
          hideAddresses={hideAddresses}
          watchOnly={!!status?.watch_only}
          hacdCount={assets?.hacd_count ?? null}
          hideBalances={hideBalances}
          onNotify={onNotify}
          onSent={onSent}
        />
      ) : (
        <>
          {!status?.watch_only && (
            <>
              <button
                type="button"
                className="collapse-toggle"
                onClick={() => {
                  setSendQrScanOpen((v) => !v);
                  clearPreview();
                }}
              >
                {sendQrScanOpen ? "▾" : "▸"} Scan QR payment
              </button>
              {sendQrScanOpen && (
                <PaymentQrScanner
                  onDetected={(payload) => void onPaymentQr(payload)}
                  onError={(msg) => onNotify(msg, "error")}
                  disabled={busy}
                />
              )}
            </>
          )}
          <div
            className={`fp-send-strip ${fastPayReady && !sendForceL1 ? "fp-send-on" : "fp-send-off"}`}
          >
            <span className="fp-send-label">Route for this wallet:</span>
            <span
              className={`fp-send-badge ${fastPayReady && !sendForceL1 ? "fp-send-badge-on" : "fp-send-badge-off"}`}
            >
              {sendForceL1
                ? "On-chain (forced)"
                : fastPayReady
                  ? "Fast Pay ON"
                  : "Fast Pay OFF (on-chain)"}
            </span>
            <button type="button" className="linkish" onClick={() => onNavigate("fastpay")}>
              Change
            </button>
          </div>
          <label>Recipient address</label>
          <input
            value={sendTo}
            onChange={(e) => setSendTo(e.target.value)}
            placeholder="1ABC..."
          />
          <label>Amount (HAC)</label>
          <input
            value={sendAmount}
            onChange={(e) => setSendAmount(e.target.value)}
            placeholder="10"
            type="number"
            min="0"
            step="0.001"
          />

          <button
            type="button"
            className="collapse-toggle"
            onClick={() => setShowSendOptions((v) => !v)}
          >
            {showSendOptions ? "▾" : "▸"} Payment options
          </button>
          {showSendOptions && (
            <div className="send-options-card">
              <fieldset className="send-option-group">
                <legend>Fast Pay network fee</legend>
                <label className="radio-row">
                  <input
                    type="radio"
                    name="hubFeePayer"
                    checked={sendHubFeePayer === "sender"}
                    onChange={() => {
                      setSendHubFeePayer("sender");
                      clearPreview();
                      persistSendPreferences("sender", sendForceL1).catch(() => undefined);
                    }}
                  />
                  I pay the fee (default)
                </label>
                <label className="radio-row">
                  <input
                    type="radio"
                    name="hubFeePayer"
                    checked={sendHubFeePayer === "recipient"}
                    onChange={() => {
                      setSendHubFeePayer("recipient");
                      clearPreview();
                      persistSendPreferences("recipient", sendForceL1).catch(() => undefined);
                    }}
                  />
                  Recipient pays. Deducted from amount they receive.
                </label>
                <p className="muted small-note">
                  Applies to Fast Pay only. On-chain L1 fees are always paid by the sender.
                </p>
              </fieldset>
              <label className="checkbox-row">
                <input
                  type="checkbox"
                  checked={sendForceL1}
                  onChange={(e) => {
                    const force = e.target.checked;
                    setSendForceL1(force);
                    clearPreview();
                    persistSendPreferences(sendHubFeePayer, force).catch(() => undefined);
                  }}
                />
                Force on-chain (skip Fast Pay for this wallet)
              </label>
            </div>
          )}

          <button
            className="primary"
            disabled={busy || !sendTo || !sendAmount}
            onClick={onPreviewSend}
          >
            Continue
          </button>
          {preview && (
            <div className="preview-card">
              <h3>Review & confirm</h3>
              <div className={railBadgeClass(preview.plan.rail)}>{preview.plan.rail_label}</div>
              <p className="muted">{preview.plan.rail_detail}</p>
              <p>
                <strong>{preview.amount_mei} HAC</strong> →{" "}
                <code>{maskAddress(preview.to, hideAddresses)}</code>
              </p>
              <ul className="send-meta">
                <li>
                  <strong>You pay:</strong> {preview.plan.fee_breakdown.payer_debit_mei.toFixed(3)}{" "}
                  HAC
                </li>
                <li>
                  <strong>Recipient receives:</strong>{" "}
                  {preview.plan.fee_breakdown.recipient_credit_mei.toFixed(3)} HAC
                </li>
                <li>
                  <strong>Network fee:</strong> {preview.plan.estimated_fee}
                </li>
                {preview.plan.rail === "L2Fast" &&
                  preview.plan.fee_breakdown.hub_fee_payer === "recipient" && (
                    <li className="muted">
                      Hub fee is taken from the recipient&apos;s credit, not added to your debit.
                    </li>
                  )}
                <li>
                  <strong>From:</strong> <code>{maskAddress(preview.from, hideAddresses)}</code>
                </li>
              </ul>
              {preview.plan.rail === "L1OnChain" && !fastPayReady && (
                <div className="info-box">
                  <p>This payment will use on-chain. Enable Fast Pay for instant sends next time.</p>
                  <button type="button" disabled={busy} onClick={() => onNavigate("fastpay")}>
                    Open Fast Pay tab
                  </button>
                </div>
              )}
              {preview.hip23.errors.length > 0 && (
                <div className="alert">
                  <strong>HIP-23 errors</strong>
                  <ul>
                    {preview.hip23.errors.map((e) => (
                      <li key={e}>{e}</li>
                    ))}
                  </ul>
                </div>
              )}
              {preview.hip23.warnings.length > 0 && (
                <div className="warn-box">
                  <strong>HIP-23 warnings</strong>
                  <ul>
                    {preview.hip23.warnings.map((w) => (
                      <li key={w}>{w}</li>
                    ))}
                  </ul>
                </div>
              )}
              {status?.security_profile === "paranoid" && status.webauthn_enabled && (
                <p className="muted">
                  Paranoid mode: WebAuthn (YubiKey / Windows Hello) required before signing.
                </p>
              )}
              <button
                type="button"
                className="primary"
                disabled={busy || !preview.hip23.ok}
                onClick={onConfirmSend}
              >
                {busy ? "Sending…" : "Confirm & send"}
              </button>
            </div>
          )}
          <p className="muted small-note">
            Quantum (Type 4) sends are on the{" "}
            <button type="button" className="linkish" onClick={() => onNavigate("quantum")}>
              Quantum
            </button>{" "}
            tab.
          </p>
        </>
      )}
    </section>
  );
}
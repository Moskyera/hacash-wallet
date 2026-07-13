import { useState } from "react";
import { AssetSummary, HubFeePayer, L1FeeSpeed, SendPreview, WalletStatus } from "../api";
import type { PaymentQrPayload } from "../paymentQr";
import BtcSendPanel from "../components/BtcSendPanel";
import HacdSendPanel from "../components/HacdSendPanel";
import PaymentQrScanner from "../components/PaymentQrScanner";
import { maskAddress, formatHacMei } from "../privacy";
import {
  formatServiceFeeRate,
  L1_FEE_SPEEDS,
  l1FeeSpeedDetail,
  l1FeeSpeedLabel,
  railBadgeClass,
} from "../fastPayUi";
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
  sendL1FeeSpeed: L1FeeSpeed;
  setSendL1FeeSpeed: (v: L1FeeSpeed) => void;
  sendServiceFeeEnabled: boolean;
  setSendServiceFeeEnabled: (v: boolean) => void;
  serviceFeeRate: number;
  showSendOptions: boolean;
  setShowSendOptions: (v: boolean | ((prev: boolean) => boolean)) => void;
  sendQrScanOpen: boolean;
  setSendQrScanOpen: (v: boolean | ((prev: boolean) => boolean)) => void;
  preview: SendPreview | null;
  clearPreview: () => void;
  persistSendPreferences: (
    hubFeePayer: HubFeePayer,
    forceL1: boolean,
    l1FeeSpeed?: L1FeeSpeed,
    serviceFeeEnabled?: boolean,
  ) => Promise<void>;
  onPaymentQr: (payload: PaymentQrPayload) => void;
  onPreviewSend: (speedOverride?: L1FeeSpeed) => void;
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
  sendL1FeeSpeed,
  setSendL1FeeSpeed,
  sendServiceFeeEnabled,
  setSendServiceFeeEnabled,
  serviceFeeRate,
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
  const showL1FeeSpeed =
    sendForceL1 || !fastPayReady || preview?.plan.rail === "L1OnChain";

  const pickL1FeeSpeed = (speed: L1FeeSpeed) => {
    setSendL1FeeSpeed(speed);
    void persistSendPreferences(sendHubFeePayer, sendForceL1, speed);
    if (preview && sendTo.trim() && sendAmount.trim()) {
      onPreviewSend(speed);
      return;
    }
    clearPreview();
  };

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
              <div className="send-options-section">
                <h4 className="send-options-heading">Fast Pay network fee</h4>
                <label className="option-choice">
                  <input
                    type="radio"
                    name="hubFeePayer"
                    checked={sendHubFeePayer === "sender"}
                    onChange={() => {
                      setSendHubFeePayer("sender");
                      clearPreview();
                      void persistSendPreferences("sender", sendForceL1);
                    }}
                  />
                  <span>I pay the fee</span>
                </label>
                <label className="option-choice">
                  <input
                    type="radio"
                    name="hubFeePayer"
                    checked={sendHubFeePayer === "recipient"}
                    onChange={() => {
                      setSendHubFeePayer("recipient");
                      clearPreview();
                      void persistSendPreferences("recipient", sendForceL1);
                    }}
                  />
                  <span>Recipient pays (deducted from amount received)</span>
                </label>
                <p className="muted small-note">
                  Applies to Fast Pay only. On-chain L1 fees are always paid by the sender.
                </p>
              </div>
              <label className="option-choice">
                <input
                  type="checkbox"
                  checked={sendForceL1}
                  onChange={(e) => {
                    const force = e.target.checked;
                    setSendForceL1(force);
                    clearPreview();
                    void persistSendPreferences(sendHubFeePayer, force);
                  }}
                />
                <span>Force on-chain (skip Fast Pay)</span>
              </label>
              <label className="option-choice">
                <input
                  type="checkbox"
                  checked={sendServiceFeeEnabled}
                  onChange={(e) => {
                    const enabled = e.target.checked;
                    setSendServiceFeeEnabled(enabled);
                    clearPreview();
                    void persistSendPreferences(
                      sendHubFeePayer,
                      sendForceL1,
                      sendL1FeeSpeed,
                      enabled,
                    );
                  }}
                />
                <span>
                  Ecosystem service fee ({formatServiceFeeRate(serviceFeeRate)} of amount, for
                  future DEX)
                </span>
              </label>
            </div>
          )}

          {showL1FeeSpeed ? (
            <div className="l1-fee-section">
              <h4>On-chain network fee</h4>
              <div className="display-toggle l1-fee-toggle">
                {L1_FEE_SPEEDS.map((speed) => {
                  const tierFee = preview?.plan.l1_fee_tiers?.find((t) => t.speed === speed)?.fee_mei;
                  const label = l1FeeSpeedLabel(speed);
                  return (
                    <button
                      key={speed}
                      type="button"
                      className={sendL1FeeSpeed === speed ? "selected" : ""}
                      disabled={busy}
                      onClick={() => pickL1FeeSpeed(speed)}
                    >
                      {tierFee != null ? `${label} ~${formatHacMei(tierFee)}` : label}
                    </button>
                  );
                })}
              </div>
              <p className="muted small-note">{l1FeeSpeedDetail(sendL1FeeSpeed)}</p>
              {!sendForceL1 && fastPayReady && preview?.plan.rail !== "L1OnChain" ? (
                <p className="muted small-note">
                  Used when this payment routes on-chain instead of Fast Pay.
                </p>
              ) : null}
            </div>
          ) : null}

          <button
            className="primary"
            disabled={busy || !sendTo || !sendAmount}
            onClick={() => onPreviewSend()}
          >
            Continue
          </button>
          {preview && (
            <div className="preview-card">
              <h3>Review & confirm</h3>
              <div className={railBadgeClass(preview.plan.rail)}>{preview.plan.rail_label}</div>
              <p className="muted">{preview.plan.rail_detail}</p>
              <p>
                <strong>{formatHacMei(preview.amount_mei)} HAC</strong> →{" "}
                <code>{maskAddress(preview.to, hideAddresses)}</code>
              </p>
              <ul className="send-meta">
                <li>
                  <strong>Amount:</strong> {formatHacMei(preview.amount_mei)} HAC
                </li>
                {preview.plan.rail === "L2Fast" ? (
                  <li>
                    <strong>Instant fee:</strong> ~{formatHacMei(preview.plan.fee_breakdown.hub_fee_mei ?? 0.001)} HAC
                    {preview.plan.fee_breakdown.hub_fee_payer === "recipient" ? " (recipient pays)" : ""}
                  </li>
                ) : (
                  <>
                    <li>
                      <strong>Network fee:</strong>{" "}
                      {formatHacMei(preview.plan.fee_breakdown.l1_fee_mei ?? 0)} HAC (
                      {l1FeeSpeedLabel(sendL1FeeSpeed)})
                    </li>
                    <li>
                      <div className="display-toggle l1-fee-toggle" style={{ marginTop: 8 }}>
                        {L1_FEE_SPEEDS.map((speed) => {
                          const tier = preview.plan.l1_fee_tiers?.find((t) => t.speed === speed);
                          const label = l1FeeSpeedLabel(speed);
                          return (
                            <button
                              key={speed}
                              type="button"
                              className={sendL1FeeSpeed === speed ? "selected" : ""}
                              disabled={busy}
                              onClick={() => pickL1FeeSpeed(speed)}
                            >
                              {tier
                                ? `${label} ~${formatHacMei(tier.fee_mei)}`
                                : label}
                            </button>
                          );
                        })}
                      </div>
                    </li>
                  </>
                )}
                {(preview.plan.fee_breakdown.service_fee_mei ?? 0) > 0 ? (
                  <li>
                    <strong>Service fee:</strong>{" "}
                    {formatHacMei(preview.plan.fee_breakdown.service_fee_mei ?? 0)} HAC (
                    {formatServiceFeeRate(preview.plan.fee_breakdown.service_fee_rate)})
                    {preview.plan.fee_breakdown.service_fee_treasury ? (
                      <>
                        {" "}
                        →{" "}
                        <code>
                          {maskAddress(preview.plan.fee_breakdown.service_fee_treasury, hideAddresses)}
                        </code>
                      </>
                    ) : null}
                  </li>
                ) : null}
                <li>
                  <strong>You pay:</strong> {formatHacMei(preview.plan.fee_breakdown.payer_debit_mei)} HAC
                </li>
                <li>
                  <strong>Recipient receives:</strong>{" "}
                  {formatHacMei(preview.plan.fee_breakdown.recipient_credit_mei)} HAC
                </li>
                {preview.plan.rail === "L2Fast" &&
                  preview.plan.fee_breakdown.hub_fee_payer === "recipient" && (
                    <li className="muted small-note">
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
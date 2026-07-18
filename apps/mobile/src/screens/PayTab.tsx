import { useState } from "react";
import AssetSelector from "../components/AssetSelector";
import BtcNetworkNotice from "../components/BtcNetworkNotice";
import DustWhisperPayOptions from "../components/DustWhisperPayOptions";
import HacdDiamondVisual from "../components/HacdDiamondVisual";
import PaymentQrScanner from "../components/PaymentQrScanner";
import { useHacdSend } from "../hooks/useHacdSend";
import { useBtcSend } from "../hooks/useBtcSend";
import type {
  DustWhisperSettings,
  HubFeePayer,
  PlatformSecurityStatus,
  SendPreview,
  WalletSettings,
} from "../api";
import type { L1FeeSpeed } from "../api";
import { resolveDustWhisper } from "../dustWhisper";
import type { SavedContact } from "../contacts";
import { formatHacMei, maskAddress } from "../privacy";
import { BIOMETRIC_THRESHOLD_MEI } from "../utils/appConstants";
import {
  isValidHacdName,
  normalizeHacdName,
  type PaymentAsset,
} from "@hacash/wallet-ui";
import type { PaymentQrPayload } from "../paymentQr";
import {
  formatServiceFeeRate,
  L1_FEE_SPEEDS,
  l1FeeSpeedDetail,
  l1FeeSpeedLabel,
} from "../fastPayUi";

type Props = {
  contacts: SavedContact[];
  sendTo: string;
  setSendTo: (v: string) => void;
  sendAmount: string;
  setSendAmount: (v: string) => void;
  sendHubFeePayer: HubFeePayer;
  sendForceL1: boolean;
  setSendForceL1: (v: boolean) => void;
  sendL1FeeSpeed: L1FeeSpeed;
  setSendL1FeeSpeed: (v: L1FeeSpeed) => void;
  sendServiceFeeEnabled: boolean;
  setSendServiceFeeEnabled: (v: boolean) => void;
  serviceFeeRate: number;
  preview: SendPreview | null;
  payScanMode: boolean;
  setPayScanMode: (v: boolean) => void;
  payCameraIntent: boolean;
  onCameraIntentConsumed: () => void;
  hideAddresses: boolean;
  settings: WalletSettings | null;
  platformSec: PlatformSecurityStatus | null;
  busy: boolean;
  dustWhisper?: DustWhisperSettings | null;
  onPersistSendPrefs: (
    hubFee: HubFeePayer,
    forceL1: boolean,
    l1FeeSpeed?: L1FeeSpeed,
    serviceFeeEnabled?: boolean,
  ) => void;
  onPersistDustWhisper: (patch: Partial<DustWhisperSettings>) => void | Promise<void>;
  onResetPreview: () => void;
  onPreviewSend: (speedOverride?: L1FeeSpeed) => void;
  onConfirmSend: () => void;
  onPaymentQr: (p: PaymentQrPayload) => void;
  onToast: (msg: string, kind: "success" | "info" | "error") => void;
  onRefresh: () => Promise<void>;
  setBusy: (b: boolean) => void;
};

export default function PayTab({
  contacts,
  sendTo,
  setSendTo,
  sendAmount,
  setSendAmount,
  sendHubFeePayer,
  sendForceL1,
  setSendForceL1,
  sendL1FeeSpeed,
  setSendL1FeeSpeed,
  serviceFeeRate,
  preview,
  payScanMode,
  setPayScanMode,
  payCameraIntent,
  onCameraIntentConsumed,
  hideAddresses,
  settings,
  platformSec,
  busy,
  dustWhisper,
  onPersistSendPrefs,
  onPersistDustWhisper,
  onResetPreview,
  onPreviewSend,
  onConfirmSend,
  onPaymentQr,
  onToast,
  onRefresh,
  setBusy,
}: Props) {
  const [asset, setAsset] = useState<PaymentAsset>("HAC");
  const [hacdDisplay, setHacdDisplay] = useState<"name" | "visual">("visual");
  const [manualHacd, setManualHacd] = useState("");
  const hacd = useHacdSend({
    active: asset === "HACD",
    settings,
    platformSec,
    setBusy,
    refresh: onRefresh,
    showToast: onToast,
  });

  const btc = useBtcSend({
    active: asset === "BTC",
    settings,
    platformSec,
    setBusy,
    refresh: onRefresh,
    showToast: onToast,
  });

  const primaryHacd = hacd.selected[0] ?? normalizeHacdName(manualHacd);
  const whisper = resolveDustWhisper(dustWhisper);
  const whisperActive = whisper.enabled && whisper.relay_urls.some((u) => u.trim().length > 0);
  const preferFastPay = settings?.send?.prefer_fast_pay ?? true;
  const showL1FeeSpeed =
    sendForceL1 || !preferFastPay || preview?.plan.rail === "L1OnChain";

  const pickL1FeeSpeed = (speed: L1FeeSpeed) => {
    setSendL1FeeSpeed(speed);
    void onPersistSendPrefs(sendHubFeePayer, sendForceL1, speed);
    if (preview && sendTo.trim() && sendAmount.trim()) {
      void onPreviewSend(speed);
      return;
    }
    onResetPreview();
  };

  const applyManualHacd = (raw: string) => {
    const norm = normalizeHacdName(raw);
    setManualHacd(norm);
    if (isValidHacdName(norm)) {
      hacd.setSingleDiamond(norm);
      hacd.resetPreview();
    }
  };

  return (
    <div className="card">
      <h2>Pay</h2>
      <AssetSelector
        value={asset}
        onChange={(next) => {
          setAsset(next);
          onResetPreview();
          hacd.resetPreview();
          setPayScanMode(false);
        }}
      />

      {asset === "HAC" && (
        <>
          {contacts.length > 0 && (
            <div className="chip-row">
              {contacts.slice(0, 6).map((c) => (
                <button
                  key={c.id}
                  type="button"
                  className={`chip ${sendTo === c.address ? "selected" : ""}`}
                  onClick={() => {
                    setSendTo(c.address);
                    onResetPreview();
                  }}
                >
                  {c.label}
                </button>
              ))}
            </div>
          )}
          {payScanMode ? (
            <PaymentQrScanner
              autoStart={payCameraIntent}
              onAutoStarted={onCameraIntentConsumed}
              disabled={busy}
              onDetected={(p) => void onPaymentQr(p)}
              onError={(msg) => onToast(msg, "error")}
            />
          ) : (
            <button type="button" onClick={() => setPayScanMode(true)}>
              Scan QR code
            </button>
          )}
          <label className="label">Recipient</label>
          <input
            placeholder="Hacash address"
            value={sendTo}
            onChange={(e) => {
              setSendTo(e.target.value);
              onResetPreview();
            }}
          />
          <label className="label">Amount (HAC)</label>
          <input
            type="number"
            min="0"
            step="0.001"
            placeholder="0.000"
            value={sendAmount}
            onChange={(e) => {
              setSendAmount(e.target.value);
              onResetPreview();
            }}
          />
          <div className="option-block">
            <p className="label">Payment options</p>
            <p className="muted small">Fast Pay has no network fee and no wallet service fee.</p>
            <label className="check-row">
              <input
                type="checkbox"
                checked={sendForceL1}
                onChange={(e) => {
                  const force = e.target.checked;
                  setSendForceL1(force);
                  void onPersistSendPrefs(sendHubFeePayer, force);
                  onResetPreview();
                }}
              />
              Force on-chain (L1)
            </label>
            <div className="check-row" role="note">
              On-chain wallet service fee: {formatServiceFeeRate(serviceFeeRate)} of amount. It is
              included in the signed L1 transaction.
            </div>
            {showL1FeeSpeed ? (
              <div style={{ marginTop: "0.75rem" }}>
                <p className="label">On-chain network fee</p>
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
                <p className="muted small">{l1FeeSpeedDetail(sendL1FeeSpeed)}</p>
              </div>
            ) : null}
            <DustWhisperPayOptions
              dustWhisper={whisper}
              onPersist={onPersistDustWhisper}
              disabled={busy}
              showFastPayNote
            />
          </div>
          <button className="primary" disabled={busy || !sendTo || !sendAmount} onClick={() => void onPreviewSend()}>
            Preview payment
          </button>
          {preview && (
            <div className="preview-box animate-in">
              <span className="badge badge-rail">{preview.plan.rail_label}</span>
              <p className="muted small">{preview.plan.rail_detail}</p>
              <p>
                <strong>{preview.amount_mei} HAC</strong> →{" "}
                <code>{maskAddress(preview.to, hideAddresses)}</code>
              </p>
              <ul className="send-meta" style={{ margin: "0.75rem 0", paddingLeft: "1.1rem" }}>
                <li>
                  <strong>Amount:</strong> {formatHacMei(preview.amount_mei)} HAC
                </li>
                {preview.plan.rail === "L2Fast" ? (
                  <li>
                    <strong>Fast Pay fee:</strong> 0 HAC
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
                              {tier ? `${label} ~${formatHacMei(tier.fee_mei)}` : label}
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
                  <strong>Recipient gets:</strong> {formatHacMei(preview.plan.fee_breakdown.recipient_credit_mei)} HAC
                </li>
              </ul>
              {!preview.hip23.ok && <p className="error">{preview.hip23.errors.join("; ")}</p>}
              {preview.plan.rail === "L1OnChain" && whisperActive ? (
                <p className="muted small">Broadcast via DUST Whisper relay.</p>
              ) : null}
              {platformSec?.native_biometric_available && preview.amount_mei >= BIOMETRIC_THRESHOLD_MEI && (
                <p className="muted">Biometric confirmation required.</p>
              )}
              <button
                className="primary"
                disabled={busy || !preview.hip23.ok}
                onClick={() => void onConfirmSend()}
              >
                {busy ? "Sending…" : "Confirm & send"}
              </button>
            </div>
          )}
        </>
      )}

      {asset === "HACD" && (
        <>
          <label className="check-row">
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

          <label className="label">
            {hacd.batchMode ? "Select HACD to send" : "HACD to send"}
          </label>
          {hacd.owned.length > 0 && (
            <div className="chip-row">
              {hacd.owned.slice(0, 12).map((name) => (
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
            <p className="muted small">Selected: {hacd.selected.join(", ")}</p>
          )}
          {hacd.owned.length === 0 && (
            <p className="muted small">
              No verified HACD found on the configured node. Metadata search may still show
              read-only mainnet information.
            </p>
          )}

          {hacdDisplay === "visual" && primaryHacd && <HacdDiamondVisual name={primaryHacd} />}

          <label className="label">Recipient Hacash address</label>
          {contacts.length > 0 && (
            <div className="chip-row">
              {contacts.slice(0, 6).map((c) => (
                <button
                  key={c.id}
                  type="button"
                  className={`chip ${hacd.recipient === c.address ? "selected" : ""}`}
                  onClick={() => {
                    hacd.setRecipient(c.address);
                    hacd.resetPreview();
                  }}
                >
                  {c.label}
                </button>
              ))}
            </div>
          )}
          {hacd.recipientScanOpen ? (
            <PaymentQrScanner
              disabled={busy}
              onAddressDetected={(addr) => hacd.applyRecipientAddress(addr)}
              onError={(msg) => onToast(msg, "error")}
            />
          ) : (
            <button type="button" onClick={() => hacd.setRecipientScanOpen(true)}>
              Scan recipient QR
            </button>
          )}
          <input
            placeholder="1ABC…"
            value={hacd.recipient}
            onChange={(e) => {
              hacd.setRecipient(e.target.value);
              hacd.resetPreview();
            }}
          />

          <p className="muted small">
            On chain L1. Network fee is estimated from the node at preview. For stack tokens use Launchpad.
          </p>
          <div className="option-block">
            <DustWhisperPayOptions
              dustWhisper={whisper}
              onPersist={onPersistDustWhisper}
              disabled={busy}
            />
          </div>

          <button
            className="primary"
            disabled={busy || hacd.selected.length === 0 || !hacd.recipient.trim()}
            onClick={() => void hacd.handlePreview()}
          >
            Preview HACD send
          </button>

          {hacd.preview && (
            <div className="preview-box animate-in">
              <span className="badge badge-rail">On-chain (L1)</span>
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
              {whisperActive ? <p className="muted small">Broadcast via DUST Whisper relay.</p> : null}
              {!hacd.preview.hip23.ok && <p className="error">{hacd.preview.hip23.errors.join("; ")}</p>}
              {platformSec?.native_biometric_available && (
                <p className="muted">Biometric confirmation will be required.</p>
              )}
              <button
                className="primary"
                disabled={busy || !hacd.preview.hip23.ok}
                onClick={() => void hacd.handleConfirm()}
              >
                {busy ? "Sending…" : "Confirm & send HACD"}
              </button>
            </div>
          )}
        </>
      )}

      {asset === "BTC" && (
        <>
          <BtcNetworkNotice onNotify={onToast} />
          <label className="label">Recipient Hacash address</label>
          <input
            placeholder="1ABC…"
            value={btc.recipient}
            onChange={(e) => {
              btc.setRecipient(e.target.value);
              btc.resetPreview();
            }}
          />
          <label className="label">Amount (BTC)</label>
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
          <div className="option-block">
            <DustWhisperPayOptions
              dustWhisper={whisper}
              onPersist={onPersistDustWhisper}
              disabled={busy}
            />
          </div>
          <button
            className="primary"
            disabled={
              busy ||
              !btc.recipient.trim().startsWith("1") ||
              !btc.btcAmount ||
              Number(btc.btcAmount) <= 0
            }
            onClick={() => void btc.handlePreview()}
          >
            Review BTC on Hacash send
          </button>
          {btc.preview && (
            <div className="preview-box animate-in">
              <span className="badge badge-rail">On-chain (L1)</span>
              <p>
                <strong>{btc.preview.btc_amount.toFixed(8)} BTC</strong> ({btc.preview.satoshi} sat) →{" "}
                <code>{maskAddress(btc.preview.to, hideAddresses)}</code>
              </p>
              <p className="muted">Network fee: {btc.preview.fee_mei.toFixed(3)} HAC</p>
              <p className="muted">
                Wallet fee (0.3%): {btc.preview.service_fee_btc.toFixed(8)} BTC · total{" "}
                {btc.preview.total_debit_satoshi} sat
              </p>
              {whisperActive ? <p className="muted small">Broadcast via DUST Whisper relay.</p> : null}
              {!btc.preview.hip23.ok && (
                <p className="error">{btc.preview.hip23.errors.join("; ")}</p>
              )}
              <button
                className="primary"
                disabled={busy || !btc.preview.hip23.ok}
                onClick={() => void btc.handleConfirm()}
              >
                {busy ? "Sending…" : "Confirm BTC on Hacash send"}
              </button>
            </div>
          )}
        </>
      )}
    </div>
  );
}

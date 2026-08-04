import { useEffect, useMemo, useState } from "react";
import type { NativeAssetBalance, NativeAssetMetadata } from "./nativeAssets";

export type NativeAssetSendPreview = {
  from: string;
  to: string;
  serial: string;
  amount: string;
  owned_amount: string;
  fee_mei: number;
  fee_wire: string;
  hip23: {
    ok: boolean;
    warnings: string[];
    errors: string[];
  };
  summary: string;
};

type Props = {
  active: boolean;
  assets: readonly NativeAssetBalance[];
  busy: boolean;
  watchOnly?: boolean;
  hideBalances?: boolean;
  formatAddress?: (address: string) => string;
  onBusy: (busy: boolean) => void;
  loadMetadata?: (serial: string) => Promise<NativeAssetMetadata>;
  onPreview: (to: string, serial: string, amount: string) => Promise<NativeAssetSendPreview>;
  onConfirm: (preview: NativeAssetSendPreview) => Promise<void>;
  onError: (error: unknown) => void;
};

export function NativeAssetSendForm({
  active,
  assets,
  busy,
  watchOnly = false,
  hideBalances = false,
  formatAddress = (address) => address,
  onBusy,
  loadMetadata,
  onPreview,
  onConfirm,
  onError,
}: Props) {
  const [serial, setSerial] = useState("");
  const [amount, setAmount] = useState("");
  const [recipient, setRecipient] = useState("");
  const [preview, setPreview] = useState<NativeAssetSendPreview | null>(null);
  const [metadata, setMetadata] = useState<NativeAssetMetadata | null>(null);

  const selected = useMemo(
    () => assets.find((asset) => asset.serial === serial) ?? null,
    [assets, serial],
  );

  useEffect(() => {
    if (!active) {
      setPreview(null);
      return;
    }
    if (!serial || !assets.some((asset) => asset.serial === serial)) {
      setSerial(assets[0]?.serial ?? "");
      setPreview(null);
    }
  }, [active, assets, serial]);

  useEffect(() => {
    if (!active || !serial || !loadMetadata) {
      setMetadata(null);
      return;
    }
    let cancelled = false;
    setMetadata(null);
    void loadMetadata(serial)
      .then((item) => {
        if (!cancelled && item.serial === serial) setMetadata(item);
      })
      .catch(() => {
        if (!cancelled) setMetadata(null);
      });
    return () => {
      cancelled = true;
    };
  }, [active, loadMetadata, serial]);

  const resetPreview = () => setPreview(null);

  const handlePreview = async () => {
    if (!serial || !amount.trim() || !recipient.trim()) return;
    onBusy(true);
    setPreview(null);
    try {
      setPreview(await onPreview(recipient.trim(), serial, amount.trim()));
    } catch (error) {
      onError(error);
    } finally {
      onBusy(false);
    }
  };

  const handleConfirm = async () => {
    if (!preview) return;
    onBusy(true);
    try {
      await onConfirm(preview);
      setPreview(null);
      setAmount("");
      setRecipient("");
    } catch (error) {
      onError(error);
    } finally {
      onBusy(false);
    }
  };

  if (watchOnly) {
    return <div className="info-box">Watch-only wallets cannot send HIP-20 assets.</div>;
  }
  if (assets.length === 0) {
    return (
      <div className="info-box">
        No HIP-20 assets were reported for this address. Purchased assets appear here after
        confirmation and refresh.
      </div>
    );
  }

  return (
    <div className="send-asset-panel native-asset-send">
      <div className="info-box">
        <strong>HIP-20 native assets</strong>
        <p>
          Direct on-chain transfer only. Verify the canonical asset serial. This screen does not
          sign reusable marketplace orders.
        </p>
      </div>

      <label>Asset</label>
      <select
        value={serial}
        disabled={busy}
        onChange={(event) => {
          setSerial(event.target.value);
          resetPreview();
        }}
      >
        {assets.map((asset) => (
          <option key={asset.serial} value={asset.serial}>
            Asset #{asset.serial}
            {hideBalances ? "" : ` · ${asset.amount} owned`}
          </option>
        ))}
      </select>

      <label>Amount (smallest asset units)</label>
      <input
        value={amount}
        inputMode="numeric"
        pattern="[0-9]*"
        placeholder="1"
        disabled={busy}
        onChange={(event) => {
          setAmount(event.target.value.replace(/[^0-9]/g, ""));
          resetPreview();
        }}
      />
      {metadata ? (
        <p className="muted small-note">
          <strong>{metadata.ticket}</strong> · {metadata.name} · Asset #{metadata.serial}
        </p>
      ) : null}
      {selected && !hideBalances ? (
        <p className="muted small-note">Available: {selected.amount}</p>
      ) : null}

      <label>Recipient Hacash address</label>
      <input
        value={recipient}
        autoCapitalize="none"
        autoCorrect="off"
        spellCheck={false}
        placeholder="1ABC..."
        disabled={busy}
        onChange={(event) => {
          setRecipient(event.target.value);
          resetPreview();
        }}
      />

      <button
        type="button"
        className="primary"
        disabled={busy || !serial || !amount || !recipient.trim()}
        onClick={() => void handlePreview()}
      >
        Preview HIP-20 transfer
      </button>

      {preview ? (
        <div className="preview-card">
          <h3>Review HIP-20 transfer</h3>
          <p>
            <strong>
              {preview.amount} units of asset #{preview.serial}
            </strong>
          </p>
          <p>
            Recipient: <code>{formatAddress(preview.to)}</code>
          </p>
          <p className="muted">Network fee: {preview.fee_wire} HAC</p>
          <p className="muted">Asset serial is the canonical identity. Metadata is display-only.</p>
          {preview.hip23.warnings.length > 0 ? (
            <ul className="send-meta">
              {preview.hip23.warnings.map((warning) => (
                <li key={warning}>{warning}</li>
              ))}
            </ul>
          ) : null}
          <button
            type="button"
            className="primary"
            disabled={busy || !preview.hip23.ok}
            onClick={() => void handleConfirm()}
          >
            {busy ? "Sending..." : "Confirm and send HIP-20"}
          </button>
        </div>
      ) : null}
    </div>
  );
}

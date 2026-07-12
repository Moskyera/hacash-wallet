import { useEffect, useState } from "react";
import AssetSelector from "../components/AssetSelector";
import HacdDiamondVisual from "../components/HacdDiamondVisual";
import PaymentQrDisplay from "../components/PaymentQrDisplay";
import { copyWithPrivacyClear } from "../privacy";
import {
  isValidBtcAddress,
  isValidHacdName,
  normalizeHacdName,
  type PaymentAsset,
} from "../utils/paymentAssets";
import { loadBtcReceiveAddress, loadWalletHacdName, saveBtcReceiveAddress, saveWalletHacdName } from "../utils/hacdName";

type Props = {
  address?: string | null;
  receiveAmount: string;
  setReceiveAmount: (v: string) => void;
  clipboardSecs: number;
  onCopyAddress: () => void;
  onShare: () => void;
  onToast: (msg: string, kind: "success" | "info" | "error") => void;
};

export default function ReceiveTab({
  address,
  receiveAmount,
  setReceiveAmount,
  clipboardSecs,
  onCopyAddress,
  onShare,
  onToast,
}: Props) {
  const [asset, setAsset] = useState<PaymentAsset>("HAC");
  const [hacdName, setHacdName] = useState(loadWalletHacdName);
  const [hacdDisplay, setHacdDisplay] = useState<"name" | "visual">("visual");
  const [btcAddress, setBtcAddress] = useState(loadBtcReceiveAddress);

  useEffect(() => {
    if (isValidHacdName(hacdName)) saveWalletHacdName(hacdName);
  }, [hacdName]);

  useEffect(() => {
    if (btcAddress.trim()) saveBtcReceiveAddress(btcAddress);
  }, [btcAddress]);

  const hacdNorm = normalizeHacdName(hacdName);

  const copyHacd = async () => {
    if (!isValidHacdName(hacdNorm)) {
      onToast("Enter a valid HACD name (4–6 letters).", "error");
      return;
    }
    await copyWithPrivacyClear(`hacd:${hacdNorm}`, clipboardSecs);
    onToast("HACD receive code copied.", "success");
  };

  const copyBtc = async () => {
    if (!isValidBtcAddress(btcAddress)) {
      onToast("Enter a valid BTC address.", "error");
      return;
    }
    await copyWithPrivacyClear(btcAddress.trim(), clipboardSecs);
    onToast("BTC address copied.", "success");
  };

  return (
    <div className="card">
      <h2>Receive</h2>
      <AssetSelector value={asset} onChange={setAsset} />

      {asset === "HAC" && (
        <>
          <p className="muted">Share your QR or payment link.</p>
          <label className="label">Requested amount (optional)</label>
          <input
            type="number"
            min="0"
            step="0.001"
            placeholder="Any amount"
            value={receiveAmount}
            onChange={(e) => setReceiveAmount(e.target.value)}
          />
          {address && (
            <PaymentQrDisplay
              address={address}
              amountMei={
                receiveAmount && Number(receiveAmount) > 0 ? Number(receiveAmount) : undefined
              }
            />
          )}
          <div className="row-btns">
            <button type="button" onClick={() => void onCopyAddress()}>
              Copy address
            </button>
            <button type="button" className="primary" onClick={() => void onShare()}>
              Share link
            </button>
          </div>
        </>
      )}

      {asset === "HACD" && (
        <>
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
              Visual
            </button>
          </div>
          <label className="label">Your HACD name</label>
          <input
            placeholder="e.g. WTUYUI"
            value={hacdName}
            onChange={(e) => setHacdName(e.target.value.toUpperCase())}
            maxLength={6}
          />
          {hacdDisplay === "visual" ? (
            <HacdDiamondVisual name={hacdNorm} />
          ) : (
            <p className="receive-name-only">
              <strong>{hacdNorm || "NAME"}</strong>
            </p>
          )}
          <p className="muted small">
            Share your name or <code>hacd:{hacdNorm || "NAME"}</code> to receive HACD. Visual is unique per diamond.
          </p>
          <button type="button" className="primary" disabled={!isValidHacdName(hacdNorm)} onClick={() => void copyHacd()}>
            Copy HACD code
          </button>
        </>
      )}

      {asset === "BTC" && (
        <>
          <label className="label">Your BTC receive address</label>
          <input
            placeholder="bc1… or 1…"
            value={btcAddress}
            onChange={(e) => setBtcAddress(e.target.value)}
          />
          <p className="muted small">Receive on-chain BTC to this wallet address.</p>
          <button type="button" className="primary" disabled={!isValidBtcAddress(btcAddress)} onClick={() => void copyBtc()}>
            Copy BTC address
          </button>
        </>
      )}
    </div>
  );
}
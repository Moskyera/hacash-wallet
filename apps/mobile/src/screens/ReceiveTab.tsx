import { useEffect, useState } from "react";
import AssetSelector from "../components/AssetSelector";
import BtcNetworkNotice from "../components/BtcNetworkNotice";
import HacdDiamondVisual from "../components/HacdDiamondVisual";
import PaymentQrDisplay from "../components/PaymentQrDisplay";
import { copyWithPrivacyClear, maskAddress } from "../privacy";
import {
  isValidHacdName,
  normalizeHacdName,
  type PaymentAsset,
} from "../utils/paymentAssets";
import { loadWalletHacdName, saveWalletHacdName } from "../utils/hacdName";

type Props = {
  address?: string | null;
  ownedHacdNames?: string[];
  receiveAmount: string;
  setReceiveAmount: (value: string) => void;
  hideAddresses: boolean;
  clipboardSecs: number;
  onCopyAddress: () => void;
  onShare: () => void;
  onToast: (message: string, kind: "success" | "info" | "error") => void;
};

export default function ReceiveTab({
  address,
  ownedHacdNames = [],
  receiveAmount,
  setReceiveAmount,
  hideAddresses,
  clipboardSecs,
  onCopyAddress,
  onShare,
  onToast,
}: Props) {
  const [asset, setAsset] = useState<PaymentAsset>("HAC");
  const [hacdName, setHacdName] = useState(() => loadWalletHacdName() || ownedHacdNames[0] || "");
  const [hacdDisplay, setHacdDisplay] = useState<"name" | "visual">("visual");

  useEffect(() => {
    if (isValidHacdName(hacdName)) saveWalletHacdName(hacdName);
  }, [hacdName]);

  const hacdNorm = normalizeHacdName(hacdName);

  const copyHacd = async () => {
    if (!isValidHacdName(hacdNorm)) {
      onToast("Enter a valid HACD name (4 to 6 letters).", "error");
      return;
    }
    await copyWithPrivacyClear(`hacd:${hacdNorm}`, clipboardSecs);
    onToast("HACD receive code copied.", "success");
  };

  const copyBtc = async () => {
    if (!address) {
      onToast("Hacash receive address is unavailable.", "error");
      return;
    }
    await copyWithPrivacyClear(address, clipboardSecs);
    onToast("Hacash address for BTC copied.", "success");
  };

  return (
    <div className="card receive-card">
      <div className="section-heading">
        <div>
          <p className="eyebrow">Wallet address</p>
          <h2>Receive</h2>
        </div>
      </div>
      <AssetSelector value={asset} onChange={setAsset} />

      {asset === "HAC" && (
        <section className="receive-section">
          <p className="muted">Share your Hacash address or a payment request.</p>
          <label className="label">Requested amount (optional)</label>
          <input
            type="number"
            min="0"
            step="0.001"
            inputMode="decimal"
            placeholder="Any amount"
            value={receiveAmount}
            onChange={(event) => setReceiveAmount(event.target.value)}
          />
          {address && (
            <PaymentQrDisplay
              address={address}
              amountMei={
                receiveAmount && Number(receiveAmount) > 0 ? Number(receiveAmount) : undefined
              }
              hideAddress={hideAddresses}
            />
          )}
          <div className="address-box">
            <code>{maskAddress(address, hideAddresses)}</code>
          </div>
          {!hideAddresses && address && (
            <div className="row-btns">
              <button type="button" onClick={() => void onCopyAddress()}>
                Copy address
              </button>
              <button type="button" className="primary" onClick={() => void onShare()}>
                Share link
              </button>
            </div>
          )}
        </section>
      )}

      {asset === "HACD" && (
        <section className="receive-section">
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

          <label className="label">Your HACD name</label>
          {ownedHacdNames.length > 0 && (
            <div className="chip-row" aria-label="Owned HACD">
              {ownedHacdNames.slice(0, 12).map((name) => (
                <button
                  key={name}
                  type="button"
                  className={`chip ${hacdNorm === name ? "selected" : ""}`}
                  onClick={() => setHacdName(name)}
                >
                  {name}
                </button>
              ))}
            </div>
          )}
          <input
            placeholder="e.g. WTUYUI"
            value={hacdName}
            onChange={(event) => setHacdName(event.target.value.toUpperCase())}
            maxLength={6}
            autoCapitalize="characters"
            spellCheck={false}
          />
          {hacdDisplay === "visual" ? (
            <HacdDiamondVisual name={hacdNorm} />
          ) : (
            <p className="receive-name-only">
              <strong>{hacdNorm || "NAME"}</strong>
            </p>
          )}
          <p className="muted small">
            Share the name or <code>hacd:{hacdNorm || "NAME"}</code>. The metadata card is loaded
            from the configured Hacash node.
          </p>
          <button
            type="button"
            className="primary"
            disabled={!isValidHacdName(hacdNorm)}
            onClick={() => void copyHacd()}
          >
            Copy HACD code
          </button>
        </section>
      )}

      {asset === "BTC" && (
        <section className="receive-section">
          <BtcNetworkNotice onNotify={onToast} />
          <label className="label">Your Hacash receive address</label>
          {address && (
            <PaymentQrDisplay
              address={address}
              hideAddress={hideAddresses}
              caption="Hacash address for BTC on Hacash"
            />
          )}
          <div className="address-box">
            <code>{maskAddress(address, hideAddresses)}</code>
          </div>
          <p className="muted small">
            Receives BTC already circulating on Hacash. This is not a Bitcoin L1 deposit address.
          </p>
          {!hideAddresses && address && (
            <button type="button" className="primary" onClick={() => void copyBtc()}>
              Copy Hacash address for BTC
            </button>
          )}
        </section>
      )}
    </div>
  );
}
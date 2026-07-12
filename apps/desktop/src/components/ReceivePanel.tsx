import { useEffect, useState } from "react";
import HacdDiamondVisual from "./HacdDiamondVisual";
import PaymentQrDisplay from "./PaymentQrDisplay";
import { encodePaymentUri } from "../paymentQr";
import { copyWithPrivacyClear, maskAddress } from "../privacy";
import {
  isValidBtcAddress,
  isValidHacdName,
  normalizeHacdName,
  type PaymentAsset,
} from "../utils/paymentAssets";
import {
  loadBtcReceiveAddress,
  loadWalletHacdName,
  saveBtcReceiveAddress,
  saveWalletHacdName,
} from "../utils/receivePrefs";

type Props = {
  address?: string | null;
  ownedHacdNames?: string[];
  receiveAmount: string;
  setReceiveAmount: (v: string) => void;
  hideAddresses: boolean;
  clipboardSecs: number;
  busy: boolean;
  onCopyAddress: () => void;
  onNotify: (msg: string, kind: "success" | "info" | "error") => void;
};

export default function ReceivePanel({
  address,
  ownedHacdNames = [],
  receiveAmount,
  setReceiveAmount,
  hideAddresses,
  clipboardSecs,
  busy,
  onCopyAddress,
  onNotify,
}: Props) {
  const [asset, setAsset] = useState<PaymentAsset>("HAC");
  const [hacdName, setHacdName] = useState(() => {
    const saved = loadWalletHacdName();
    return saved || ownedHacdNames[0] || "";
  });
  const [hacdDisplay, setHacdDisplay] = useState<"name" | "visual">("visual");
  const [btcAddress, setBtcAddress] = useState(loadBtcReceiveAddress);

  useEffect(() => {
    if (isValidHacdName(hacdName)) saveWalletHacdName(hacdName);
  }, [hacdName]);

  useEffect(() => {
    if (btcAddress.trim()) saveBtcReceiveAddress(btcAddress);
  }, [btcAddress]);

  const hacdNorm = normalizeHacdName(hacdName);

  async function copyHacd() {
    if (!isValidHacdName(hacdNorm)) {
      onNotify("Enter a valid HACD name (4 to 6 letters).", "error");
      return;
    }
    await copyWithPrivacyClear(`hacd:${hacdNorm}`, clipboardSecs);
    onNotify("HACD receive code copied.", "success");
  }

  async function copyBtc() {
    if (!isValidBtcAddress(btcAddress)) {
      onNotify("Enter a valid BTC address.", "error");
      return;
    }
    await copyWithPrivacyClear(btcAddress.trim(), clipboardSecs);
    onNotify("BTC address copied.", "success");
  }

  async function shareHacLink() {
    if (!address) return;
    const amount =
      receiveAmount && Number(receiveAmount) > 0 ? Number(receiveAmount) : undefined;
    const uri = encodePaymentUri(address, amount);
    try {
      if (navigator.share) {
        await navigator.share({ title: "Hacash payment", text: uri, url: uri });
        onNotify("Shared.", "success");
      } else {
        await copyWithPrivacyClear(uri, clipboardSecs);
        onNotify("Payment link copied.", "success");
      }
    } catch (e) {
      if ((e as Error).name !== "AbortError") {
        onNotify(String(e), "error");
      }
    }
  }

  return (
    <>
      <div className="display-toggle send-asset-toggle">
        <button
          type="button"
          className={asset === "HAC" ? "selected" : ""}
          onClick={() => setAsset("HAC")}
        >
          HAC
        </button>
        <button
          type="button"
          className={asset === "HACD" ? "selected" : ""}
          onClick={() => setAsset("HACD")}
        >
          HACD
        </button>
        <button
          type="button"
          className={asset === "BTC" ? "selected" : ""}
          onClick={() => setAsset("BTC")}
        >
          BTC
        </button>
      </div>

      {asset === "HAC" && (
        <div className="send-section">
          <p className="muted">
            Show your QR code for quick payments. Fast Pay and on-chain both credit the same
            address.
          </p>
          <label>Requested amount (optional, HAC)</label>
          <input
            value={receiveAmount}
            onChange={(e) => setReceiveAmount(e.target.value)}
            placeholder="Leave empty for any amount"
            type="number"
            min="0"
            step="0.001"
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
          {address && !hideAddresses && (
            <div className="actions-row">
              <button type="button" disabled={busy} onClick={onCopyAddress}>
                Copy address
              </button>
              <button type="button" className="primary" disabled={busy} onClick={() => void shareHacLink()}>
                Share link
              </button>
            </div>
          )}
        </div>
      )}

      {asset === "HACD" && (
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
              Visual
            </button>
          </div>
          <label>Your HACD name</label>
          {ownedHacdNames.length > 0 && (
            <div className="chip-row">
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
          <p className="muted small-note">
            Share your name or <code>hacd:{hacdNorm || "NAME"}</code> to receive HACD. Visual is
            unique per diamond.
          </p>
          <button
            type="button"
            className="primary"
            disabled={!isValidHacdName(hacdNorm)}
            onClick={() => void copyHacd()}
          >
            Copy HACD code
          </button>
        </div>
      )}

      {asset === "BTC" && (
        <div className="send-section">
          <label>Your BTC receive address</label>
          <input
            placeholder="bc1… or 1…"
            value={btcAddress}
            onChange={(e) => setBtcAddress(e.target.value)}
          />
          <p className="muted small-note">Receive on-chain BTC to this wallet address.</p>
          <button
            type="button"
            className="primary"
            disabled={!isValidBtcAddress(btcAddress)}
            onClick={() => void copyBtc()}
          >
            Copy BTC address
          </button>
        </div>
      )}
    </>
  );
}
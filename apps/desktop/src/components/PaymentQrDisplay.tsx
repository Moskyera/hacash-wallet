import { useEffect, useState } from "react";
import QRCode from "qrcode";
import { encodePaymentUri } from "../paymentQr";

type Props = {
  address: string;
  amountMei?: number;
  label?: string;
  hideAddress?: boolean;
};

export default function PaymentQrDisplay({
  address,
  amountMei,
  label,
  hideAddress = false,
}: Props) {
  const [dataUrl, setDataUrl] = useState<string | null>(null);
  const [uri, setUri] = useState("");

  useEffect(() => {
    if (!address || hideAddress) {
      setDataUrl(null);
      setUri("");
      return;
    }
    let cancelled = false;
    const paymentUri = encodePaymentUri(address, amountMei, label);
    setUri(paymentUri);
    QRCode.toDataURL(paymentUri, { errorCorrectionLevel: "M", margin: 1, width: 280 })
      .then((url) => {
        if (!cancelled) setDataUrl(url);
      })
      .catch(() => {
        if (!cancelled) setDataUrl(null);
      });
    return () => {
      cancelled = true;
    };
  }, [address, amountMei, label, hideAddress]);

  if (hideAddress || !dataUrl) {
    return (
      <p className="muted">Enable address visibility in Privacy to show a receive QR code.</p>
    );
  }

  return (
    <div className="payment-qr-block">
      <div className="qr-card">
        <img src={dataUrl} alt="Hacash payment QR code" width={220} height={220} />
        <span className="muted small-note">
          {amountMei != null && amountMei > 0
            ? `Request ${amountMei} HAC`
            : "Address only — any amount"}
        </span>
      </div>
      <p className="muted small-note qr-uri-hint">
        Scan with Send → Scan QR, or any Hacash wallet.
      </p>
      <code className="qr-uri-text">{uri}</code>
    </div>
  );
}
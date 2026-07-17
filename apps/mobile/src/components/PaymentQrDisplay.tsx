import { useEffect, useState } from "react";
import QRCode from "qrcode";
import { encodePaymentUri } from "../paymentQr";

type Props = {
  address: string;
  amountMei?: number;
  caption?: string;
  hideAddress?: boolean;
};

export default function PaymentQrDisplay({
  address,
  amountMei,
  caption,
  hideAddress = false,
}: Props) {
  const [dataUrl, setDataUrl] = useState<string | null>(null);

  useEffect(() => {
    if (!address || hideAddress) {
      setDataUrl(null);
      return;
    }
    let cancelled = false;
    const uri = encodePaymentUri(address, amountMei);
    QRCode.toDataURL(uri, { errorCorrectionLevel: "M", margin: 1, width: 260 })
      .then((url) => {
        if (!cancelled) setDataUrl(url);
      })
      .catch(() => {
        if (!cancelled) setDataUrl(null);
      });
    return () => {
      cancelled = true;
    };
  }, [address, amountMei, hideAddress]);

  if (hideAddress) {
    return <p className="muted">Show addresses in Privacy to display the receive QR code.</p>;
  }

  if (!dataUrl) return null;

  return (
    <div className="qr-wrap">
      <img src={dataUrl} alt="Receive QR" className="qr-img" />
      <p className="muted">
        {caption ?? (amountMei != null && amountMei > 0
          ? `Request ${amountMei} HAC`
          : "Any amount")}
      </p>
    </div>
  );
}
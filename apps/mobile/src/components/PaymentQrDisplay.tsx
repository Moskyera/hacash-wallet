import { useEffect, useState } from "react";
import QRCode from "qrcode";
import { encodePaymentUri } from "../paymentQr";

type Props = {
  address: string;
  amountMei?: number;
};

export default function PaymentQrDisplay({ address, amountMei }: Props) {
  const [dataUrl, setDataUrl] = useState<string | null>(null);

  useEffect(() => {
    if (!address) {
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
  }, [address, amountMei]);

  if (!dataUrl) return null;

  return (
    <div className="qr-wrap">
      <img src={dataUrl} alt="Receive QR" className="qr-img" />
      <p className="muted">
        {amountMei != null && amountMei > 0
          ? `Request ${amountMei} HAC`
          : "Any amount"}
      </p>
    </div>
  );
}
import { useEffect, useState } from "react";
import QRCode from "qrcode";
import { encodePrivateKeyQr } from "../utils/privateKeyQr";

type Props = {
  privateKeyHex: string;
};

export default function PrivateKeyQrDisplay({ privateKeyHex }: Props) {
  const [dataUrl, setDataUrl] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    try {
      const payload = encodePrivateKeyQr(privateKeyHex);
      QRCode.toDataURL(payload, { errorCorrectionLevel: "M", margin: 2, width: 280 })
        .then((url) => {
          if (!cancelled) setDataUrl(url);
        })
        .catch(() => {
          if (!cancelled) setDataUrl(null);
        });
    } catch {
      setDataUrl(null);
    }
    return () => {
      cancelled = true;
    };
  }, [privateKeyHex]);

  if (!dataUrl) return null;

  return (
    <div className="qr-wrap" style={{ marginTop: "0.75rem" }}>
      <img src={dataUrl} alt="Private key QR" className="qr-img" />
      <p className="muted small">
        Scan with Welcome → Import → Scan QR on your new phone. Do not share this screen.
      </p>
    </div>
  );
}
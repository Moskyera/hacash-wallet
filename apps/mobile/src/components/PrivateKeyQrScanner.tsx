import { useCallback } from "react";
import { parsePrivateKeyQr, PRIVATE_KEY_HEX_LEN } from "../utils/privateKeyQr";
import QrScannerBase from "./QrScannerBase";

type Props = {
  onDetected: (hex: string) => void;
  onError: (message: string) => void;
  disabled?: boolean;
};

export default function PrivateKeyQrScanner({ onDetected, onError, disabled = false }: Props) {
  const validate = useCallback((decoded: string) => parsePrivateKeyQr(decoded), []);

  return (
    <QrScannerBase
      mountId="mobile-private-key-qr-reader"
      pastePlaceholder="Paste QR text or 64 character hex"
      pasteButtonLabel="Use pasted key"
      validate={validate}
      invalidMessage={`Not a valid private key QR (expected ${PRIVATE_KEY_HEX_LEN} hex characters).`}
      onDetected={onDetected}
      onError={onError}
      disabled={disabled}
      qrboxSize={240}
      primaryCameraButton
    />
  );
}
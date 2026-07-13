import { useCallback } from "react";
import { isValidHacashAddress, parsePaymentQr, type PaymentQrPayload } from "../paymentQr";
import QrScannerBase from "./QrScannerBase";

type Props = {
  onDetected?: (payload: PaymentQrPayload) => void;
  onAddressDetected?: (address: string) => void;
  onError: (message: string) => void;
  disabled?: boolean;
  autoStart?: boolean;
  onAutoStarted?: () => void;
};

export default function PaymentQrScanner({
  onDetected,
  onAddressDetected,
  onError,
  disabled = false,
  autoStart = false,
  onAutoStarted,
}: Props) {
  const addressOnly = Boolean(onAddressDetected) && !onDetected;

  const validate = useCallback(
    (decoded: string): PaymentQrPayload | string | null => {
      if (addressOnly) {
        const payload = parsePaymentQr(decoded);
        const address = payload?.address ?? (isValidHacashAddress(decoded) ? decoded.trim() : null);
        return address;
      }
      return parsePaymentQr(decoded);
    },
    [addressOnly],
  );

  const handleDetected = useCallback(
    (result: PaymentQrPayload | string) => {
      if (addressOnly) {
        onAddressDetected?.(result as string);
      } else {
        onDetected?.(result as PaymentQrPayload);
      }
    },
    [addressOnly, onAddressDetected, onDetected],
  );

  return (
    <QrScannerBase
      mountId="mobile-payment-qr-reader"
      pastePlaceholder={addressOnly ? "Paste Hacash address or hacash:…" : "Paste hacash:… or address"}
      pasteButtonLabel="Use pasted code"
      validate={validate}
      invalidMessage={addressOnly ? "Not a Hacash address." : "Not a Hacash payment QR."}
      onDetected={handleDetected}
      onError={onError}
      disabled={disabled}
      autoStart={autoStart}
      onAutoStarted={onAutoStarted}
    />
  );
}
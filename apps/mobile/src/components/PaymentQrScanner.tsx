import { useCallback, useEffect, useRef, useState } from "react";
import { Html5Qrcode } from "html5-qrcode/esm/index.js";
import { isValidHacashAddress, parsePaymentQr, type PaymentQrPayload } from "../paymentQr";

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
  const [scanning, setScanning] = useState(false);
  const [pasteInput, setPasteInput] = useState("");
  const scannerRef = useRef<Html5Qrcode | null>(null);
  const handledRef = useRef(false);
  const autoStartedRef = useRef(false);
  const mountId = "mobile-payment-qr-reader";

  const addressOnly = Boolean(onAddressDetected) && !onDetected;

  const stopScanner = useCallback(async () => {
    if (!scannerRef.current) return;
    try {
      await scannerRef.current.stop();
    } catch {
      /* already stopped */
    }
    scannerRef.current.clear();
    scannerRef.current = null;
    setScanning(false);
  }, []);

  useEffect(() => {
    return () => {
      void stopScanner();
    };
  }, [stopScanner]);

  const ingestDecoded = useCallback(
    (decoded: string) => {
      if (addressOnly) {
        const payload = parsePaymentQr(decoded);
        const address = payload?.address ?? (isValidHacashAddress(decoded) ? decoded.trim() : null);
        if (!address) {
          onError("Not a Hacash address.");
          return false;
        }
        onAddressDetected?.(address);
        return true;
      }
      const payload = parsePaymentQr(decoded);
      if (!payload) {
        onError("Not a Hacash payment QR.");
        return false;
      }
      onDetected?.(payload);
      return true;
    },
    [addressOnly, onAddressDetected, onDetected, onError],
  );

  const startScanner = useCallback(async () => {
    if (disabled || scannerRef.current) return;
    handledRef.current = false;
    const scanner = new Html5Qrcode(mountId);
    scannerRef.current = scanner;
    setScanning(true);
    try {
      await scanner.start(
        { facingMode: "environment" },
        { fps: 10, qrbox: { width: 220, height: 220 } },
        (decoded) => {
          if (handledRef.current) return;
          if (!ingestDecoded(decoded)) return;
          handledRef.current = true;
          void stopScanner();
        },
        () => undefined,
      );
    } catch (e) {
      setScanning(false);
      scannerRef.current = null;
      onError(`Camera unavailable: ${e}`);
    }
  }, [disabled, ingestDecoded, onError, stopScanner]);

  useEffect(() => {
    if (!autoStart || disabled || autoStartedRef.current) return;
    autoStartedRef.current = true;
    void startScanner().finally(() => onAutoStarted?.());
  }, [autoStart, disabled, onAutoStarted, startScanner]);

  function ingestPaste() {
    handledRef.current = false;
    if (!ingestDecoded(pasteInput)) return;
    void stopScanner();
    setPasteInput("");
  }

  return (
    <div className="qr-scanner">
      <div id={mountId} className={`qr-reader ${scanning ? "active" : ""}`} />
      {!scanning && (
        <button type="button" disabled={disabled} onClick={() => void startScanner()}>
          Open camera
        </button>
      )}
      {scanning && (
        <button type="button" disabled={disabled} onClick={() => void stopScanner()}>
          Stop camera
        </button>
      )}
      <input
        placeholder={addressOnly ? "Paste Hacash address or hacash:…" : "Paste hacash:… or address"}
        value={pasteInput}
        onChange={(e) => setPasteInput(e.target.value)}
        disabled={disabled}
      />
      <button type="button" disabled={disabled || !pasteInput.trim()} onClick={ingestPaste}>
        Use pasted code
      </button>
    </div>
  );
}
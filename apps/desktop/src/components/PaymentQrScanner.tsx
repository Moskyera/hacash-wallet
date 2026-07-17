import { useCallback, useEffect, useRef, useState } from "react";
import { Html5Qrcode } from "html5-qrcode";
import { parsePaymentQr, type PaymentQrPayload } from "../paymentQr";

type Props = {
  mountId?: string;
  onDetected: (payload: PaymentQrPayload) => void;
  onError: (message: string) => void;
  disabled?: boolean;
};

export default function PaymentQrScanner({
  mountId = "payment-qr-reader",
  onDetected,
  onError,
  disabled = false,
}: Props) {
  const [scanning, setScanning] = useState(false);
  const [pasteInput, setPasteInput] = useState("");
  const scannerRef = useRef<Html5Qrcode | null>(null);
  const handledRef = useRef(false);

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

  function ingest(text: string) {
    if (handledRef.current) return;
    const payload = parsePaymentQr(text);
    if (!payload) {
      onError("Not a Hacash payment QR. expected address or hacash:… URI.");
      return;
    }
    handledRef.current = true;
    void stopScanner().finally(() => onDetected(payload));
  }

  async function toggleScanner() {
    if (disabled) return;
    handledRef.current = false;
    if (scanning) {
      await stopScanner();
      return;
    }
    const scanner = new Html5Qrcode(mountId);
    scannerRef.current = scanner;
    setScanning(true);
    try {
      await scanner.start(
        { facingMode: "environment" },
        { fps: 8, qrbox: { width: 240, height: 240 } },
        (decoded) => ingest(decoded),
        () => undefined,
      );
    } catch (e) {
      setScanning(false);
      scannerRef.current = null;
      onError(`Camera unavailable: ${e}`);
    }
  }

  function handlePaste() {
    handledRef.current = false;
    ingest(pasteInput);
    setPasteInput("");
  }

  return (
    <div className="payment-qr-scanner">
      <div className="actions-row">
        <button type="button" disabled={disabled} onClick={() => void toggleScanner()}>
          {scanning ? "Stop camera" : "Open camera scanner"}
        </button>
      </div>
      <div id={mountId} className={`qr-reader ${scanning ? "active" : ""}`} />
      <label className="muted small-note">Or paste payment URI / address</label>
      <textarea
        value={pasteInput}
        onChange={(e) => setPasteInput(e.target.value)}
        placeholder="hacash:1ABC…?amount=10"
        rows={2}
        disabled={disabled}
      />
      <button type="button" disabled={disabled || !pasteInput.trim()} onClick={handlePaste}>
        Use pasted code
      </button>
    </div>
  );
}
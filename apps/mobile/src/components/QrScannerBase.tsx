import { useCallback, useEffect, useRef, useState } from "react";
import { Html5Qrcode } from "html5-qrcode/esm/index.js";
import { expectSystemDialog } from "../utils/systemDialogGuard";

type Props<T> = {
  mountId: string;
  pastePlaceholder: string;
  pasteButtonLabel: string;
  validate: (decoded: string) => T | null;
  invalidMessage: string;
  onDetected: (result: T) => void;
  onError: (message: string) => void;
  disabled?: boolean;
  qrboxSize?: number;
  primaryCameraButton?: boolean;
};

export default function QrScannerBase<T>({
  mountId,
  pastePlaceholder,
  pasteButtonLabel,
  validate,
  invalidMessage,
  onDetected,
  onError,
  disabled = false,
  qrboxSize = 220,
  primaryCameraButton = false,
}: Props<T>) {
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

  const ingestDecoded = useCallback(
    (decoded: string) => {
      const result = validate(decoded);
      if (!result) {
        onError(invalidMessage);
        return false;
      }
      onDetected(result);
      return true;
    },
    [invalidMessage, onDetected, onError, validate],
  );

  const startScanner = useCallback(async () => {
    if (disabled || scannerRef.current) return;
    // Starting the camera can raise the Android permission dialog, which runs as a
    // separate activity and makes the WebView look backgrounded. Tell the background
    // lock that this one is expected, so it conceals without locking the wallet and
    // dropping the user on the unlock screen mid-scan.
    expectSystemDialog();
    handledRef.current = false;
    const scanner = new Html5Qrcode(mountId);
    scannerRef.current = scanner;
    setScanning(true);
    try {
      await scanner.start(
        { facingMode: "environment" },
        { fps: 10, qrbox: { width: qrboxSize, height: qrboxSize } },
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
  }, [disabled, ingestDecoded, mountId, onError, qrboxSize, stopScanner]);


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
        <button
          type="button"
          className={primaryCameraButton ? "primary" : undefined}
          disabled={disabled}
          onClick={() => void startScanner()}
        >
          Open camera
        </button>
      )}
      {scanning && (
        <button type="button" disabled={disabled} onClick={() => void stopScanner()}>
          Stop camera
        </button>
      )}
      <input
        placeholder={pastePlaceholder}
        value={pasteInput}
        onChange={(e) => setPasteInput(e.target.value)}
        disabled={disabled}
      />
      <button type="button" disabled={disabled || !pasteInput.trim()} onClick={ingestPaste}>
        {pasteButtonLabel}
      </button>
    </div>
  );
}
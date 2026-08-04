import { useCallback, useEffect, useId, useRef, useState } from "react";
import {
  Html5Qrcode,
  Html5QrcodeSupportedFormats,
} from "html5-qrcode/esm/index.js";
import QRCode from "qrcode";

import { MAX_COMPANION_QR_TEXT_CHARS } from "./companionPairing";

const QR_RENDER_SIZE = 1024;
const QR_QUIET_ZONE_MODULES = 4;
const QR_SCAN_FPS = 8;
const REAR_CAMERA_CONSTRAINTS: MediaTrackConstraints = {
  facingMode: "environment",
  width: { ideal: 1920 },
  height: { ideal: 1080 },
};
const MAX_QR_IMAGE_BYTES = 8 * 1024 * 1024;

type DisplayProps = {
  value: string;
  label: string;
  showTransferActions?: boolean;
};

export function CompanionQrDisplay({
  value,
  label,
  showTransferActions = true,
}: DisplayProps) {
  const [dataUrl, setDataUrl] = useState("");
  const [transferStatus, setTransferStatus] = useState("");

  async function copyPayload() {
    try {
      await navigator.clipboard.writeText(value);
      setTransferStatus("Pairing payload copied. Keep it private.");
    } catch {
      setTransferStatus("Copy is unavailable on this device.");
    }
  }

  async function sharePayload() {
    if (typeof navigator.share !== "function") return;
    try {
      await navigator.share({
        title: label,
        text: value,
      });
      setTransferStatus("Pairing payload shared locally.");
    } catch {
      setTransferStatus("Sharing was cancelled.");
    }
  }

  useEffect(() => {
    let cancelled = false;
    QRCode.toDataURL(value, {
      errorCorrectionLevel: "M",
      // Four modules is the QR specification's quiet-zone minimum. The old
      // one-module/240px rendering made signed pairing payloads too dense for
      // physical Android cameras even though ordinary payment QRs still read.
      margin: QR_QUIET_ZONE_MODULES,
      width: QR_RENDER_SIZE,
      color: { dark: "#000000", light: "#ffffff" },
    })
      .then((url) => {
        if (!cancelled) setDataUrl(url);
      })
      .catch(() => {
        if (!cancelled) setDataUrl("");
      });
    return () => {
      cancelled = true;
    };
  }, [value]);

  if (!dataUrl) {
    return <p className="agent-safe-note">QR generation unavailable.</p>;
  }
  return (
    <div className="agent-companion-qr">
      <img src={dataUrl} width={420} height={420} alt={label} />
      <span>{label}</span>
      {showTransferActions ? (
        <>
          <div className="agent-qr-transfer-actions">
            <button type="button" onClick={() => void copyPayload()}>
              Copy pairing payload
            </button>
            {typeof navigator.share === "function" ? (
              <button type="button" onClick={() => void sharePayload()}>
                Share locally
              </button>
            ) : null}
          </div>
          <p className="agent-safe-note">
            Pairing data is temporary. Transfer it only over a trusted local channel.
          </p>
          {transferStatus ? <p role="status">{transferStatus}</p> : null}
        </>
      ) : null}
    </div>
  );
}

type ScannerProps = {
  label: string;
  disabled?: boolean;
  onValue: (value: string) => void;
};

export function CompanionQrScanner({
  label,
  disabled = false,
  onValue,
}: ScannerProps) {
  const rawId = useId();
  const mountId = `companion-qr-${rawId.replace(/[^a-zA-Z0-9_-]/g, "")}`;
  const [scanning, setScanning] = useState(false);
  const [pasted, setPasted] = useState("");
  const [importing, setImporting] = useState(false);
  const [scannerError, setScannerError] = useState("");
  const fileInput = useRef<HTMLInputElement | null>(null);
  const scanner = useRef<Html5Qrcode | null>(null);
  const handled = useRef(false);

  const stop = useCallback(async () => {
    const current = scanner.current;
    scanner.current = null;
    if (!current) return;
    try {
      await current.stop();
    } catch {
      // The camera may already be stopped by the native webview lifecycle.
    } finally {
      try {
        current.clear();
      } catch {
        // Cleanup must not leave the UI stuck in its scanning state.
      }
      setScanning(false);
    }
  }, []);

  useEffect(() => () => void stop(), [stop]);

  const accept = useCallback(
    (value: string) => {
      const normalized = value.trim();
      if (!normalized || handled.current) return;
      if (normalized.length > MAX_COMPANION_QR_TEXT_CHARS) {
        setScannerError("The pairing payload is too large.");
        return;
      }
      setScannerError("");
      void stop().finally(() => onValue(normalized));
      handled.current = true;
    },
    [onValue, stop],
  );

  async function toggle() {
    if (disabled || importing) return;
    if (scanning) {
      await stop();
      return;
    }
    handled.current = false;
    setScannerError("");
    const next = new Html5Qrcode(mountId, {
      formatsToSupport: [Html5QrcodeSupportedFormats.QR_CODE],
      useBarCodeDetectorIfSupported: false,
      verbose: false,
    });
    scanner.current = next;
    setScanning(true);
    try {
      await next.start(
        // html5-qrcode accepts exactly one camera selector here. Resolution
        // constraints belong in the scanner config below.
        { facingMode: "environment" },
        {
          // Dense signed companion payloads need the complete camera frame.
          // A cropped qrbox reduced the effective pixels enough to miss them.
          fps: QR_SCAN_FPS,
          disableFlip: true,
          videoConstraints: REAR_CAMERA_CONSTRAINTS,
        },
        accept,
        () => undefined,
      );
    } catch (reason) {
      scanner.current = null;
      try {
        next.clear();
      } catch {
        // A failed permission/start attempt may not have created a QR canvas.
      }
      setScanning(false);
      const reasonText =
        reason instanceof Error
          ? `${reason.name} ${reason.message}`.toLowerCase()
          : String(reason ?? "").toLowerCase();
      const permissionDenied =
        reasonText.includes("notallowed") ||
        reasonText.includes("permission denied") ||
        reasonText.includes("permission dismissed") ||
        reasonText.includes("securityerror");
      setScannerError(
        permissionDenied
          ? "Camera permission is off. Allow Camera for HPAY in Android Settings, then try again."
          : "The camera could not start. Close any other camera app and try again.",
      );
    }
  }

  async function importQrImage(file: File | undefined) {
    if (!file || disabled || importing) return;
    if (!file.type.startsWith("image/")) {
      setScannerError("Choose an image that contains the pairing QR.");
      return;
    }
    if (file.size > MAX_QR_IMAGE_BYTES) {
      setScannerError("The QR image is too large. Maximum size is 8 MB.");
      return;
    }

    setScannerError("");
    setImporting(true);
    await stop();
    handled.current = false;
    const next = new Html5Qrcode(mountId, {
      formatsToSupport: [Html5QrcodeSupportedFormats.QR_CODE],
      useBarCodeDetectorIfSupported: false,
      verbose: false,
    });
    scanner.current = next;
    try {
      const decoded = await next.scanFile(file, false);
      scanner.current = null;
      next.clear();
      accept(decoded);
    } catch {
      scanner.current = null;
      try {
        next.clear();
      } catch {
        // The file decoder may already have released its temporary canvas.
      }
      setScannerError("No valid HPAY pairing QR was found in that image.");
    } finally {
      setImporting(false);
      if (fileInput.current) {
        fileInput.current.value = "";
      }
    }
  }

  return (
    <div className="agent-companion-scanner">
      <button type="button" disabled={disabled || importing} onClick={() => void toggle()}>
        {scanning ? "Stop camera" : label}
      </button>
      <div
        id={mountId}
        className={scanning ? "qr-reader active" : "qr-reader"}
      />
      <details className="agent-advanced-details">
        <summary>Camera not available?</summary>
        <input
          ref={fileInput}
          className="agent-qr-file-input"
          type="file"
          accept="image/*"
          disabled={disabled || importing}
          onChange={(event) => void importQrImage(event.target.files?.[0])}
        />
        <button
          type="button"
          disabled={disabled || importing}
          onClick={() => fileInput.current?.click()}
        >
          {importing ? "Reading QR image..." : "Choose a QR image"}
        </button>
        <label>
          Paste pairing text
          <textarea
            rows={3}
            value={pasted}
            disabled={disabled || importing}
            spellCheck={false}
            onChange={(event) => setPasted(event.target.value)}
            maxLength={MAX_COMPANION_QR_TEXT_CHARS}
          />
        </label>
        <button
          type="button"
          disabled={disabled || importing || !pasted.trim()}
          onClick={() => {
            handled.current = false;
            accept(pasted);
            setPasted("");
          }}
        >
          Continue with pasted text
        </button>
      </details>
      {scannerError ? (
        <p className="agent-safe-note" role="status">
          {scannerError}
        </p>
      ) : null}
    </div>
  );
}

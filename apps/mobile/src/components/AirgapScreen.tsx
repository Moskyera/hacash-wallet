import { useCallback, useEffect, useRef, useState } from "react";
import QRCode from "qrcode";
import { Html5Qrcode } from "html5-qrcode";
import {
  api,
  type AirgapEnvelope,
  type AirgapParseResult,
  type AirgapPrepareResult,
  type AirgapSignResult,
  type AirgapSigned,
  type AirgapUnsigned,
} from "../api";
import { formatInvokeError } from "../formatInvokeError";

type AirgapMode = "coordinator" | "signer";

type Props = {
  watchOnly: boolean;
  busy: boolean;
  setBusy: (v: boolean) => void;
  onToast: (msg: string, kind: "success" | "info" | "error") => void;
  onBroadcast: () => void;
};

function isUnsigned(env: AirgapEnvelope): env is AirgapUnsigned & { kind: "unsigned" } {
  return env.kind === "unsigned";
}

function isSigned(env: AirgapEnvelope): env is AirgapSigned & { kind: "signed" } {
  return env.kind === "signed";
}

async function qrDataUrls(parts: string[]): Promise<string[]> {
  return Promise.all(
    parts.map((text) =>
      QRCode.toDataURL(text, { errorCorrectionLevel: "M", margin: 1, width: 240 }),
    ),
  );
}

export default function AirgapScreen({ watchOnly, busy, setBusy, onToast, onBroadcast }: Props) {
  const [mode, setMode] = useState<AirgapMode>("coordinator");
  const [sendTo, setSendTo] = useState("");
  const [sendAmount, setSendAmount] = useState("");
  const [prepareResult, setPrepareResult] = useState<AirgapPrepareResult | null>(null);
  const [prepareQrUrls, setPrepareQrUrls] = useState<string[]>([]);

  const [scanParts, setScanParts] = useState<string[]>([]);
  const [parsed, setParsed] = useState<AirgapParseResult | null>(null);
  const [signResult, setSignResult] = useState<AirgapSignResult | null>(null);
  const [signQrUrls, setSignQrUrls] = useState<string[]>([]);
  const [pasteInput, setPasteInput] = useState("");
  const [scanning, setScanning] = useState(false);

  const scannerRef = useRef<Html5Qrcode | null>(null);
  const scanMountId = "airgap-qr-reader";

  const resetScan = useCallback(() => {
    setScanParts([]);
    setParsed(null);
    setSignResult(null);
    setSignQrUrls([]);
    setPasteInput("");
  }, []);

  useEffect(() => {
    if (!prepareResult) {
      setPrepareQrUrls([]);
      return;
    }
    qrDataUrls(prepareResult.qr_parts)
      .then(setPrepareQrUrls)
      .catch((e) => onToast(String(e), "error"));
  }, [prepareResult, onToast]);

  useEffect(() => {
    if (!signResult) {
      setSignQrUrls([]);
      return;
    }
    qrDataUrls(signResult.qr_parts)
      .then(setSignQrUrls)
      .catch((e) => onToast(String(e), "error"));
  }, [signResult, onToast]);

  useEffect(() => {
    return () => {
      if (scannerRef.current) {
        scannerRef.current.stop().catch(() => undefined);
        scannerRef.current.clear();
        scannerRef.current = null;
      }
    };
  }, []);

  async function handlePrepare() {
    setBusy(true);
    setPrepareResult(null);
    resetScan();
    try {
      const result = await api.airgapPrepareSend(sendTo.trim(), Number(sendAmount));
      setPrepareResult(result);
      onToast(
        result.qr_parts.length > 1
          ? `Unsigned tx. scan ${result.qr_parts.length} QR codes offline.`
          : "Unsigned tx ready. scan QR offline.",
        "success",
      );
    } catch (e) {
      onToast(formatInvokeError(e), "error");
    } finally {
      setBusy(false);
    }
  }

  async function ingestQrText(text: string) {
    const trimmed = text.trim();
    if (!trimmed) return;
    const nextParts = scanParts.includes(trimmed) ? scanParts : [...scanParts, trimmed];
    setScanParts(nextParts);
    try {
      const result = await api.airgapParseQrBatch(nextParts);
      setParsed(result);
      if (result.needs_more_parts) {
        onToast(`Chunk ${result.received_parts}/${result.total_parts}. scan next QR.`, "info");
        return;
      }
      if (!result.envelope) {
        onToast("QR decoded but envelope missing.", "error");
        return;
      }
      if (isUnsigned(result.envelope)) {
        onToast("Unsigned tx loaded.", "success");
      } else if (isSigned(result.envelope)) {
        onToast("Signed tx loaded. ready to broadcast.", "success");
      }
    } catch (e) {
      onToast(formatInvokeError(e), "error");
    }
  }

  async function handlePasteQr() {
    await ingestQrText(pasteInput);
    setPasteInput("");
  }

  async function toggleScanner() {
    if (scanning && scannerRef.current) {
      await scannerRef.current.stop();
      scannerRef.current.clear();
      scannerRef.current = null;
      setScanning(false);
      return;
    }
    const scanner = new Html5Qrcode(scanMountId);
    scannerRef.current = scanner;
    setScanning(true);
    try {
      await scanner.start(
        { facingMode: "environment" },
        { fps: 8, qrbox: { width: 220, height: 220 } },
        (decoded) => ingestQrText(decoded),
        () => undefined,
      );
    } catch (e) {
      setScanning(false);
      scannerRef.current = null;
      onToast(`Camera unavailable: ${e}`, "error");
    }
  }

  async function handleSign() {
    if (!parsed?.envelope || !isUnsigned(parsed.envelope)) return;
    setBusy(true);
    try {
      const unsigned: AirgapUnsigned = {
        v: parsed.envelope.v,
        from: parsed.envelope.from,
        to: parsed.envelope.to,
        amount_mei: parsed.envelope.amount_mei,
        amount_wire: parsed.envelope.amount_wire,
        fee: parsed.envelope.fee,
        service_fee_mei: parsed.envelope.service_fee_mei,
        service_fee_treasury: parsed.envelope.service_fee_treasury,
        body_hex: parsed.envelope.body_hex,
        summary: parsed.envelope.summary,
      };
      const result = await api.airgapSignUnsigned(unsigned);
      setSignResult(result);
      onToast("Signed. show QR to coordinator.", "success");
    } catch (e) {
      onToast(formatInvokeError(e), "error");
    } finally {
      setBusy(false);
    }
  }

  async function handleBroadcast() {
    if (!parsed?.envelope || !isSigned(parsed.envelope)) return;
    setBusy(true);
    try {
      const signed: AirgapSigned = {
        v: parsed.envelope.v,
        from: parsed.envelope.from,
        to: parsed.envelope.to,
        amount_mei: parsed.envelope.amount_mei,
        amount_wire: parsed.envelope.amount_wire,
        fee: parsed.envelope.fee,
        service_fee_mei: parsed.envelope.service_fee_mei,
        service_fee_treasury: parsed.envelope.service_fee_treasury,
        signed_hex: parsed.envelope.signed_hex,
        summary: parsed.envelope.summary,
      };
      const result = await api.airgapBroadcastSigned(signed);
      resetScan();
      setPrepareResult(null);
      onBroadcast();
      onToast(`Broadcast: ${result.summary}`, "success");
    } catch (e) {
      onToast(formatInvokeError(e), "error");
    } finally {
      setBusy(false);
    }
  }

  const unsignedLoaded = parsed?.envelope && isUnsigned(parsed.envelope);
  const signedLoaded = parsed?.envelope && isSigned(parsed.envelope);

  return (
    <>
      <div className="card">
        <h2>Air-gapped QR (L1)</h2>
        <p className="muted">
          Coordinator builds unsigned tx → offline signer scans & signs → coordinator broadcasts.
        </p>
        <div className="display-toggle">
          <button
            type="button"
            className={mode === "coordinator" ? "selected" : ""}
            onClick={() => setMode("coordinator")}
          >
            Coordinator
          </button>
          <button
            type="button"
            className={mode === "signer" ? "selected" : ""}
            onClick={() => setMode("signer")}
          >
            Offline signer
          </button>
        </div>
      </div>

      {mode === "coordinator" && (
        <div className="card">
          <h3>Prepare unsigned send</h3>
          <label className="label">To address</label>
          <input value={sendTo} onChange={(e) => setSendTo(e.target.value)} placeholder="1…" />
          <label className="label">Amount (mei)</label>
          <input
            value={sendAmount}
            onChange={(e) => setSendAmount(e.target.value)}
            type="number"
            min="0"
            step="0.001"
          />
          <button
            type="button"
            className="primary"
            disabled={busy || !sendTo || !sendAmount}
            onClick={() => void handlePrepare()}
          >
            Build unsigned QR
          </button>
          {prepareResult && (
            <div className="preview-box">
              <p>{prepareResult.envelope.summary}</p>
              <div className="qr-grid">
                {prepareQrUrls.map((url, i) => (
                  <img key={i} src={url} alt={`Unsigned QR ${i + 1}`} className="qr-thumb" />
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      <div className="card">
        <h3>{mode === "coordinator" ? "Scan signed QR & broadcast" : "Scan unsigned QR"}</h3>
        <p className="muted">
          {mode === "signer" && watchOnly
            ? "Watch-only cannot sign. use an offline signing wallet."
            : mode === "signer"
              ? "Keep device offline while signing."
              : "Scan the signed QR from the offline device."}
        </p>
        <div className="row-btns">
          <button type="button" disabled={busy} onClick={() => void toggleScanner()}>
            {scanning ? "Stop camera" : "Scan QR"}
          </button>
          <button type="button" disabled={busy || scanParts.length === 0} onClick={resetScan}>
            Clear
          </button>
        </div>
        <div id={scanMountId} className={scanning ? "qr-reader active" : "qr-reader"} />
        <label className="label">Or paste payload</label>
        <textarea
          value={pasteInput}
          onChange={(e) => setPasteInput(e.target.value)}
          rows={3}
          placeholder="Paste air-gap QR payload"
        />
        <button type="button" disabled={busy || !pasteInput.trim()} onClick={() => void handlePasteQr()}>
          Add pasted QR
        </button>

        {parsed?.needs_more_parts && (
          <p className="warn-text">
            Partial QR: {parsed.received_parts}/{parsed.total_parts} parts.
          </p>
        )}

        {unsignedLoaded && parsed.envelope && isUnsigned(parsed.envelope) && (
          <div className="preview-box">
            <p>{parsed.envelope.summary}</p>
            {mode === "signer" && !watchOnly && (
              <button type="button" className="primary" disabled={busy} onClick={() => void handleSign()}>
                Sign offline
              </button>
            )}
          </div>
        )}

        {signResult && (
          <div className="preview-box">
            <p>Signed. show to coordinator</p>
            <div className="qr-grid">
              {signQrUrls.map((url, i) => (
                <img key={i} src={url} alt={`Signed QR ${i + 1}`} className="qr-thumb" />
              ))}
            </div>
          </div>
        )}

        {signedLoaded && parsed.envelope && isSigned(parsed.envelope) && mode === "coordinator" && (
          <div className="preview-box">
            <p>{parsed.envelope.summary}</p>
            <button type="button" className="primary" disabled={busy} onClick={() => void handleBroadcast()}>
              Broadcast to network
            </button>
          </div>
        )}
      </div>
    </>
  );
}

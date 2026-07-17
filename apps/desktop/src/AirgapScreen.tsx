import { useCallback, useEffect, useRef, useState } from "react";
import QRCode from "qrcode";
import { Html5Qrcode } from "html5-qrcode";
import {
  AirgapEnvelope,
  AirgapParseResult,
  AirgapPrepareResult,
  AirgapSignResult,
  AirgapSigned,
  AirgapUnsigned,
  WalletStatus,
  api,
} from "./api";

type AirgapMode = "coordinator" | "signer";

type Props = {
  status: WalletStatus;
  busy: boolean;
  setBusy: (v: boolean) => void;
  clearMessages: () => void;
  setError: (v: string) => void;
  setInfo: (v: string) => void;
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
      QRCode.toDataURL(text, { errorCorrectionLevel: "M", margin: 1, width: 280 }),
    ),
  );
}

export default function AirgapScreen({
  status,
  busy,
  setBusy,
  clearMessages,
  setError,
  setInfo,
  onBroadcast,
}: Props) {
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
      .catch((e) => setError(String(e)));
  }, [prepareResult, setError]);

  useEffect(() => {
    if (!signResult) {
      setSignQrUrls([]);
      return;
    }
    qrDataUrls(signResult.qr_parts)
      .then(setSignQrUrls)
      .catch((e) => setError(String(e)));
  }, [signResult, setError]);

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
    clearMessages();
    setPrepareResult(null);
    resetScan();
    try {
      const result = await api.airgapPrepareSend(sendTo.trim(), Number(sendAmount));
      setPrepareResult(result);
      setInfo(
        result.qr_parts.length > 1
          ? `Unsigned tx ready. scan ${result.qr_parts.length} QR codes on offline device.`
          : "Unsigned tx ready. scan QR on offline device.",
      );
    } catch (e) {
      setError(String(e));
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
        setInfo(`Chunk ${result.received_parts}/${result.total_parts} captured. scan next QR.`);
        return;
      }
      if (!result.envelope) {
        setError("QR decoded but envelope missing.");
        return;
      }
      if (isUnsigned(result.envelope)) {
        setInfo("Unsigned tx loaded. review and sign on offline device.");
      } else if (isSigned(result.envelope)) {
        setInfo("Signed tx loaded. ready to broadcast.");
      }
    } catch (e) {
      setError(String(e));
    }
  }

  async function handlePasteQr() {
    clearMessages();
    await ingestQrText(pasteInput);
    setPasteInput("");
  }

  async function toggleScanner() {
    clearMessages();
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
        { fps: 8, qrbox: { width: 240, height: 240 } },
        (decoded) => ingestQrText(decoded),
        () => undefined,
      );
    } catch (e) {
      setScanning(false);
      scannerRef.current = null;
      setError(`Camera unavailable: ${e}`);
    }
  }

  async function handleSign() {
    if (!parsed?.envelope || !isUnsigned(parsed.envelope)) return;
    setBusy(true);
    clearMessages();
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
      setInfo("Signed. show QR(s) to online coordinator for broadcast.");
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }

  async function handleBroadcast() {
    if (!parsed?.envelope || !isSigned(parsed.envelope)) return;
    setBusy(true);
    clearMessages();
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
      setInfo(`Broadcast via L1: ${result.summary} (${result.tx_hash})`);
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }

  const unsignedLoaded = parsed?.envelope && isUnsigned(parsed.envelope);
  const signedLoaded = parsed?.envelope && isSigned(parsed.envelope);

  return (
    <section className="panel panel-wide">
      <h2>Air-gapped QR (L1)</h2>
      <p className="muted">
        Coordinator builds unsigned tx → offline signer scans & signs → coordinator broadcasts.
        L2 fast pay is not supported over air-gap.
      </p>

      <div className="tab-row">
        <button
          type="button"
          className={mode === "coordinator" ? "tab active" : "tab"}
          onClick={() => {
            setMode("coordinator");
            clearMessages();
          }}
        >
          Coordinator (online)
        </button>
        <button
          type="button"
          className={mode === "signer" ? "tab active" : "tab"}
          onClick={() => {
            setMode("signer");
            clearMessages();
          }}
        >
          Offline signer
        </button>
      </div>

      {mode === "coordinator" && (
        <>
          <h3>Prepare unsigned send</h3>
          <label>To address</label>
          <input value={sendTo} onChange={(e) => setSendTo(e.target.value)} placeholder="1ABC..." />
          <label>Amount (mei)</label>
          <input
            value={sendAmount}
            onChange={(e) => setSendAmount(e.target.value)}
            type="number"
            min="0"
            step="0.001"
          />
          <button disabled={busy || !sendTo || !sendAmount} onClick={handlePrepare}>
            Build unsigned QR
          </button>

          {prepareResult && (
            <div className="preview-card">
              <h4>{prepareResult.envelope.summary}</h4>
              <ul>
                <li>
                  <strong>From:</strong> <code>{prepareResult.envelope.from}</code>
                </li>
                <li>
                  <strong>To:</strong> <code>{prepareResult.envelope.to}</code>
                </li>
                <li>
                  <strong>Amount:</strong> {prepareResult.envelope.amount_mei} mei
                </li>
              </ul>
              <div className="qr-grid">
                {prepareQrUrls.map((url, i) => (
                  <div key={i} className="qr-card">
                    {prepareQrUrls.length > 1 && (
                      <span className="muted">
                        Part {i + 1}/{prepareQrUrls.length}
                      </span>
                    )}
                    <img src={url} alt={`Unsigned QR part ${i + 1}`} />
                  </div>
                ))}
              </div>
            </div>
          )}

          <hr className="divider" />

          <h3>Scan signed QR & broadcast</h3>
          <p className="muted">
            {status.watch_only
              ? "Watch-only mode: broadcast signed txs from your cold signer."
              : "Scan the signed QR returned from the offline device."}
          </p>
        </>
      )}

      {mode === "signer" && (
        <>
          <h3>Scan unsigned QR</h3>
          <p className="muted">
            {status.watch_only
              ? "Unlock a signing wallet on an offline machine. watch-only cannot sign."
              : "Device should stay offline. Only L1 body is signed locally."}
          </p>
        </>
      )}

      <div className="actions-row">
        <button disabled={busy} onClick={toggleScanner}>
          {scanning ? "Stop camera" : "Scan with camera"}
        </button>
        <button disabled={busy || scanParts.length === 0} onClick={resetScan}>
          Clear scans
        </button>
      </div>

      <div id={scanMountId} className={`qr-reader ${scanning ? "active" : ""}`} />

      <label>Or paste QR payload</label>
      <textarea
        className="textarea mono"
        value={pasteInput}
        onChange={(e) => setPasteInput(e.target.value)}
        rows={3}
        placeholder="Paste JSON or hacash-airgap:1/2:..."
      />
      <button disabled={busy || !pasteInput.trim()} onClick={handlePasteQr}>
        Add pasted QR
      </button>

      {parsed?.needs_more_parts && (
        <div className="warn-box">
          Partial QR: {parsed.received_parts}/{parsed.total_parts} parts collected.
        </div>
      )}

      {unsignedLoaded && parsed.envelope && isUnsigned(parsed.envelope) && (
        <div className="preview-card">
          <h4>Unsigned transaction</h4>
          <p>{parsed.envelope.summary}</p>
          <ul>
            <li>
              <strong>From:</strong> <code>{parsed.envelope.from}</code>
            </li>
            <li>
              <strong>To:</strong> <code>{parsed.envelope.to}</code>
            </li>
            <li>
              <strong>Amount:</strong> {parsed.envelope.amount_mei} mei
            </li>
          </ul>
          {mode === "signer" && !status.watch_only && (
            <button className="primary" disabled={busy} onClick={handleSign}>
              Sign offline
            </button>
          )}
        </div>
      )}

      {signResult && (
        <div className="preview-card">
          <h4>Signed. show to coordinator</h4>
          <div className="qr-grid">
            {signQrUrls.map((url, i) => (
              <div key={i} className="qr-card">
                {signQrUrls.length > 1 && (
                  <span className="muted">
                    Part {i + 1}/{signQrUrls.length}
                  </span>
                )}
                <img src={url} alt={`Signed QR part ${i + 1}`} />
              </div>
            ))}
          </div>
        </div>
      )}

      {signedLoaded && parsed.envelope && isSigned(parsed.envelope) && mode === "coordinator" && (
        <div className="preview-card">
          <h4>Signed transaction ready</h4>
          <p>{parsed.envelope.summary}</p>
          <button className="primary" disabled={busy} onClick={handleBroadcast}>
            Broadcast to network
          </button>
        </div>
      )}
    </section>
  );
}

import { useCallback, useEffect, useRef, useState } from "react";
import { AirgapInspectionCard, useLocale } from "@hacash/wallet-ui";
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
  const { t } = useLocale();
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
  const scanPartsRef = useRef<string[]>([]);
  const scanGeneration = useRef(0);
  const scanMountId = "airgap-qr-reader";

  const resetScan = useCallback(() => {
    scanGeneration.current += 1;
    scanPartsRef.current = [];
    setScanParts([]);
    setParsed(null);
    setSignResult(null);
    setSignQrUrls([]);
    setPasteInput("");
  }, []);

  useEffect(() => {
    let active = true;
    if (!prepareResult) {
      setPrepareQrUrls([]);
      return () => {
        active = false;
      };
    }
    void qrDataUrls(prepareResult.qr_parts)
      .then((urls) => {
        if (active) setPrepareQrUrls(urls);
      })
      .catch((error) => {
        if (active) setError(String(error));
      });
    return () => {
      active = false;
    };
  }, [prepareResult, setError]);

  useEffect(() => {
    let active = true;
    if (!signResult) {
      setSignQrUrls([]);
      return () => {
        active = false;
      };
    }
    void qrDataUrls(signResult.qr_parts)
      .then((urls) => {
        if (active) setSignQrUrls(urls);
      })
      .catch((error) => {
        if (active) setError(String(error));
      });
    return () => {
      active = false;
    };
  }, [signResult, setError]);

  useEffect(() => {
    return () => {
      scanGeneration.current += 1;
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
    setPrepareQrUrls([]);
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
    const currentParts = scanPartsRef.current;
    if (currentParts.includes(trimmed)) return;
    const nextParts = [...currentParts, trimmed];
    scanPartsRef.current = nextParts;
    setScanParts(nextParts);
    const generation = ++scanGeneration.current;
    try {
      const result = await api.airgapParseQrBatch(nextParts);
      if (generation !== scanGeneration.current) return;
      if (result.needs_more_parts) {
        setParsed(result);
        setInfo(`Chunk ${result.received_parts}/${result.total_parts} captured. scan next QR.`);
        return;
      }
      if (!result.envelope) {
        setError("QR decoded but envelope missing.");
        return;
      }
      if (!result.inspection) {
        setError(t("airgap.inspection.missing"));
        return;
      }
      setParsed(result);
      if (isUnsigned(result.envelope)) {
        setInfo("Unsigned tx loaded. review and sign on offline device.");
      } else if (isSigned(result.envelope)) {
        setInfo("Signed tx loaded. ready to broadcast.");
      }
    } catch (e) {
      if (generation === scanGeneration.current) setError(String(e));
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
    if (
      !parsed?.envelope ||
      !isUnsigned(parsed.envelope) ||
      parsed.inspection?.kind !== "unsigned" ||
      parsed.inspection.tx_type !== 2
    ) return;
    setBusy(true);
    clearMessages();
    setSignResult(null);
    setSignQrUrls([]);
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
        tx_type: parsed.envelope.tx_type,
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
    if (
      !parsed?.envelope ||
      !isSigned(parsed.envelope) ||
      parsed.inspection?.kind !== "signed"
    ) return;
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
        tx_type: parsed.envelope.tx_type,
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

  const unsignedLoaded =
    parsed?.envelope && isUnsigned(parsed.envelope) && parsed.inspection?.kind === "unsigned";
  const signedLoaded =
    parsed?.envelope && isSigned(parsed.envelope) && parsed.inspection?.kind === "signed";

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
              <AirgapInspectionCard
                inspection={prepareResult.inspection}
                title={t("airgap.inspection.encodedUnsignedTitle")}
              />
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

      {unsignedLoaded && parsed.inspection && (
        <div className="preview-card">
          <AirgapInspectionCard inspection={parsed.inspection} title={t("airgap.inspection.unsignedTitle")} />
          {parsed.inspection.tx_type !== 2 && (
            <p className="warn-box">{t("airgap.inspection.type4QuantumOnly")}</p>
          )}
          {mode === "signer" && !status.watch_only && (
            <button
              className="primary"
              disabled={
                busy || parsed.inspection.kind !== "unsigned" || parsed.inspection.tx_type !== 2
              }
              onClick={handleSign}
            >
              Sign offline
            </button>
          )}
        </div>
      )}

      {signResult && (
        <div className="preview-card">
          <AirgapInspectionCard
            inspection={signResult.inspection}
            title={t("airgap.inspection.signedTitle")}
          />
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

      {signedLoaded && parsed.inspection && mode === "coordinator" && (
        <div className="preview-card">
          <h4>{t("airgap.inspection.signedReadyTitle")}</h4>
          <AirgapInspectionCard inspection={parsed.inspection} />
          <button
            className="primary"
            disabled={busy || parsed.inspection.kind !== "signed"}
            onClick={handleBroadcast}
          >
            Broadcast to network
          </button>
        </div>
      )}
    </section>
  );
}

import { QuantumFundingCard, type4Balance, useType4Probe } from "@hacash/wallet-ui";
import { useCallback, useEffect, useState } from "react";
import QRCode from "qrcode";
import {
  api,
  quantumApi,
  type AirgapUnsigned,
  type PlatformSecurityStatus,
  type QuantumAccountSummary,
  type QuantumPreflight,
  type QuantumSettings,
} from "../api";
import { formatInvokeError } from "../formatInvokeError";
import { copyWithPrivacyClear } from "../privacy";
import {
  accountSummaryFromSettings,
  canSendType4,
  kindLabel,
  MIN_KEYSTORE_PASS,
  REPLACE_KEYSTORE_WARNING,
  summaryFromAccountInfo,
} from "../quantumMeta";
import { maybeSecondFactorGate } from "../utils/secondFactorGate";
import AddressBadge from "./AddressBadge";
import KeystoreV3Modal from "./KeystoreV3Modal";

const DEFAULT_TO = "1MzNY1oA3kfgYi75zquj3SRUPYztzXHzK9";

type Props = {
  legacyAddress?: string | null;
  nodeUrl?: string;
  clipboardClearSecs: number;
  platformSec: PlatformSecurityStatus | null;
  securityProfile?: string | null;
  biometricSendEnabled?: boolean;
  onToast: (msg: string, kind: "success" | "info" | "error") => void;
  onGoLegacySend?: () => void;
};

export default function QuantumScreen({
  legacyAddress,
  nodeUrl,
  clipboardClearSecs,
  platformSec,
  securityProfile,
  biometricSendEnabled = true,
  onToast,
  onGoLegacySend,
}: Props) {
  const [settings, setSettings] = useState<QuantumSettings | null>(null);
  const [account, setAccount] = useState<QuantumAccountSummary | null>(null);
  const [ksPass, setKsPass] = useState("");
  const [legacyPrikey, setLegacyPrikey] = useState("");
  const [busy, setBusy] = useState(false);
  const [showKs, setShowKs] = useState(false);

  const [sendTo, setSendTo] = useState(DEFAULT_TO);
  const [sendAmount, setSendAmount] = useState("0.1");
  const [sendPass, setSendPass] = useState("");
  const [preflight, setPreflight] = useState<QuantumPreflight | null>(null);
  const [sendHash, setSendHash] = useState("");
  const [nodeMetrics, setNodeMetrics] = useState<Record<string, unknown> | null>(null);
  const [nodeErr, setNodeErr] = useState("");
  const [airgapQr, setAirgapQr] = useState<string[]>([]);
  const [airgapQrUrls, setAirgapQrUrls] = useState<string[]>([]);
  const [signedAirgapQr, setSignedAirgapQr] = useState<string[]>([]);
  const [signedAirgapUrls, setSignedAirgapUrls] = useState<string[]>([]);
  const [showAirgap, setShowAirgap] = useState(false);

  const type4Ready = canSendType4(account);
  const { probe: balanceProbe, refresh: refreshBalance } = useType4Probe(
    account?.address,
    quantumApi.balanceProbe,
    formatInvokeError,
  );

  const qBalance = type4Balance(balanceProbe);
  const refreshSettings = useCallback(async () => {
    const s = await quantumApi.getSettings();
    setSettings(s);
    setAccount(accountSummaryFromSettings(s));
  }, []);

  const refreshNode = useCallback(async () => {
    setNodeErr("");
    try {
      setNodeMetrics(await quantumApi.nodePing());
    } catch (e) {
      setNodeMetrics(null);
      setNodeErr(formatInvokeError(e));
    }
  }, []);

  const runPreflight = useCallback(async () => {
    if (!account || !type4Ready) {
      setPreflight(null);
      return;
    }
    try {
      setPreflight(await quantumApi.preflightType4(sendTo.trim(), sendAmount.trim()));
    } catch (e) {
      setPreflight({
        ok: false,
        warnings: [],
        errors: [formatInvokeError(e)],
        balance_mei: qBalance ?? 0,
        fee_wire: "0:004",
        fee_mei: 0.004,
        service_fee_mei: 0,
        service_fee_treasury: "",
        total_mei: 0,
      });
    }
  }, [account, type4Ready, sendTo, sendAmount, qBalance]);

  useEffect(() => {
    void refreshSettings().catch((e) => onToast(formatInvokeError(e), "error"));
  }, [refreshSettings, onToast]);

  useEffect(() => {
    void refreshNode();
  }, [refreshNode]);

  useEffect(() => {
    const t = window.setTimeout(() => void runPreflight(), 400);
    return () => window.clearTimeout(t);
  }, [runPreflight]);

  async function toggleMode(on: boolean) {
    setBusy(true);
    try {
      await quantumApi.setMode(on);
      await refreshSettings();
      onToast(on ? "Quantum mode enabled." : "Quantum mode disabled.", "info");
    } catch (e) {
      onToast(formatInvokeError(e), "error");
    } finally {
      setBusy(false);
    }
  }

  function confirmReplace(): boolean {
    if (!account) return true;
    return window.confirm(`${REPLACE_KEYSTORE_WARNING}\n\nContinue?`);
  }

  async function createPqc() {
    if (ksPass.length < MIN_KEYSTORE_PASS) {
      onToast(`Password needs at least ${MIN_KEYSTORE_PASS} characters.`, "error");
      return;
    }
    if (!confirmReplace()) return;
    setBusy(true);
    try {
      const acc = summaryFromAccountInfo(await quantumApi.createPqc(ksPass));
      setAccount(acc);
      await refreshSettings();
      onToast(`PQC account created.`, "success");
    } catch (e) {
      onToast(formatInvokeError(e), "error");
    } finally {
      setBusy(false);
    }
  }

  async function createHybrid() {
    if (ksPass.length < MIN_KEYSTORE_PASS) {
      onToast(`Password needs at least ${MIN_KEYSTORE_PASS} characters.`, "error");
      return;
    }
    if (!confirmReplace()) return;
    setBusy(true);
    try {
      const acc = summaryFromAccountInfo(
        await quantumApi.createHybrid(ksPass, legacyPrikey || undefined),
      );
      setAccount(acc);
      await refreshSettings();
      onToast(`Hybrid account created.`, "success");
    } catch (e) {
      onToast(formatInvokeError(e), "error");
    } finally {
      setBusy(false);
    }
  }

  useEffect(() => {
    if (!airgapQr.length) {
      setAirgapQrUrls([]);
      return;
    }
    Promise.all(
      airgapQr.map((text) =>
        QRCode.toDataURL(text, { errorCorrectionLevel: "M", margin: 1, width: 220 }),
      ),
    )
      .then(setAirgapQrUrls)
      .catch(() => setAirgapQrUrls([]));
  }, [airgapQr]);

  useEffect(() => {
    if (!signedAirgapQr.length) {
      setSignedAirgapUrls([]);
      return;
    }
    Promise.all(
      signedAirgapQr.map((text) =>
        QRCode.toDataURL(text, { errorCorrectionLevel: "M", margin: 1, width: 220 }),
      ),
    )
      .then(setSignedAirgapUrls)
      .catch(() => setSignedAirgapUrls([]));
  }, [signedAirgapQr]);

  async function maybeSecondFactor(amount: number) {
    await maybeSecondFactorGate({
      amountMei: amount,
      securityProfile,
      biometricSendEnabled,
      nativeBiometricAvailable: platformSec?.native_biometric_available,
    });
  }

  async function prepareAirgapType4() {
    if (!type4Ready) {
      onToast("Create or import a PQC/Hybrid account first.", "error");
      return;
    }
    setBusy(true);
    try {
      const prep = await quantumApi.prepareAirgapType4(sendTo.trim(), sendAmount.trim());
      setAirgapQr(prep.qr_parts);
      setSignedAirgapQr([]);
      setShowAirgap(true);
      onToast("Unsigned Type 4 QR ready. scan on offline device.", "success");
    } catch (e) {
      onToast(formatInvokeError(e), "error");
    } finally {
      setBusy(false);
    }
  }

  async function signAirgapType4() {
    if (!airgapQr.length || !sendPass.trim()) {
      onToast("Prepare air-gap QR and enter keystore password.", "error");
      return;
    }
    setBusy(true);
    try {
      const parsed = await api.airgapParseQrBatch(airgapQr);
      const env = parsed.envelope;
      if (!env || env.kind !== "unsigned") {
        throw new Error("Expected unsigned Type 4 envelope");
      }
      const amt = Number(sendAmount);
      await maybeSecondFactor(amt);
      const unsigned: AirgapUnsigned = {
        v: env.v,
        from: env.from,
        to: env.to,
        amount_mei: env.amount_mei,
        amount_wire: env.amount_wire,
        fee: env.fee,
        service_fee_mei: env.service_fee_mei,
        service_fee_treasury: env.service_fee_treasury,
        body_hex: env.body_hex,
        summary: env.summary,
        tx_type: env.tx_type ?? 4,
      };
      const signed = await quantumApi.airgapSignType4(unsigned, sendPass);
      setSignedAirgapQr(signed.qr_parts);
      onToast("Signed Type 4 QR ready. broadcast from online device.", "success");
    } catch (e) {
      onToast(formatInvokeError(e), "error");
    } finally {
      setBusy(false);
    }
  }

  async function broadcastAirgapType4() {
    if (!signedAirgapQr.length) return;
    setBusy(true);
    try {
      const parsed = await api.airgapParseQrBatch(signedAirgapQr);
      const env = parsed.envelope;
      if (!env || env.kind !== "signed") {
        throw new Error("Expected signed Type 4 envelope");
      }
      const result = await api.airgapBroadcastSigned({
        v: env.v,
        from: env.from,
        to: env.to,
        amount_mei: env.amount_mei,
        amount_wire: env.amount_wire,
        fee: env.fee,
        service_fee_mei: env.service_fee_mei,
        service_fee_treasury: env.service_fee_treasury,
        signed_hex: env.signed_hex,
        summary: env.summary,
        tx_type: env.tx_type ?? 4,
      });
      setSendHash(result.tx_hash);
      setAirgapQr([]);
      setSignedAirgapQr([]);
      setShowAirgap(false);
      onToast("Type 4 air-gap broadcast complete.", "success");
      await refreshBalance();
      void runPreflight();
    } catch (e) {
      onToast(formatInvokeError(e), "error");
    } finally {
      setBusy(false);
    }
  }

  async function sendType4() {
    if (!type4Ready) {
      onToast("Create or import a PQC/Hybrid account first.", "error");
      return;
    }
    if (!sendPass.trim()) {
      onToast("Enter keystore password.", "error");
      return;
    }
    if (!preflight?.ok) {
      onToast(preflight?.errors.join("; ") || "Preflight failed.", "error");
      return;
    }
    const amt = Number(sendAmount);
    if (!Number.isFinite(amt) || amt <= 0) {
      onToast("Enter a valid amount.", "error");
      return;
    }
    setBusy(true);
    setSendHash("");
    try {
      await maybeSecondFactor(amt);
      const res = await quantumApi.sendType4(sendTo.trim(), sendAmount.trim(), sendPass);
      setSendHash(res.hash);
      onToast("Quantum transaction sent.", "success");
      await refreshBalance();
      void runPreflight();
    } catch (e) {
      onToast(formatInvokeError(e), "error");
    } finally {
      setBusy(false);
    }
  }

  async function copyQuantumAddress() {
    if (!account) return;
    await copyWithPrivacyClear(account.address, clipboardClearSecs);
    onToast("Quantum address copied.", "success");
  }

  if (!settings) {
    return (
      <div className="card">
        <p className="muted">Loading quantum settings…</p>
      </div>
    );
  }

  return (
    <>
      <div className="card quantum-panel">
        <div className="toggle-row">
          <div>
            <strong>Quantum Mode</strong>
            <p className="muted">ML-DSA-65 · v6 PQC / v7 Hybrid</p>
          </div>
          <label className="quantum-switch">
            <input
              type="checkbox"
              checked={settings.quantum_mode}
              disabled={busy}
              onChange={(e) => void toggleMode(e.target.checked)}
            />
            <span />
          </label>
        </div>
        <p className="muted small">
          Experimental Type 4 support. PQC and hybrid signing are implemented, but this wallet has
          not completed an independent cryptographic audit.
        </p>

        {settings.quantum_mode && (
          <>
            {account && (
              <div className="quantum-active">
                <AddressBadge address={account.address} version={account.address_version} kind={account.kind} />
                <code>{account.address}</code>
                <span className="muted">{kindLabel(account.kind)}</span>
                <button type="button" className="small" onClick={() => void copyQuantumAddress()}>
                  Copy
                </button>
              </div>
            )}

            <label className="label">Keystore password (≥{MIN_KEYSTORE_PASS} chars)</label>
            <input type="password" value={ksPass} onChange={(e) => setKsPass(e.target.value)} />
            <label className="label">Legacy prikey (optional, 64-hex for hybrid)</label>
            <input value={legacyPrikey} onChange={(e) => setLegacyPrikey(e.target.value)} placeholder="optional" />

            <div className="row-btns">
              <button type="button" className="btn-pqc" disabled={busy} onClick={() => void createPqc()}>
                Create PQC
              </button>
              <button type="button" className="btn-hybrid" disabled={busy} onClick={() => void createHybrid()}>
                Create Hybrid
              </button>
            </div>
            <button type="button" disabled={busy} onClick={() => setShowKs(true)}>
              Keystore v3 import/export
            </button>
          </>
        )}
      </div>

      {settings.quantum_mode && account && (
        <QuantumFundingCard
          account={{
            address: account.address,
            addressVersion: account.address_version,
            kind: account.kind,
          }}
          probe={balanceProbe}
          legacyAddress={legacyAddress}
          accountBadge={
            <AddressBadge
              address={account.address}
              version={account.address_version}
              kind={account.kind}
            />
          }
          onCopyAddress={(address) => copyWithPrivacyClear(address, clipboardClearSecs)}
          onOpenLegacyFund={onGoLegacySend}
        />
      )}

      {settings.quantum_mode && (
        <div className="card">
          <h2>Send Type 4</h2>
          <p className="muted">Node: {nodeUrl ?? "default"}</p>

          <label className="label">To address</label>
          <input value={sendTo} onChange={(e) => setSendTo(e.target.value)} />

          <label className="label">Amount (HAC)</label>
          <input value={sendAmount} onChange={(e) => setSendAmount(e.target.value)} />

          <label className="label">Keystore password</label>
          <input type="password" value={sendPass} onChange={(e) => setSendPass(e.target.value)} />

          {preflight && (
            <div className={`preview-box ${preflight.ok ? "" : "preflight-bad"}`}>
              {preflight.errors.map((e) => (
                <p key={e} className="error">
                  {e}
                </p>
              ))}
              {preflight.ok && (
                <p className="muted">
                  Preflight OK · balance {preflight.balance_mei.toFixed(3)} HAC · fee ~
                  {preflight.fee_mei.toFixed(4)} · wallet fee {preflight.service_fee_mei.toFixed(6)} · total ~
                  {preflight.total_mei.toFixed(4)} HAC
                </p>
              )}
            </div>
          )}

          <div className="row-btns">
            <button
              type="button"
              className="primary"
              disabled={busy || !type4Ready || !sendPass || !preflight?.ok}
              onClick={() => void sendType4()}
            >
              Sign & Send
            </button>
          </div>

          {sendHash && (
            <div className="quantum-success">
              <p>Transaction accepted</p>
              <code>{sendHash}</code>
            </div>
          )}

          <div className="row-btns">
            <button type="button" disabled={busy || !type4Ready} onClick={() => void prepareAirgapType4()}>
              Air-gap QR (unsigned)
            </button>
            {showAirgap && airgapQr.length > 0 && (
              <button type="button" disabled={busy || !sendPass} onClick={() => void signAirgapType4()}>
                Sign offline
              </button>
            )}
            {signedAirgapQr.length > 0 && (
              <button type="button" disabled={busy} onClick={() => void broadcastAirgapType4()}>
                Broadcast signed
              </button>
            )}
          </div>

          {showAirgap && airgapQrUrls.length > 0 && (
            <div className="preview-box">
              <p className="muted">Unsigned Type 4. scan on offline signer</p>
              <div className="qr-grid">
                {airgapQrUrls.map((url, i) => (
                  <img key={i} src={url} alt={`Type4 unsigned ${i + 1}`} className="qr-thumb" />
                ))}
              </div>
            </div>
          )}

          {signedAirgapUrls.length > 0 && (
            <div className="preview-box">
              <p className="muted">Signed Type 4. scan on online coordinator</p>
              <div className="qr-grid">
                {signedAirgapUrls.map((url, i) => (
                  <img key={i} src={url} alt={`Type4 signed ${i + 1}`} className="qr-thumb" />
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {settings.quantum_mode && (
        <div className="card">
          <div className="toggle-row">
            <strong>Node health</strong>
            <button type="button" className="small" disabled={busy} onClick={() => void refreshNode()}>
              Refresh
            </button>
          </div>
          {nodeUrl && (
            <p className="muted small">
              Node: <code>{nodeUrl}</code>
            </p>
          )}
          <p className={`quantum-node-status ${nodeMetrics && !nodeErr ? "ok" : "bad"}`}>
            {nodeMetrics && !nodeErr
              ? (() => {
                  const latest = nodeMetrics.latest as { height?: number } | undefined;
                  const h = latest?.height;
                  return h != null ? `Node reachable · height ${h}` : "Node reachable";
                })()
              : "Node unreachable"}
          </p>
          {nodeMetrics && (
            <pre className="quantum-metrics">{JSON.stringify(nodeMetrics, null, 2)}</pre>
          )}
          {nodeErr && <p className="error">{nodeErr}</p>}
        </div>
      )}

      {showKs && (
        <KeystoreV3Modal
          initialPassword={ksPass}
          hasAccount={!!account}
          onClose={() => setShowKs(false)}
          onImported={async (acc) => {
            setAccount(acc);
            await refreshSettings();
            setShowKs(false);
            onToast(`Keystore imported: ${acc.address}`, "success");
          }}
        />
      )}
    </>
  );
}

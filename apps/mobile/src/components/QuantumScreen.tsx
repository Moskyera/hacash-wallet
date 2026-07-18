import {
  canUseQuantumLabTransactions,
  QuantumFundingCard,
  type4Balance,
  useType4Probe,
} from "@hacash/wallet-ui";
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
import { useLocale } from "../locale";
import { copyWithPrivacyClear } from "../privacy";
import {
  accountSummaryFromSettings,
  canSendType4,
  MIN_KEYSTORE_PASS,
  summaryFromAccountInfo,
} from "../quantumMeta";
import { maybeSecondFactorGate } from "../utils/secondFactorGate";
import AddressBadge from "./AddressBadge";
import KeystoreV3Modal from "./KeystoreV3Modal";

const DEFAULT_TO = "1MzNY1oA3kfgYi75zquj3SRUPYztzXHzK9";

type Props = {
  legacyAddress?: string | null;
  nodeUrl?: string;
  networkMode: "mainnet" | "testnet";
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
  networkMode,
  clipboardClearSecs,
  platformSec,
  securityProfile,
  biometricSendEnabled = true,
  onToast,
  onGoLegacySend,
}: Props) {
  const { t } = useLocale();
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
  const mainnetBlocked = !canUseQuantumLabTransactions(networkMode);
  const { probe: balanceProbe, refresh: refreshBalance } = useType4Probe(
    mainnetBlocked ? null : account?.address,
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
    if (!account || !type4Ready || mainnetBlocked) {
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
  }, [account, type4Ready, mainnetBlocked, sendTo, sendAmount, qBalance]);

  useEffect(() => {
    void refreshSettings().catch((e) => onToast(formatInvokeError(e), "error"));
  }, [refreshSettings, onToast]);

  useEffect(() => {
    if (mainnetBlocked) {
      setNodeMetrics(null);
      setNodeErr("");
      return;
    }
    void refreshNode();
  }, [mainnetBlocked, refreshNode]);

  useEffect(() => {
    const t = window.setTimeout(() => void runPreflight(), 400);
    return () => window.clearTimeout(t);
  }, [runPreflight]);

  async function toggleMode(on: boolean) {
    setBusy(true);
    try {
      await quantumApi.setMode(on);
      await refreshSettings();
      onToast(t(on ? "quantum.modeEnabled" : "quantum.modeDisabled"), "info");
    } catch (e) {
      onToast(formatInvokeError(e), "error");
    } finally {
      setBusy(false);
    }
  }

  function confirmReplace(): boolean {
    if (!account) return true;
    return window.confirm(`${t("quantum.replaceWarning")}\n\n${t("common.continue")}?`);
  }

  async function createPqc() {
    if (ksPass.length < MIN_KEYSTORE_PASS) {
      onToast(t("quantum.passwordMin", { count: MIN_KEYSTORE_PASS }), "error");
      return;
    }
    if (!confirmReplace()) return;
    setBusy(true);
    try {
      const acc = summaryFromAccountInfo(await quantumApi.createPqc(ksPass));
      setAccount(acc);
      await refreshSettings();
      onToast(t("quantum.accountCreated", { kind: t("account.pqc") }), "success");
    } catch (e) {
      onToast(formatInvokeError(e), "error");
    } finally {
      setBusy(false);
    }
  }

  async function createHybrid() {
    if (ksPass.length < MIN_KEYSTORE_PASS) {
      onToast(t("quantum.passwordMin", { count: MIN_KEYSTORE_PASS }), "error");
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
      onToast(t("quantum.accountCreated", { kind: t("account.hybrid") }), "success");
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

  function allowType4Action(): boolean {
    if (!mainnetBlocked) return true;
    onToast(t("quantum.lab.mainnetBlocked"), "error");
    return false;
  }

  async function prepareAirgapType4() {
    if (!allowType4Action()) return;
    if (!type4Ready) {
      onToast(t("quantum.compatibleAccountRequired"), "error");
      return;
    }
    setBusy(true);
    try {
      const prep = await quantumApi.prepareAirgapType4(sendTo.trim(), sendAmount.trim());
      setAirgapQr(prep.qr_parts);
      setSignedAirgapQr([]);
      setShowAirgap(true);
      onToast(t("quantum.unsignedReady"), "success");
    } catch (e) {
      onToast(formatInvokeError(e), "error");
    } finally {
      setBusy(false);
    }
  }

  async function signAirgapType4() {
    if (!allowType4Action()) return;
    if (!airgapQr.length || !sendPass.trim()) {
      onToast(t("quantum.airgapCredentialsRequired"), "error");
      return;
    }
    setBusy(true);
    try {
      const parsed = await api.airgapParseQrBatch(airgapQr);
      const env = parsed.envelope;
      if (!env || env.kind !== "unsigned") {
        throw new Error(t("quantum.expectedUnsigned"));
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
      onToast(t("quantum.signedReady"), "success");
    } catch (e) {
      onToast(formatInvokeError(e), "error");
    } finally {
      setBusy(false);
    }
  }

  async function broadcastAirgapType4() {
    if (!allowType4Action()) return;
    if (!signedAirgapQr.length) return;
    setBusy(true);
    try {
      const parsed = await api.airgapParseQrBatch(signedAirgapQr);
      const env = parsed.envelope;
      if (!env || env.kind !== "signed") {
        throw new Error(t("quantum.expectedSigned"));
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
      onToast(t("quantum.broadcastComplete"), "success");
      await refreshBalance();
      void runPreflight();
    } catch (e) {
      onToast(formatInvokeError(e), "error");
    } finally {
      setBusy(false);
    }
  }

  async function sendType4() {
    if (!allowType4Action()) return;
    if (!type4Ready) {
      onToast(t("quantum.compatibleAccountRequired"), "error");
      return;
    }
    if (!sendPass.trim()) {
      onToast(t("quantum.passwordRequired"), "error");
      return;
    }
    if (!preflight?.ok) {
      onToast(preflight?.errors.join("; ") || t("quantum.preflightFailed"), "error");
      return;
    }
    const amt = Number(sendAmount);
    if (!Number.isFinite(amt) || amt <= 0) {
      onToast(t("quantum.invalidAmount"), "error");
      return;
    }
    setBusy(true);
    setSendHash("");
    try {
      await maybeSecondFactor(amt);
      const res = await quantumApi.sendType4(sendTo.trim(), sendAmount.trim(), sendPass);
      setSendHash(res.hash);
      onToast(t("quantum.transactionSent"), "success");
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
    onToast(t("quantum.addressCopied"), "success");
  }

  if (!settings) {
    return (
      <div className="card">
        <p className="muted">{t("quantum.loadingSettings")}</p>
      </div>
    );
  }

  return (
    <>
      <div className="card quantum-lab-banner">
        <h2 style={{ marginTop: 0 }}>{t("quantum.lab.title")}</h2>
        <p className="muted" style={{ marginBottom: "0.5rem" }}>
          {t("quantum.lab.tagline")}
        </p>
        <p className="muted small">{t("quantum.lab.disclaimer")}</p>
      </div>
      <div className="card quantum-panel">
        <div className="toggle-row">
          <div>
            <strong>{t("quantum.lab.title")}</strong>
            <p className="muted">{t("quantum.algorithmSummary")}</p>
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

        {settings.quantum_mode && (
          <>
            {account && (
              <div className="quantum-active">
                <AddressBadge address={account.address} version={account.address_version} kind={account.kind} />
                <code>{account.address}</code>
                <span className="muted">
                  {t(account.kind === "hybrid" ? "account.hybrid" : "account.pqc")}
                </span>
                <button type="button" className="small" onClick={() => void copyQuantumAddress()}>
                  {t("common.copy")}
                </button>
              </div>
            )}

            <label className="label">
              {t("quantum.keystorePasswordMin", { count: MIN_KEYSTORE_PASS })}
            </label>
            <input type="password" value={ksPass} onChange={(e) => setKsPass(e.target.value)} />
            <label className="label">{t("quantum.legacyPrivateKey")}</label>
            <input
              value={legacyPrikey}
              onChange={(e) => setLegacyPrikey(e.target.value)}
              placeholder={t("common.optional")}
            />

            <div className="row-btns">
              <button type="button" className="btn-pqc" disabled={busy} onClick={() => void createPqc()}>
                {t("quantum.createPqc")}
              </button>
              <button type="button" className="btn-hybrid" disabled={busy} onClick={() => void createHybrid()}>
                {t("quantum.createHybrid")}
              </button>
            </div>
            <button type="button" disabled={busy} onClick={() => setShowKs(true)}>
              {t("quantum.keystoreImportExport")}
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
          blocked={mainnetBlocked}
          blockedMessage={t("quantum.lab.mainnetBlocked")}
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
          <h2>{t("quantum.sendTitle")}</h2>
          {mainnetBlocked ? <p className="warn">{t("quantum.lab.mainnetBlocked")}</p> : null}
          <p className="muted">
            {t("common.node")}: {nodeUrl ?? t("common.default")}
          </p>

          <label className="label">{t("quantum.toAddress")}</label>
          <input value={sendTo} onChange={(e) => setSendTo(e.target.value)} />

          <label className="label">{t("quantum.amountHac")}</label>
          <input value={sendAmount} onChange={(e) => setSendAmount(e.target.value)} />

          <label className="label">{t("quantum.keystorePassword")}</label>
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
                  {t("quantum.preflightSummary", {
                    balance: preflight.balance_mei.toFixed(3),
                    networkFee: preflight.fee_mei.toFixed(4),
                    walletFee: preflight.service_fee_mei.toFixed(6),
                    total: preflight.total_mei.toFixed(4),
                  })}
                </p>
              )}
            </div>
          )}

          <div className="row-btns">
            <button
              type="button"
              className="primary"
              disabled={busy || mainnetBlocked || !type4Ready || !sendPass || !preflight?.ok}
              onClick={() => void sendType4()}
            >
              {t("quantum.signSend")}
            </button>
          </div>

          {sendHash && (
            <div className="quantum-success">
              <p>{t("quantum.transactionAccepted")}</p>
              <code>{sendHash}</code>
            </div>
          )}

          <div className="row-btns">
            <button type="button" disabled={busy || mainnetBlocked || !type4Ready} onClick={() => void prepareAirgapType4()}>
              {t("quantum.airgapUnsignedAction")}
            </button>
            {showAirgap && airgapQr.length > 0 && (
              <button type="button" disabled={busy || mainnetBlocked || !sendPass} onClick={() => void signAirgapType4()}>
                {t("quantum.signOffline")}
              </button>
            )}
            {signedAirgapQr.length > 0 && (
              <button type="button" disabled={busy || mainnetBlocked} onClick={() => void broadcastAirgapType4()}>
                {t("quantum.broadcastSigned")}
              </button>
            )}
          </div>

          {showAirgap && airgapQrUrls.length > 0 && (
            <div className="preview-box">
              <p className="muted">{t("quantum.unsignedQrHint")}</p>
              <div className="qr-grid">
                {airgapQrUrls.map((url, i) => (
                  <img key={i} src={url} alt={`Type4 unsigned ${i + 1}`} className="qr-thumb" />
                ))}
              </div>
            </div>
          )}

          {signedAirgapUrls.length > 0 && (
            <div className="preview-box">
              <p className="muted">{t("quantum.signedQrHint")}</p>
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
            <strong>{t("quantum.nodeHealth")}</strong>
            <button type="button" className="small" disabled={busy || mainnetBlocked} onClick={() => void refreshNode()}>
              {t("common.refresh")}
            </button>
          </div>
          {nodeUrl && (
            <p className="muted small">
              {t("common.node")}: <code>{nodeUrl}</code>
            </p>
          )}
          {mainnetBlocked ? (
            <p className="warn">{t("quantum.lab.mainnetBlocked")}</p>
          ) : (
            <>
          <p className={`quantum-node-status ${nodeMetrics && !nodeErr ? "ok" : "bad"}`}>
            {nodeMetrics && !nodeErr
              ? (() => {
                  const latest = nodeMetrics.latest as { height?: number } | undefined;
                  const h = latest?.height;
                  return h != null
                    ? t("quantum.nodeReachableHeight", { height: h })
                    : t("quantum.nodeReachable");
                })()
              : t("quantum.nodeUnreachable")}
          </p>
          {nodeMetrics && (
            <pre className="quantum-metrics">{JSON.stringify(nodeMetrics, null, 2)}</pre>
          )}
          {nodeErr && <p className="error">{nodeErr}</p>}
            </>
          )}
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
            onToast(t("quantum.keystoreImported", { address: acc.address }), "success");
          }}
        />
      )}
    </>
  );
}

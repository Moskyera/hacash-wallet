import { type4Balance, type Type4Probe } from "@hacash/wallet-ui";
import { useCallback, useEffect, useState } from "react";
import { api, quantumApi, QuantumAccountSummary, QuantumPreflight } from "../api";
import { formatInvokeError } from "../formatInvokeError";
import { useLocale } from "../locale";
import { canSendType4 } from "../quantumMeta";
import { runWebAuthnAuth, webAuthnClientOrigin } from "../webauthn";
import AddressBadge from "./AddressBadge";

const DEFAULT_TO = "";


type Props = {
  account: QuantumAccountSummary | null;
  balanceProbe: Type4Probe;
  onRefreshBalance: () => Promise<void>;
  nodeUrl?: string;
  disabled?: boolean;
  blockedMessage?: string;
  webauthnEnabled?: boolean;
  securityProfile?: string;
  nativeBioAvailable?: boolean;
};

async function maybeWebAuthnGate(
  amount: number,
  webauthnEnabled?: boolean,
  securityProfile?: string,
  nativeBioAvailable?: boolean,
  unavailableMessage?: string,
) {
  const needs2fa =
    securityProfile === "paranoid" || (securityProfile !== "paranoid" && amount >= 100);
  if (!needs2fa) return;
  if (webauthnEnabled) {
    const origin = webAuthnClientOrigin();
    const options = await api.webauthnAuthBegin(origin);
    const assertion = await runWebAuthnAuth(options);
    await api.webauthnAuthFinish(assertion);
    return;
  }
  if (nativeBioAvailable) {
    await api.confirmBiometricNative();
    return;
  }
  throw new Error(unavailableMessage ?? "Second-factor authentication is required.");
}

export default function SendQuantumTx({
  account,
  nodeUrl,
  disabled,
  balanceProbe,
  onRefreshBalance,
  blockedMessage,
  webauthnEnabled,
  securityProfile,
  nativeBioAvailable,
}: Props) {
  const [to, setTo] = useState(DEFAULT_TO);
  const { t } = useLocale();
  const [amount, setAmount] = useState("0.1");
  const [pass, setPass] = useState("");
  const [preflight, setPreflight] = useState<QuantumPreflight | null>(null);
  const [phase, setPhase] = useState<"idle" | "busy" | "ok" | "err">("idle");
  const [hash, setHash] = useState("");
  const [fee, setFee] = useState("");
  const [err, setErr] = useState("");
  const [showAirgap, setShowAirgap] = useState(false);
  const [airgapQr, setAirgapQr] = useState<string[]>([]);
  const [signedQr, setSignedQr] = useState<string[]>([]);

  const type4Ready = canSendType4(account);
  const isPqcSender = account?.kind === "pqckey" && account.address_version === 6;

  const balance = type4Balance(balanceProbe);

  const runPreflight = useCallback(async () => {
    if (!account || !type4Ready || disabled) {
      setPreflight(null);
      return;
    }
    try {
      const p = await quantumApi.preflightType4(to.trim(), amount.trim());
      setPreflight(p);
    } catch (e) {
      setPreflight({
        ok: false,
        warnings: [],
        errors: [formatInvokeError(e)],
        balance_mei: balance ?? 0,
        fee_wire: "0:004",
        fee_mei: 0.004,
        service_fee_mei: 0,
        service_fee_treasury: "",
        total_mei: 0,
      });
    }
  }, [account, type4Ready, disabled, to, amount, balance]);

  useEffect(() => {
    const t = setTimeout(() => {
      runPreflight();
    }, 400);
    return () => clearTimeout(t);
  }, [runPreflight]);

  const canSubmit =
    type4Ready &&
    !!pass.trim() &&
    preflight?.ok === true &&
    phase !== "busy" &&
    !disabled;

  async function send() {
    if (disabled) {
      setErr(blockedMessage ?? t("quantum.signingUnavailable"));
      return;
    }
    if (!account) {
      setErr(t("quantum.createAccountFirst"));
      return;
    }
    if (!type4Ready) {
      setErr(t("quantum.compatibleAccountRequired"));
      return;
    }
    if (!pass.trim()) {
      setErr(t("quantum.passwordRequired"));
      return;
    }
    if (!preflight?.ok) {
      setErr(preflight?.errors.join("; ") || t("quantum.preflightChecksFailed"));
      return;
    }
    setPhase("busy");
    setErr("");
    try {
      const amt = Number(amount);
      await maybeWebAuthnGate(
        amt,
        webauthnEnabled,
        securityProfile,
        nativeBioAvailable,
        t("quantum.secondFactorRequired"),
      );
      const res = await quantumApi.sendType4(to.trim(), amount.trim(), pass);
      setHash(res.hash);
      setFee(res.fee_used ?? preflight?.fee_wire ?? "");
      setPhase("ok");
      await onRefreshBalance();
      runPreflight();
    } catch (e) {
      setErr(formatInvokeError(e));
      setPhase("err");
    }
  }

  async function prepareAirgap() {
    if (disabled) {
      setErr(blockedMessage ?? t("quantum.signingUnavailable"));
      return;
    }
    if (!type4Ready) {
      setErr(t("quantum.compatibleAccountRequired"));
      return;
    }
    setPhase("busy");
    setErr("");
    try {
      const prep = await quantumApi.prepareAirgapType4(to.trim(), amount.trim());
      setAirgapQr(prep.qr_parts);
      setSignedQr([]);
      setShowAirgap(true);
      setPhase("idle");
    } catch (e) {
      setErr(formatInvokeError(e));
      setPhase("err");
    }
  }

  async function signAirgap() {
    if (disabled) {
      setErr(blockedMessage ?? t("quantum.signingUnavailable"));
      return;
    }
    if (!airgapQr.length) return;
    setPhase("busy");
    setErr("");
    try {
      const parsed = await api.airgapParseQrBatch(airgapQr);
      const env = parsed.envelope;
      if (!env || env.kind !== "unsigned") {
        throw new Error(t("quantum.expectedUnsigned"));
      }
      await maybeWebAuthnGate(
        Number(amount),
        webauthnEnabled,
        securityProfile,
        nativeBioAvailable,
        t("quantum.secondFactorRequired"),
      );
      const signed = await quantumApi.airgapSignType4(
        {
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
        },
        pass,
      );
      setSignedQr(signed.qr_parts);
      setPhase("idle");
    } catch (e) {
      setErr(formatInvokeError(e));
      setPhase("err");
    }
  }

  async function broadcastAirgap() {
    if (disabled) {
      setErr(blockedMessage ?? t("quantum.signingUnavailable"));
      return;
    }
    if (!signedQr.length) return;
    setPhase("busy");
    setErr("");
    try {
      const parsed = await api.airgapParseQrBatch(signedQr);
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
      setHash(result.tx_hash);
      setPhase("ok");
      await onRefreshBalance();
    } catch (e) {
      setErr(formatInvokeError(e));
      setPhase("err");
    }
  }

  return (
    <section className="panel send-quantum">
      <h3>{t("quantum.sendTitle")}</h3>
      <p className="muted">{t("quantum.experimentalWarning")}</p>
      {blockedMessage ? <p className="warn quantum-policy-hint">{blockedMessage}</p> : null}
      <p className="muted">
        {t("common.node")}: <code>{nodeUrl ?? "http://127.0.0.1:8080"}</code>
        {preflight?.ok ? (
          <>
            {" "}
            {" "}
            {t("quantum.feeSummary", {
              networkFee: preflight.fee_mei.toFixed(4),
              walletFee: preflight.service_fee_mei.toFixed(6),
              total: preflight.total_mei.toFixed(4),
            })}
          </>
        ) : fee ? (
          <>
            {" "}
            {" "}{t("quantum.lastFee")}: <code>{fee}</code>
          </>
        ) : null}
      </p>

      {isPqcSender && (
        <p className="warn quantum-policy-hint">{t("quantum.pqcV6Warning")}</p>
      )}

      <div className="from-row quantum-active">
        <span className="muted">{t("common.from")}</span>
        {account ? (
          <>
            <AddressBadge
              address={account.address}
              version={account.address_version}
              kind={account.kind}
            />
            <code className="mono">{account.address}</code>
            <span className="muted">
              {balance == null ? "" : `${balance.toFixed(3)} HAC`}
            </span>
          </>
        ) : (
          <span className="muted">{t("quantum.noAccount")}</span>
        )}
      </div>

      <label className="field">
        {t("quantum.toAddress")}
        <input className="mono" value={to} onChange={(e) => setTo(e.target.value)} />
      </label>
      <label className="field">
        {t("quantum.amountHac")}
        <input value={amount} onChange={(e) => setAmount(e.target.value)} />
      </label>

      {preflight && (
        <div className={`preflight-box ${preflight.ok ? "ok" : "bad"}`}>
          {preflight.errors.map((e) => (
            <p key={e} className="error">
              {e}
            </p>
          ))}
          {preflight.warnings.map((w) => (
            <p key={w} className="warn">
              {w}
            </p>
          ))}
          {preflight.ok && preflight.warnings.length === 0 && (
            <p className="info">
              {t("quantum.preflightOkBalance", { balance: preflight.balance_mei.toFixed(3) })}
            </p>
          )}
        </div>
      )}

      <label className="field">
        {t("quantum.keystorePassword")}
        <input type="password" value={pass} onChange={(e) => setPass(e.target.value)} />
      </label>

      <div className="actions-row">
        <button
          type="button"
          className="primary"
          disabled={!canSubmit}
          onClick={() => send()}
        >
          {t("quantum.signSend")}
        </button>
        <button
          type="button"
          className="btn-ghost"
          disabled={disabled || phase === "busy" || !type4Ready}
          onClick={prepareAirgap}
        >
          {t("quantum.airgapUnsignedAction")}
        </button>
      </div>
      {!canSubmit && type4Ready && phase !== "busy" && (
        <p className="muted small">
          {!pass.trim()
            ? t("quantum.enterPasswordToSign")
            : !preflight
              ? t("quantum.runningPreflight")
              : !preflight.ok
                ? t("quantum.fixPreflight")
                : null}
        </p>
      )}

      {showAirgap && (
        <div className="quantum-airgap-box">
          <h4>{t("quantum.airgapTitle")}</h4>
          <p className="muted small">
            {t("quantum.airgapParts", { unsigned: airgapQr.length, signed: signedQr.length })}
          </p>
          <div className="actions-row">
            <button type="button" disabled={disabled || phase === "busy" || !airgapQr.length} onClick={signAirgap}>
              {t("quantum.signOffline")}
            </button>
            <button
              type="button"
              disabled={disabled || phase === "busy" || !signedQr.length}
              onClick={broadcastAirgap}
            >
              {t("quantum.broadcastSigned")}
            </button>
          </div>
        </div>
      )}

      {phase === "ok" && (
        <div className="quantum-success">
          <div className="quantum-success__ring" />
          <p>{t("quantum.transactionAccepted")}</p>
          <code className="mono">{hash}</code>
        </div>
      )}
      {err && <p className="error">{err}</p>}
    </section>
  );
}

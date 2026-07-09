import { useCallback, useEffect, useState } from "react";
import { api, quantumApi, QuantumAccountSummary, QuantumPreflight } from "../api";
import { formatInvokeError } from "../formatInvokeError";
import { canSendType4, PQC_TYPE4_HINT } from "../quantumMeta";
import { runWebAuthnAuth } from "../webauthn";
import AddressBadge from "./AddressBadge";

const DEFAULT_TO = "1MzNY1oA3kfgYi75zquj3SRUPYztzXHzK9";
const AUTO_FEE = "40:244";

type Props = {
  account: QuantumAccountSummary | null;
  nodeUrl?: string;
  disabled?: boolean;
  webauthnEnabled?: boolean;
  securityProfile?: string;
  nativeBioAvailable?: boolean;
};

async function maybeWebAuthnGate(
  amount: number,
  webauthnEnabled?: boolean,
  securityProfile?: string,
  nativeBioAvailable?: boolean,
) {
  const needs2fa =
    securityProfile === "paranoid" || (securityProfile !== "paranoid" && amount >= 100);
  if (!needs2fa) return;
  if (webauthnEnabled) {
    const options = await api.webauthnAuthBegin();
    const assertion = await runWebAuthnAuth(options);
    await api.webauthnAuthFinish(assertion);
    return;
  }
  if (nativeBioAvailable) {
    await api.confirmBiometricNative();
    return;
  }
  throw new Error("Enable WebAuthn or Windows Hello for large quantum sends");
}

export default function SendQuantumTx({
  account,
  nodeUrl,
  disabled,
  webauthnEnabled,
  securityProfile,
  nativeBioAvailable,
}: Props) {
  const [to, setTo] = useState(DEFAULT_TO);
  const [amount, setAmount] = useState("0.1");
  const [pass, setPass] = useState("");
  const [balance, setBalance] = useState<number | null>(null);
  const [preflight, setPreflight] = useState<QuantumPreflight | null>(null);
  const [phase, setPhase] = useState<"idle" | "busy" | "ok" | "err">("idle");
  const [hash, setHash] = useState("");
  const [fee, setFee] = useState(AUTO_FEE);
  const [err, setErr] = useState("");
  const [showAirgap, setShowAirgap] = useState(false);
  const [airgapQr, setAirgapQr] = useState<string[]>([]);
  const [signedQr, setSignedQr] = useState<string[]>([]);

  const type4Ready = canSendType4(account);
  const isPqcSender = account?.kind === "pqckey" && account.address_version === 6;

  const refreshBalance = useCallback(async () => {
    if (!account) {
      setBalance(null);
      return;
    }
    try {
      const b = await quantumApi.balance();
      setBalance(b);
    } catch {
      setBalance(null);
    }
  }, [account]);

  const runPreflight = useCallback(async () => {
    if (!account || !type4Ready) {
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
        fee_wire: AUTO_FEE,
      });
    }
  }, [account, type4Ready, to, amount, balance]);

  useEffect(() => {
    refreshBalance();
  }, [refreshBalance]);

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

  async function send(isTest: boolean) {
    if (!account) {
      setErr("Create or import a quantum account first.");
      return;
    }
    if (!type4Ready) {
      setErr("Create or import a PQC (v6) or Hybrid (v7) quantum account first.");
      return;
    }
    if (!pass.trim()) {
      setErr("Enter your quantum keystore password to sign.");
      return;
    }
    if (!preflight?.ok) {
      setErr(preflight?.errors.join("; ") || "Preflight checks failed — wait or fix amount/recipient.");
      return;
    }
    setPhase("busy");
    setErr("");
    try {
      const amt = Number(amount);
      await maybeWebAuthnGate(amt, webauthnEnabled, securityProfile, nativeBioAvailable);
      if (isTest) {
        const test = await quantumApi.sendTestTx(pass);
        setHash(test.hash);
        setFee(test.fee_used ?? AUTO_FEE);
      } else {
        const res = await quantumApi.sendType4(to.trim(), amount.trim(), pass);
        setHash(res.hash);
        setFee(res.fee_used ?? AUTO_FEE);
      }
      setPhase("ok");
      await refreshBalance();
      runPreflight();
    } catch (e) {
      setErr(formatInvokeError(e));
      setPhase("err");
    }
  }

  async function prepareAirgap() {
    if (!type4Ready) {
      setErr("Create or import a PQC (v6) or Hybrid (v7) quantum account first.");
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
    if (!airgapQr.length) return;
    setPhase("busy");
    setErr("");
    try {
      const parsed = await api.airgapParseQrBatch(airgapQr);
      const env = parsed.envelope;
      if (!env || env.kind !== "unsigned") {
        throw new Error("Expected unsigned Type 4 envelope");
      }
      await maybeWebAuthnGate(Number(amount), webauthnEnabled, securityProfile, nativeBioAvailable);
      const signed = await quantumApi.airgapSignType4(
        {
          v: env.v,
          from: env.from,
          to: env.to,
          amount_mei: env.amount_mei,
          amount_wire: env.amount_wire,
          fee: env.fee,
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
    if (!signedQr.length) return;
    setPhase("busy");
    setErr("");
    try {
      const parsed = await api.airgapParseQrBatch(signedQr);
      const env = parsed.envelope;
      if (!env || env.kind !== "signed") {
        throw new Error("Expected signed Type 4 envelope");
      }
      const result = await api.airgapBroadcastSigned({
        v: env.v,
        from: env.from,
        to: env.to,
        amount_mei: env.amount_mei,
        signed_hex: env.signed_hex,
        summary: env.summary,
        tx_type: env.tx_type ?? 4,
      });
      setHash(result.tx_hash);
      setPhase("ok");
      await refreshBalance();
    } catch (e) {
      setErr(formatInvokeError(e));
      setPhase("err");
    }
  }

  return (
    <section className="panel send-quantum">
      <h3>Send Type 4 (Quantum)</h3>
      <p className="muted">
        Node: <code>{nodeUrl ?? "http://127.0.0.1:8080"}</code> · auto-fee <code>{fee}</code>
      </p>

      {isPqcSender && (
        <p className="warn quantum-policy-hint">{PQC_TYPE4_HINT}</p>
      )}

      <div className="from-row quantum-active">
        <span className="muted">From</span>
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
          <span className="muted">— no quantum account —</span>
        )}
      </div>

      <label className="field">
        To
        <input className="mono" value={to} onChange={(e) => setTo(e.target.value)} />
      </label>
      <label className="field">
        Amount (HAC)
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
            <p className="info">Preflight OK · balance {preflight.balance_mei.toFixed(3)} HAC</p>
          )}
        </div>
      )}

      <label className="field">
        Keystore password
        <input type="password" value={pass} onChange={(e) => setPass(e.target.value)} />
      </label>

      <div className="actions-row">
        <button
          type="button"
          className="primary"
          disabled={!canSubmit}
          onClick={() => send(false)}
        >
          Sign &amp; Send Type 4
        </button>
        <button
          type="button"
          className="btn-test"
          disabled={!canSubmit}
          onClick={() => send(true)}
        >
          Send Test Quantum TX
        </button>
        <button
          type="button"
          className="btn-ghost"
          disabled={disabled || phase === "busy" || !type4Ready}
          onClick={prepareAirgap}
        >
          Air-gap prepare…
        </button>
      </div>
      {!canSubmit && type4Ready && phase !== "busy" && (
        <p className="muted small">
          {!pass.trim()
            ? "Enter keystore password to enable signing."
            : !preflight
              ? "Running preflight checks…"
              : !preflight.ok
                ? "Fix preflight errors above before sending."
                : null}
        </p>
      )}

      {showAirgap && (
        <div className="quantum-airgap-box">
          <h4>Type 4 air-gap</h4>
          <p className="muted small">
            Unsigned QR parts: {airgapQr.length} · Signed: {signedQr.length}
          </p>
          <div className="actions-row">
            <button type="button" disabled={phase === "busy" || !airgapQr.length} onClick={signAirgap}>
              Sign offline (this device)
            </button>
            <button
              type="button"
              disabled={phase === "busy" || !signedQr.length}
              onClick={broadcastAirgap}
            >
              Broadcast signed
            </button>
          </div>
        </div>
      )}

      {phase === "ok" && (
        <div className="quantum-success">
          <div className="quantum-success__ring" />
          <p>Quantum transaction accepted</p>
          <code className="mono">{hash}</code>
        </div>
      )}
      {err && <p className="error">{err}</p>}
    </section>
  );
}
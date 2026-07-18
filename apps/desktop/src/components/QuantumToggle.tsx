import { useEffect, useState } from "react";
import { quantumApi, QuantumAccountSummary, QuantumSettings } from "../api";
import { formatInvokeError } from "../formatInvokeError";
import { useLocale } from "../locale";
import {
  accountSummaryFromSettings,
  summaryFromAccountInfo,
} from "../quantumMeta";
import AddressBadge from "./AddressBadge";
import KeystoreV3Modal from "./KeystoreV3Modal";

type Props = {
  onAccountChange?: (acc: QuantumAccountSummary | null) => void;
};

export default function QuantumToggle({ onAccountChange }: Props) {
  const { t } = useLocale();
  const [settings, setSettings] = useState<QuantumSettings | null>(null);
  const [account, setAccount] = useState<QuantumAccountSummary | null>(null);
  const [pass, setPass] = useState("");
  const [legacyPrikey, setLegacyPrikey] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const [info, setInfo] = useState("");
  const [showKs, setShowKs] = useState(false);

  async function refreshSettings() {
    const s = await quantumApi.getSettings();
    setSettings(s);
    const acc = accountSummaryFromSettings(s);
    setAccount(acc);
    onAccountChange?.(acc);
  }

  useEffect(() => {
    const id = window.setTimeout(() => {
      refreshSettings().catch((e) => setErr(formatInvokeError(e)));
    }, 0);
    return () => window.clearTimeout(id);
    // eslint-disable-next-line react-hooks/exhaustive-deps -- mount once
  }, []);

  async function toggleMode(on: boolean) {
    setErr("");
    setInfo("");
    try {
      await quantumApi.setMode(on);
      await refreshSettings();
    } catch (e) {
      setErr(formatInvokeError(e));
    }
  }

  async function createPqc() {
    if (pass.length < 8) {
      setErr(t("quantum.passwordProgress", { current: pass.length, count: 8 }));
      return;
    }
    if (account && !window.confirm(`${t("quantum.replaceWarning")}\n\n${t("common.continue")}?`)) return;
    setBusy(true);
    setErr("");
    setInfo(t("quantum.creatingAccount", { kind: t("account.pqc") }));
    try {
      const acc = summaryFromAccountInfo(await quantumApi.createPqc(pass));
      setAccount(acc);
      onAccountChange?.(acc);
      await refreshSettings();
      setInfo(t("quantum.accountCreatedAddress", { address: acc.address }));
    } catch (e) {
      setErr(formatInvokeError(e));
      setInfo("");
    } finally {
      setBusy(false);
    }
  }

  async function createHybrid() {
    if (pass.length < 8) {
      setErr(t("quantum.passwordProgress", { current: pass.length, count: 8 }));
      return;
    }
    if (account && !window.confirm(`${t("quantum.replaceWarning")}\n\n${t("common.continue")}?`)) return;
    setBusy(true);
    setErr("");
    setInfo(t("quantum.creatingAccount", { kind: t("account.hybrid") }));
    try {
      const acc = summaryFromAccountInfo(
        await quantumApi.createHybrid(pass, legacyPrikey || undefined),
      );
      setAccount(acc);
      onAccountChange?.(acc);
      await refreshSettings();
      setInfo(t("quantum.accountCreatedAddress", { address: acc.address }));
    } catch (e) {
      setErr(formatInvokeError(e));
      setInfo("");
    } finally {
      setBusy(false);
    }
  }

  if (!settings) {
    return (
      <section className="panel quantum-panel">
        <p className="muted">{t("quantum.loadingSettings")}</p>
      </section>
    );
  }

  return (
    <section className="panel quantum-panel">
      <div className="panel-head row-between">
        <div>
          <h3>{t("quantum.lab.title")}</h3>
          <p className="muted">{t("quantum.algorithmSummaryDesktop")}</p>
        </div>
        <label className="quantum-switch">
          <input
            type="checkbox"
            checked={settings.quantum_mode}
            disabled={busy}
            onChange={(e) => toggleMode(e.target.checked)}
          />
          <span />
        </label>
      </div>

      {settings.quantum_mode && (
        <>
          {account && (
            <div className="quantum-active">
              <AddressBadge
                address={account.address}
                version={account.address_version}
                kind={account.kind}
              />
              <code className="mono">{account.address}</code>
              <span className="muted">
                {t(account.kind === "hybrid" ? "account.hybrid" : "account.pqc")}
              </span>
            </div>
          )}

          <label className="field">
            {t("quantum.keystorePasswordLocal", { count: 8 })}
            <input
              type="password"
              value={pass}
              onChange={(e) => setPass(e.target.value)}
              autoComplete="new-password"
            />
            <span className={`field-hint ${pass.length >= 8 ? "ok" : "warn"}`}>
              {t("quantum.characterProgress", { current: pass.length, count: 8 })}
            </span>
          </label>

          <label className="field">
            {t("quantum.legacyPrivateKeyDesktop")}
            <input
              className="mono"
              value={legacyPrikey}
              onChange={(e) => setLegacyPrikey(e.target.value)}
              placeholder={t("quantum.freshHybridPlaceholder")}
            />
          </label>

          <div className="actions-row">
            <button type="button" className="btn-pqc" disabled={busy} onClick={createPqc}>
              {busy ? t("quantum.creating") : t("quantum.createPqcV6")}
            </button>
            <button type="button" className="btn-hybrid" disabled={busy} onClick={createHybrid}>
              {busy ? t("quantum.creating") : t("quantum.createHybridV7")}
            </button>
            <button type="button" className="btn-ghost" disabled={busy} onClick={() => setShowKs(true)}>
              {t("quantum.keystoreV3")}
            </button>
          </div>

          {info && <p className="info">{info}</p>}
          {err && <p className="error">{err}</p>}
        </>
      )}

      {showKs && (
        <KeystoreV3Modal
          initialPassword={pass}
          hasAccount={!!account}
          onClose={() => setShowKs(false)}
          onImported={async (acc) => {
            setAccount(acc);
            onAccountChange?.(acc);
            await refreshSettings();
            setInfo(t("quantum.keystoreImported", { address: acc.address }));
            setShowKs(false);
          }}
        />
      )}
    </section>
  );
}

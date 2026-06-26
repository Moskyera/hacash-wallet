import { useEffect, useState } from "react";
import { quantumApi, QuantumAccountInfo, QuantumSettings } from "../api";
import AddressBadge from "./AddressBadge";
import KeystoreV3Modal from "./KeystoreV3Modal";

type Props = {
  onAccountChange?: (acc: QuantumAccountInfo | null) => void;
};

function accountFromSettings(s: QuantumSettings): QuantumAccountInfo | null {
  if (!s.active_address) return null;
  const kind = s.kind ?? "hybrid";
  const version =
    kind === "hybrid" ? 7 : kind === "pqckey" ? 6 : (s.address_version ?? 0);
  return {
    address: s.active_address,
    kind,
    address_version: version,
    alg_id: 3,
    mldsa_pubkey: "",
    secp_pubkey: "",
  };
}

function kindLabel(kind: string): string {
  if (kind === "hybrid") return "Hybrid";
  if (kind === "pqckey") return "PQC";
  return kind;
}

function formatInvokeError(e: unknown): string {
  if (typeof e === "string") return e;
  if (e instanceof Error) return e.message;
  if (e && typeof e === "object") {
    const o = e as Record<string, unknown>;
    if (typeof o.message === "string") return o.message;
  }
  return String(e);
}

export default function QuantumToggle({ onAccountChange }: Props) {
  const [settings, setSettings] = useState<QuantumSettings | null>(null);
  const [account, setAccount] = useState<QuantumAccountInfo | null>(null);
  const [pass, setPass] = useState("hybrid-pass-12345");
  const [legacyPrikey, setLegacyPrikey] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const [info, setInfo] = useState("");
  const [showKs, setShowKs] = useState(false);

  async function refreshSettings() {
    const s = await quantumApi.getSettings();
    setSettings(s);
    const acc = accountFromSettings(s);
    if (acc) {
      setAccount(acc);
      onAccountChange?.(acc);
    }
  }

  useEffect(() => {
    refreshSettings().catch((e) => setErr(formatInvokeError(e)));
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
      setErr(`Password needs at least 8 characters (${pass.length}/8).`);
      return;
    }
    setBusy(true);
    setErr("");
    setInfo("Creating PQC (v6)…");
    try {
      const acc = await quantumApi.createPqc(pass);
      setAccount(acc);
      onAccountChange?.(acc);
      await refreshSettings();
      setInfo(`Created: ${acc.address}`);
    } catch (e) {
      setErr(formatInvokeError(e));
      setInfo("");
    } finally {
      setBusy(false);
    }
  }

  async function createHybrid() {
    if (pass.length < 8) {
      setErr(`Password needs at least 8 characters (${pass.length}/8).`);
      return;
    }
    setBusy(true);
    setErr("");
    setInfo("Creating Hybrid (v7)…");
    try {
      const acc = await quantumApi.createHybrid(pass, legacyPrikey || undefined);
      setAccount(acc);
      onAccountChange?.(acc);
      await refreshSettings();
      setInfo(`Created: ${acc.address}`);
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
        <p className="muted">Loading quantum settings…</p>
      </section>
    );
  }

  return (
    <section className="panel quantum-panel">
      <div className="panel-head row-between">
        <div>
          <h3>Quantum Mode</h3>
          <p className="muted">ML-DSA-65 · v6 PQC / v7 Hybrid · Keystore v3</p>
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
              <span className="muted">{kindLabel(account.kind)}</span>
            </div>
          )}

          <label className="field">
            Keystore password (≥8 chars, local only)
            <input
              type="password"
              value={pass}
              onChange={(e) => setPass(e.target.value)}
              autoComplete="new-password"
            />
            <span className={`field-hint ${pass.length >= 8 ? "ok" : "warn"}`}>
              {pass.length}/8 characters
            </span>
          </label>

          <label className="field">
            Optional legacy prikey (64-hex) for hybrid-from-secp
            <input
              className="mono"
              value={legacyPrikey}
              onChange={(e) => setLegacyPrikey(e.target.value)}
              placeholder="leave empty for fresh hybrid"
            />
          </label>

          <div className="actions-row">
            <button type="button" className="btn-pqc" disabled={busy} onClick={createPqc}>
              {busy ? "Creating…" : "Create PQC (v6)"}
            </button>
            <button type="button" className="btn-hybrid" disabled={busy} onClick={createHybrid}>
              {busy ? "Creating…" : "Create Hybrid (v7)"}
            </button>
            <button type="button" className="btn-ghost" disabled={busy} onClick={() => setShowKs(true)}>
              Keystore v3…
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
            setInfo(`Keystore imported: ${acc.address}`);
            setShowKs(false);
          }}
        />
      )}
    </section>
  );
}
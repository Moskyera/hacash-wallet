import { useRef, useState } from "react";
import { quantumApi, QuantumAccountInfo, QuantumAccountSummary } from "../api";
import { formatInvokeError } from "../formatInvokeError";
import { kindLabel, summaryFromAccountInfo } from "../quantumMeta";
import AddressBadge from "./AddressBadge";

type Props = {
  initialPassword?: string;
  hasAccount: boolean;
  onClose: () => void;
  onImported: (acc: QuantumAccountSummary) => void;
};

function exportFilename(kind?: string): string {
  if (kind === "pqckey") return "pqc_keystore_v3.json";
  if (kind === "hybrid") return "hybrid_keystore_v3.json";
  return "quantum_keystore_v3.json";
}

export default function KeystoreV3Modal({
  initialPassword = "",
  hasAccount,
  onClose,
  onImported,
}: Props) {
  const fileRef = useRef<HTMLInputElement>(null);
  const [pass, setPass] = useState(initialPassword);
  const [paste, setPaste] = useState("");
  const [preview, setPreview] = useState<QuantumAccountInfo | null>(null);
  const [pendingJson, setPendingJson] = useState("");
  const [err, setErr] = useState("");
  const [info, setInfo] = useState("");
  const [busy, setBusy] = useState(false);

  async function loadJson(json: string) {
    setErr("");
    setInfo("");
    if (pass.length < 8) {
      setErr(`Keystore password must be at least 8 characters (${pass.length}/8).`);
      setPreview(null);
      setPendingJson("");
      return;
    }
    setPendingJson(json);
    setBusy(true);
    setInfo("Decrypting keystore (Argon2id)…");
    try {
      const acc = await quantumApi.previewKeystore(json, pass);
      setPreview(acc);
      setInfo("Keystore unlocked — ready to import.");
    } catch (e) {
      setErr(formatInvokeError(e));
      setPreview(null);
      setInfo("");
    } finally {
      setBusy(false);
    }
  }

  async function onFile(file: File) {
    const json = await file.text();
    await loadJson(json);
  }

  async function onPastePreview() {
    const json = paste.trim();
    if (!json) {
      setErr("Paste keystore JSON first.");
      return;
    }
    await loadJson(json);
  }

  async function doImport() {
    if (!pendingJson || !preview) return;
    setBusy(true);
    setErr("");
    setInfo("Importing…");
    try {
      const acc = await quantumApi.importKeystore(pendingJson, pass);
      setInfo(`Imported ${acc.address}`);
      onImported(summaryFromAccountInfo(acc));
    } catch (e) {
      setErr(formatInvokeError(e));
      setInfo("");
    } finally {
      setBusy(false);
    }
  }

  async function doExport() {
    if (pass.length < 8) {
      setErr(`Keystore password must be at least 8 characters (${pass.length}/8).`);
      return;
    }
    setBusy(true);
    setErr("");
    setInfo("Exporting…");
    try {
      const json = await quantumApi.exportKeystore(pass);
      const meta = JSON.parse(json) as { kind?: string; address?: string };
      const blob = new Blob([json], { type: "application/json" });
      const a = document.createElement("a");
      a.href = URL.createObjectURL(blob);
      a.download = exportFilename(meta.kind);
      a.click();
      URL.revokeObjectURL(a.href);
      setInfo(`Exported ${meta.address ?? "keystore"}`);
    } catch (e) {
      setErr(formatInvokeError(e));
      setInfo("");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal card" onClick={(e) => e.stopPropagation()}>
        <h3>Keystore v3</h3>
        <p className="muted">Argon2id + AES-256-GCM · compatible with mint API JSON</p>

        <label className="field">
          Keystore password
          <input
            type="password"
            value={pass}
            onChange={(e) => {
              setPass(e.target.value);
              setPreview(null);
              setPendingJson("");
              setErr("");
              setInfo("");
            }}
            autoComplete="current-password"
          />
          <span className={`field-hint ${pass.length >= 8 ? "ok" : "warn"}`}>
            {pass.length}/8 characters
          </span>
        </label>

        <label className="field">
          Import file (.json)
          <input
            ref={fileRef}
            type="file"
            accept=".json,application/json"
            disabled={busy}
            onChange={(e) => {
              const f = e.target.files?.[0];
              if (f) onFile(f);
            }}
          />
        </label>

        <label className="field">
          Or paste JSON
          <textarea
            className="textarea mono"
            rows={4}
            value={paste}
            disabled={busy}
            onChange={(e) => setPaste(e.target.value)}
            placeholder='{"version":3,"kind":"hybrid",...}'
          />
        </label>
        <button type="button" className="btn-ghost" disabled={busy || !paste.trim()} onClick={onPastePreview}>
          Preview pasted JSON
        </button>

        {preview && (
          <div className="quantum-active" style={{ marginTop: 12 }}>
            <AddressBadge
              address={preview.address}
              version={preview.address_version}
              kind={preview.kind}
            />
            <code className="mono">{preview.address}</code>
            <span className="muted">{kindLabel(preview.kind)}</span>
          </div>
        )}

        <div className="actions-row" style={{ marginTop: 16 }}>
          <button type="button" disabled={busy || !preview} onClick={doImport}>
            Import &amp; activate
          </button>
          <button type="button" disabled={busy || !hasAccount} onClick={doExport}>
            Export active
          </button>
          <button type="button" className="btn-ghost" disabled={busy} onClick={onClose}>
            Close
          </button>
        </div>

        {info && <p className="info">{info}</p>}
        {err && <p className="error">{err}</p>}
      </div>
    </div>
  );
}
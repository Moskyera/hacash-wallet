import { useRef, useState } from "react";
import { quantumApi, type QuantumAccountInfo, type QuantumAccountSummary } from "../api";
import { handOffTextFile } from "@hacash/wallet-ui";
import { formatInvokeError } from "../formatInvokeError";
import { kindLabel, MIN_KEYSTORE_PASS, summaryFromAccountInfo } from "../quantumMeta";
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
  const [msg, setMsg] = useState("");
  const [busy, setBusy] = useState(false);

  async function loadJson(json: string) {
    setMsg("");
    if (pass.length < MIN_KEYSTORE_PASS) {
      setMsg(`Password needs at least ${MIN_KEYSTORE_PASS} characters.`);
      setPreview(null);
      setPendingJson("");
      return;
    }
    setPendingJson(json);
    setBusy(true);
    try {
      const acc = await quantumApi.previewKeystore(json, pass);
      setPreview(acc);
      setMsg("Keystore unlocked. ready to import.");
    } catch (e) {
      setMsg(formatInvokeError(e));
      setPreview(null);
    } finally {
      setBusy(false);
    }
  }

  async function doImport() {
    if (!pendingJson || !preview) return;
    setBusy(true);
    setMsg("");
    try {
      const acc = await quantumApi.importKeystore(pendingJson, pass);
      onImported(summaryFromAccountInfo(acc));
      setMsg(`Imported ${acc.address}`);
    } catch (e) {
      setMsg(formatInvokeError(e));
    } finally {
      setBusy(false);
    }
  }

  async function doExport() {
    if (pass.length < MIN_KEYSTORE_PASS) {
      setMsg(`Password needs at least ${MIN_KEYSTORE_PASS} characters.`);
      return;
    }
    setBusy(true);
    setMsg("");
    try {
      const json = await quantumApi.exportKeystore(pass);
      const meta = JSON.parse(json) as { kind?: string; address?: string };
      /*
       * The encrypted post-quantum keystore: Argon2id + AES-256-GCM around a key
       * that holds real value. `setMsg("Exported ...")` used to run whatever
       * happened, and on Android nothing ever happened - the shell installs no
       * DownloadListener, so `<a download>` does nothing at all. The repo already
       * knows the correct native route for a wallet backup
       * (`wallet_export_backup_to_downloads`, whose Rust body stages into
       * app_cache_dir and calls a MediaStore copy); there is no equivalent for
       * this keystore, so the honest thing is to say no file was written rather
       * than to claim one was.
       */
      const handoff = await handOffTextFile(exportFilename(meta.kind), json);
      setMsg(
        handoff.ok
          ? handoff.message
          : `${handoff.message} The keystore for ${meta.address ?? "this key"} was NOT saved to a file, and this screen has no copy control either, so there is no route off this phone for it yet. Your key is unharmed and still in this wallet. The same export on the desktop wallet does write a file, for a wallet that holds this key there.`,
      );
    } catch (e) {
      setMsg(formatInvokeError(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal-sheet" onClick={(e) => e.stopPropagation()}>
        <h2>Keystore v3</h2>
        <p className="muted">Argon2id + AES-256-GCM</p>

        <label className="label">Keystore password</label>
        <input
          type="password"
          value={pass}
          onChange={(e) => {
            setPass(e.target.value);
            setPreview(null);
            setPendingJson("");
            setMsg("");
          }}
        />
        <p className={`field-hint ${pass.length >= MIN_KEYSTORE_PASS ? "ok" : "warn"}`}>
          {pass.length}/{MIN_KEYSTORE_PASS} characters
        </p>

        <label className="label">Import file (.json)</label>
        <input
          ref={fileRef}
          type="file"
          accept=".json,application/json"
          disabled={busy}
          onChange={(e) => {
            const f = e.target.files?.[0];
            if (f) void f.text().then(loadJson);
          }}
        />

        <label className="label">Or paste JSON</label>
        <textarea
          value={paste}
          disabled={busy}
          onChange={(e) => setPaste(e.target.value)}
          placeholder='{"version":3,"kind":"hybrid",...}'
        />
        <button type="button" className="small" disabled={busy || !paste.trim()} onClick={() => void loadJson(paste.trim())}>
          Preview pasted JSON
        </button>

        {preview && (
          <div className="quantum-active">
            <AddressBadge address={preview.address} version={preview.address_version} kind={preview.kind} />
            <code>{preview.address}</code>
            <span className="muted">{kindLabel(preview.kind)}</span>
          </div>
        )}

        <div className="row-btns">
          <button type="button" disabled={busy || !preview} onClick={() => void doImport()}>
            Import
          </button>
          <button type="button" className="primary" disabled={busy || !hasAccount} onClick={() => void doExport()}>
            Export
          </button>
        </div>
        {msg && <p className="muted">{msg}</p>}
        <button type="button" className="ghost" onClick={onClose}>
          Close
        </button>
      </div>
    </div>
  );
}
import { useState } from "react";
import {
  agentWalletApi,
  type AgentPilotDiagnosticsExport,
  type AgentPilotDiagnosticsPreview,
} from "./api";

type Props = {
  walletId: string;
  busy: boolean;
  run: (work: () => Promise<void>) => Promise<void>;
  onInfo: (message: string) => void;
};

export function PilotDiagnosticsPanel({ walletId, busy, run, onInfo }: Props) {
  const [preview, setPreview] = useState<AgentPilotDiagnosticsPreview | null>(null);
  const [destination, setDestination] = useState("");
  const [confirmed, setConfirmed] = useState(false);
  const [result, setResult] = useState<AgentPilotDiagnosticsExport | null>(null);

  async function createPreview() {
    const next = await agentWalletApi.diagnosticsPreview(walletId);
    setPreview(next);
    setConfirmed(false);
    setResult(null);
  }

  async function exportDiagnostics() {
    if (!preview || !confirmed || !destination.trim()) return;
    const exported = await agentWalletApi.diagnosticsExport(
      walletId,
      preview.preview_sha256,
      destination.trim(),
    );
    setResult(exported);
    setConfirmed(false);
    onInfo("Redacted pilot diagnostics exported locally. Nothing was uploaded.");
  }

  return (
    <section className="agent-panel" aria-label="Pilot diagnostics export">
      <span className="agent-eyebrow">Local only</span>
      <h2>Pilot diagnostics</h2>
      <p>
        Create a redacted preview first. The wallet never uploads this file and never
        includes keys, secrets, raw transactions or AI prompts.
      </p>
      <button type="button" disabled={busy} onClick={() => void run(createPreview)}>
        Create redacted preview
      </button>
      {preview && (
        <div className="agent-card-list">
          <div>
            <strong>Included categories</strong>
            <ul>{preview.categories.map((item) => <li key={item}>{readable(item)}</li>)}</ul>
          </div>
          <div>
            <strong>Explicitly excluded</strong>
            <ul>{preview.excluded_categories.map((item) => <li key={item}>{readable(item)}</li>)}</ul>
          </div>
          <dl className="agent-detail-grid">
            <Detail label="Network" value={preview.diagnostics.network_id} />
            <Detail label="Protocol" value={preview.diagnostics.pilot_protocol_version} />
            <Detail label="Journal sequence" value={String(preview.diagnostics.journal_sequence)} />
            <Detail label="Anchor sequence" value={String(preview.diagnostics.anchor_sequence ?? "Not initialized")} />
            <Detail label="Preview SHA-256" value={preview.preview_sha256} wide />
          </dl>
          <label className="agent-field">
            Destination .json path
            <input
              value={destination}
              onChange={(event) => {
                setDestination(event.target.value);
                setConfirmed(false);
              }}
              placeholder="C:\\Users\\you\\Downloads\\hpay-pilot-diagnostics.json"
              spellCheck={false}
            />
          </label>
          <label className="agent-confirm-row">
            <input
              type="checkbox"
              checked={confirmed}
              onChange={(event) => setConfirmed(event.target.checked)}
            />
            I reviewed the categories and confirm this exact preview.
          </label>
          <button
            type="button"
            className="agent-primary-action"
            disabled={busy || !confirmed || !destination.trim().toLowerCase().endsWith(".json")}
            onClick={() => void run(exportDiagnostics)}
          >
            Export Pilot Diagnostics
          </button>
        </div>
      )}
      {result && (
        <dl className="agent-detail-grid">
          <Detail label="Saved path" value={result.path} wide />
          <Detail label="Size" value={`${result.size_bytes} bytes`} />
          <Detail label="SHA-256" value={result.sha256} wide />
        </dl>
      )}
    </section>
  );
}

function readable(value: string): string {
  return value.replace(/_/g, " ");
}

function Detail({ label, value, wide = false }: { label: string; value: string; wide?: boolean }) {
  return <div className={wide ? "wide" : ""}><dt>{label}</dt><dd>{value}</dd></div>;
}

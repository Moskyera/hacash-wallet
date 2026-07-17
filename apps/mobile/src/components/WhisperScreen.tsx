import { useCallback, useEffect, useState } from "react";
import { api, type DustWhisperSettings, type RelayHealthStatus } from "../api";
import { formatInvokeError } from "../formatInvokeError";

const RELAY_PLACEHOLDER = "https://relay.example";

type Props = {
  initial?: DustWhisperSettings;
  onToast: (msg: string, kind: "success" | "info" | "error") => void;
};

export default function WhisperScreen({ initial, onToast }: Props) {
  const [draft, setDraft] = useState<DustWhisperSettings>(
    initial ?? {
      enabled: false,
      relay_urls: [],
      fallback_direct: true,
      auto_start_relay: true,
    },
  );
  const [relayText, setRelayText] = useState((initial?.relay_urls ?? []).join("\n"));
  const [health, setHealth] = useState<RelayHealthStatus[]>([]);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (initial) {
      setDraft(initial);
      setRelayText(initial.relay_urls.join("\n"));
    }
  }, [initial]);

  const refreshHealth = useCallback(async () => {
    try {
      setHealth(await api.whisperRelayHealth());
    } catch {
      setHealth([]);
    }
  }, []);

  useEffect(() => {
    if (draft.enabled) void refreshHealth();
  }, [draft.enabled, refreshHealth]);

  async function handleSave() {
    setBusy(true);
    try {
      const relay_urls = relayText
        .split("\n")
        .map((l) => l.trim())
        .filter(Boolean);
      if (draft.enabled && relay_urls.length === 0) {
        onToast("Add at least one relay URL.", "error");
        return;
      }
      const next: DustWhisperSettings = { ...draft, relay_urls, auto_start_relay: false };
      await api.updateDustWhisper(next);
      setDraft(next);
      onToast("DUST Whisper settings saved.", "success");
      await refreshHealth();
    } catch (e) {
      onToast(formatInvokeError(e), "error");
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <div className="card">
        <h2>DUST Whisper</h2>
        <p className="muted">
          Encrypted transaction broadcast and chat delivery via relay. A remote relay can hide your
          IP from the full node. The local relay encrypts transport but does not provide network
          anonymity.
        </p>
        <div className="toggle-row">
          <span>Enable Whisper</span>
          <input
            type="checkbox"
            checked={draft.enabled}
            onChange={(e) => setDraft((d) => ({ ...d, enabled: e.target.checked }))}
          />
        </div>
        <div className="toggle-row">
          <span>Fallback to direct node</span>
          <input
            type="checkbox"
            checked={draft.fallback_direct}
            onChange={(e) => setDraft((d) => ({ ...d, fallback_direct: e.target.checked }))}
          />
        </div>
        <label className="label">Relay URLs (one per line)</label>
        <textarea
          value={relayText}
          onChange={(e) => setRelayText(e.target.value)}
          placeholder={RELAY_PLACEHOLDER}
        />
        <button type="button" className="primary" disabled={busy} onClick={() => void handleSave()}>
          Save Whisper settings
        </button>
      </div>

      {draft.enabled && (
        <div className="card">
          <div className="toggle-row">
            <strong>Relay status</strong>
            <button type="button" className="small" onClick={() => void refreshHealth()}>
              Refresh
            </button>
          </div>
          {health.length === 0 ? (
            <p className="muted">No relay health data. check URLs.</p>
          ) : (
            health.map((h) => (
              <div key={h.url} className="list-item">
                <div>
                  <span className={h.online ? "badge badge-ok" : "badge badge-warn"}>
                    {h.online ? "Online" : "Offline"}
                  </span>{" "}
                  {h.url}
                </div>
                {h.error && <p className="muted">{h.error}</p>}
              </div>
            ))
          )}
        </div>
      )}
    </>
  );
}

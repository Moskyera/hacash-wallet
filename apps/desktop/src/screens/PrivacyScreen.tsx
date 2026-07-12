import { useEffect, useRef, useState } from "react";
import {
  DustWhisperSettings,
  PrivacySettings,
  RelayHealthStatus,
  WalletStatus,
} from "../api";
import { DEFAULT_DUST_WHISPER, DEFAULT_PRIVACY } from "../privacy";

type Props = {
  status: WalletStatus | null;
  dustWhisper: DustWhisperSettings;
  relayHealth: RelayHealthStatus[];
  busy: boolean;
  onSavePrivacy: (draft: PrivacySettings) => void;
  onSaveWhisper: (draft: DustWhisperSettings, relayText: string) => Promise<DustWhisperSettings | null>;
  onClearHistory: () => void;
};

export default function PrivacyScreen({
  status,
  dustWhisper,
  relayHealth,
  busy,
  onSavePrivacy,
  onSaveWhisper,
  onClearHistory,
}: Props) {
  const [privacyDraft, setPrivacyDraft] = useState<PrivacySettings>(DEFAULT_PRIVACY);
  const [whisperDraft, setWhisperDraft] = useState<DustWhisperSettings>(DEFAULT_DUST_WHISPER);
  const [whisperRelayText, setWhisperRelayText] = useState("");
  const syncedRef = useRef(false);

  // Sync drafts once when the tab mounts — not on status polls.
  useEffect(() => {
    if (syncedRef.current || !status) return;
    if (status.privacy) setPrivacyDraft(status.privacy);
    if (status.dust_whisper) {
      setWhisperDraft(status.dust_whisper);
      setWhisperRelayText(status.dust_whisper.relay_urls.join("\n"));
    }
    syncedRef.current = true;
  }, [status]);

  return (
    <section className="panel">
      <h2>Privacy</h2>
      <p className="muted">
        Control what appears on screen and what is stored locally. Keys stay encrypted —
        these settings reduce shoulder-surfing and local metadata exposure.
      </p>

      <label className="check-row">
        <input
          type="checkbox"
          checked={privacyDraft.hide_balances}
          onChange={(e) =>
            setPrivacyDraft((p) => ({ ...p, hide_balances: e.target.checked }))
          }
        />
        Hide balances
      </label>
      <label className="check-row">
        <input
          type="checkbox"
          checked={privacyDraft.hide_addresses}
          onChange={(e) =>
            setPrivacyDraft((p) => ({ ...p, hide_addresses: e.target.checked }))
          }
        />
        Hide addresses &amp; tx hashes
      </label>
      <label className="check-row">
        <input
          type="checkbox"
          checked={privacyDraft.screen_privacy}
          onChange={(e) =>
            setPrivacyDraft((p) => ({ ...p, screen_privacy: e.target.checked }))
          }
        />
        Screen privacy (blur when unfocused)
      </label>
      <label className="check-row">
        <input
          type="checkbox"
          checked={privacyDraft.store_tx_history}
          onChange={(e) =>
            setPrivacyDraft((p) => ({ ...p, store_tx_history: e.target.checked }))
          }
        />
        Store transaction history locally
      </label>
      <label className="check-row">
        <input
          type="checkbox"
          checked={privacyDraft.pause_auto_lock_dapp ?? true}
          onChange={(e) =>
            setPrivacyDraft((p) => ({ ...p, pause_auto_lock_dapp: e.target.checked }))
          }
        />
        Pause auto-lock during HACD session (hacd.it)
      </label>

      <label>Clipboard auto-clear (seconds, 0 = off)</label>
      <input
        type="number"
        min="0"
        max="300"
        value={privacyDraft.clipboard_clear_secs}
        onChange={(e) =>
          setPrivacyDraft((p) => ({
            ...p,
            clipboard_clear_secs: Math.max(0, Number(e.target.value)),
          }))
        }
      />

      <div className="actions-row">
        <button className="primary" disabled={busy} onClick={() => onSavePrivacy(privacyDraft)}>
          Save privacy settings
        </button>
        <button disabled={busy} onClick={onClearHistory}>
          Clear local history
        </button>
      </div>

      <hr className="divider" />

      <h3>DUST Whisper</h3>
      <p className="muted">
        Route signed transactions through an encrypted relay so the fullnode never sees your
        IP. Balance queries still use your node URL directly.
      </p>
      <label className="check-row">
        <input
          type="checkbox"
          checked={whisperDraft.enabled}
          onChange={(e) =>
            setWhisperDraft((w) => ({ ...w, enabled: e.target.checked }))
          }
        />
        Enable DUST Whisper for tx broadcast
      </label>
      <label className="check-row">
        <input
          type="checkbox"
          checked={whisperDraft.fallback_direct}
          onChange={(e) =>
            setWhisperDraft((w) => ({ ...w, fallback_direct: e.target.checked }))
          }
        />
        Fall back to direct node submit if relay fails
      </label>
      <label className="check-row">
        <input
          type="checkbox"
          checked={whisperDraft.auto_start_relay ?? true}
          onChange={(e) =>
            setWhisperDraft((w) => ({ ...w, auto_start_relay: e.target.checked }))
          }
        />
        Auto-start local relay when wallet opens (127.0.0.1 or localhost only)
      </label>
      {(whisperDraft.enabled || dustWhisper.enabled) && (
        <div className="relay-status-list">
          <strong>Relay status</strong>
          {(relayHealth.length > 0
            ? relayHealth
            : dustWhisper.relay_urls.map((url) => ({
                url,
                online: false,
                error: "Checking…",
                node_url: null,
                protocol_version: null,
              }))
          ).map((row) => (
            <div
              key={row.url}
              className={`relay-status-row ${row.online ? "online" : "offline"}`}
            >
              <span className={`relay-status-dot ${row.online ? "online" : "offline"}`} />
              <code>{row.url}</code>
              <span className="muted">
                {row.online
                  ? `online · node ${row.node_url ?? "n/a"}`
                  : row.error ?? "offline"}
              </span>
            </div>
          ))}
          {dustWhisper.relay_urls.length === 0 && (
            <p className="muted">Add a relay URL to see status.</p>
          )}
        </div>
      )}
      <label>Relay URLs (one per line)</label>
      <textarea
        className="textarea mono"
        rows={3}
        placeholder="http://127.0.0.1:8787"
        value={whisperRelayText}
        onChange={(e) => setWhisperRelayText(e.target.value)}
      />
      <div className="actions-row">
        <button
          className="primary"
          disabled={busy}
          onClick={() =>
            void onSaveWhisper(whisperDraft, whisperRelayText).then((next) => {
              if (next) {
                setWhisperDraft(next);
                setWhisperRelayText(next.relay_urls.join("\n"));
              }
            })
          }
        >
          Save DUST Whisper
        </button>
      </div>

      <div className="info-box">
        <strong>No cloud telemetry</strong> — node queries use your configured URL only.
        Air-gap and watch-only modes keep signing keys off the online device.
      </div>
    </section>
  );
}
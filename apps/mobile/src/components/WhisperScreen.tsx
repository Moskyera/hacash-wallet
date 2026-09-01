import { useCallback, useEffect, useState } from "react";
import { api, type DustWhisperSettings, type RelayHealthStatus } from "../api";
import { formatInvokeError } from "../formatInvokeError";

/**
 * What a relay URL looks like, in the two shapes a person is actually handed.
 *
 * It used to name an https host only, while the paragraph beside it tells the
 * reader to paste the plain http LAN address a friend's desktop wallet prints.
 * The example the field itself offers made the right answer look wrong.
 */
const RELAY_PLACEHOLDER = "http://192.168.1.24:8787";

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
        onToast(
          "Add at least one relay URL. Somebody has to run a relay, and it can be you: docs/RUNNING-A-RELAY.md.",
          "error",
        );
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
        <p className="muted">
          The encryption ends at the relay, not at the node. A relay decrypts each transaction in
          order to forward it, so whoever runs a remote relay sees the whole transaction: amounts,
          addresses, all of it. The node learns the relay instead of you, and the relay operator
          learns everything.
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
        <p className="muted small">
          This box is empty on a new wallet because there is no public relay to fill it with.
          Somebody has to run one, and it can be you, on a computer rather than on this phone:
          only the desktop wallet can host a relay. See <code>docs/RUNNING-A-RELAY.md</code>.
        </p>
        <p className="muted small">
          If the person you want to message is hosting on their computer, the address they give
          you is what goes in this box. It usually looks like{" "}
          <code>http://192.168.1.24:8787</code> rather than like a web address. You both have to
          be using the same relay: an envelope posted to one is only ever collected from that one.
          Whether their address reaches this phone at all depends on their network and not on this
          setting, which is section 0 of that guide.
        </p>
        <p className="muted small">
          If you put more than one address here, order matters and only in one direction. A
          message you send stops at the first relay in this list that accepts it, while checking
          for new mail tries all of them. So a relay that is not the one your correspondent uses,
          sitting above the one they do use, quietly swallows everything you send while their
          replies keep arriving.
        </p>
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

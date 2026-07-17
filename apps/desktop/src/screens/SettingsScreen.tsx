import { useEffect, useState } from "react";
import { api, type NodeDiscoveryReport, type WalletSettings } from "../api";
import AppUpdateSection from "../components/AppUpdateSection";

type Props = {
  settings: WalletSettings | null;
  busy: boolean;
  onSave: (nodeUrl: string, fallbackUrls: string[], autoFailover: boolean) => void;
  onInfo: (msg: string) => void;
  onError: (msg: string) => void;
};

export default function SettingsScreen({ settings, busy, onSave, onInfo, onError }: Props) {
  const [nodeUrl, setNodeUrl] = useState("");
  const [fallbackText, setFallbackText] = useState("");
  const [autoFailover, setAutoFailover] = useState(true);
  const [discovering, setDiscovering] = useState(false);
  const [discovery, setDiscovery] = useState<NodeDiscoveryReport | null>(null);

  useEffect(() => {
    if (!settings) return;
    setNodeUrl(settings.node_url);
    setFallbackText((settings.node_fallback_urls ?? []).join("\n"));
    setAutoFailover(settings.auto_node_failover ?? true);
  }, [settings]);

  const fallbackUrls = fallbackText
    .split(/\r?\n/)
    .map((value) => value.trim())
    .filter(Boolean);

  const findActiveNode = async () => {
    setDiscovering(true);
    try {
      const report = await api.discoverNodes();
      setDiscovery(report);
      if (report.switched) {
        setNodeUrl(report.active_node);
        onInfo(`Connected to ${report.active_node}`);
      } else if (
        report.candidates.some(
          (candidate) =>
            candidate.url === report.active_node && candidate.online && candidate.network_match,
        )
      ) {
        onInfo("The active node is healthy.");
      } else {
        onError("No compatible Hacash node was found in the configured list.");
      }
    } catch (error) {
      onError(String(error));
    } finally {
      setDiscovering(false);
    }
  };

  return (
    <section className="panel">
      <h2>Settings</h2>

      <AppUpdateSection onInfo={onInfo} onError={onError} />

      <hr className="divider" />

      <h3>Node</h3>
      <p className="muted">
        Network: <strong>{settings?.network_mode ?? "mainnet"}</strong>. Mainnet candidates are
        verified against the Hacash genesis chain before the wallet switches nodes.
      </p>
      <label>Node API URL</label>
      <input
        value={nodeUrl}
        onChange={(e) => setNodeUrl(e.target.value)}
        placeholder="http://nodeapi.hacash.org"
      />
      <label>Fallback node APIs (one per line)</label>
      <textarea
        className="textarea mono"
        rows={3}
        value={fallbackText}
        onChange={(event) => setFallbackText(event.target.value)}
        placeholder="http://your-node.example:8081"
      />
      <label className="check-row">
        <input
          type="checkbox"
          checked={autoFailover}
          onChange={(event) => setAutoFailover(event.target.checked)}
        />
        Automatically switch to a verified fallback node
      </label>
      <p className="muted small">
        The wallet checks only your saved list and the official mainnet fallback. Testnet mode
        never switches to a mainnet node.
      </p>
      <div className="actions-row">
        <button
          className="primary"
          disabled={busy}
          onClick={() => onSave(nodeUrl, fallbackUrls, autoFailover)}
        >
          Save node settings
        </button>
        <button disabled={busy || discovering} onClick={() => void findActiveNode()}>
          {discovering ? "Searching..." : "Find active node"}
        </button>
      </div>
      {discovery ? (
        <div className="relay-status-list">
          <strong>Node check</strong>
          {discovery.candidates.map((candidate) => (
            <div
              key={candidate.url}
              className={`relay-status-row ${candidate.online && candidate.network_match ? "online" : "offline"}`}
            >
              <span
                className={`relay-status-dot ${candidate.online && candidate.network_match ? "online" : "offline"}`}
              />
              <code>{candidate.url}</code>
              <span className="muted">
                {candidate.online
                  ? candidate.network_match
                    ? `ready, height ${candidate.height ?? "unknown"}`
                    : "wrong Hacash network"
                  : candidate.error ?? "offline"}
              </span>
            </div>
          ))}
        </div>
      ) : null}
    </section>
  );
}

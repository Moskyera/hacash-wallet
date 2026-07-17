import { useEffect, useMemo, useState } from "react";
import { api, type NodeDiscoveryReport, type WalletSettings } from "../api";
import AppUpdateSection from "../components/AppUpdateSection";
import { LanguageSwitcher, useLocale } from "../locale";

const OFFICIAL_NODE_URL = "http://nodeapi.hacash.org";

function normalizeNodeUrl(url: string): string {
  return url.trim().replace(/\/+$/, "").toLowerCase();
}

function isOfficialNode(url: string): boolean {
  const n = normalizeNodeUrl(url);
  return (
    n === "" ||
    n === normalizeNodeUrl(OFFICIAL_NODE_URL) ||
    n === "http://nodeapi.org" ||
    n === "https://nodeapi.hacash.org" ||
    n === "https://nodeapi.org" ||
    n === "nodeapi.hacash.org" ||
    n === "nodeapi.org"
  );
}

type Props = {
  settings: WalletSettings | null;
  busy: boolean;
  onSave: (nodeUrl: string, fallbackUrls: string[], autoFailover: boolean) => void;
  onInfo: (msg: string) => void;
  onError: (msg: string) => void;
};

export default function SettingsScreen({ settings, busy, onSave, onInfo, onError }: Props) {
  const { t } = useLocale();
  const [nodeUrl, setNodeUrl] = useState(OFFICIAL_NODE_URL);
  const [fallbackText, setFallbackText] = useState("");
  const [autoFailover, setAutoFailover] = useState(true);
  const [discovering, setDiscovering] = useState(false);
  const [discovery, setDiscovery] = useState<NodeDiscoveryReport | null>(null);
  const [showCustomNode, setShowCustomNode] = useState(false);

  useEffect(() => {
    if (!settings) return;
    setNodeUrl(settings.node_url);
    setFallbackText((settings.node_fallback_urls ?? []).join("\n"));
    setAutoFailover(settings.auto_node_failover ?? true);
    setShowCustomNode(!isOfficialNode(settings.node_url));
  }, [settings]);

  const activeIsOfficial = useMemo(() => isOfficialNode(nodeUrl), [nodeUrl]);

  const fallbackUrls = fallbackText
    .split(/\r?\n/)
    .map((value) => value.trim())
    .filter(Boolean);

  const applyOfficial = () => {
    setNodeUrl(OFFICIAL_NODE_URL);
    setShowCustomNode(false);
  };

  const findActiveNode = async () => {
    setDiscovering(true);
    try {
      const report = await api.discoverNodes();
      setDiscovery(report);
      setNodeUrl(report.active_node);
      if (!isOfficialNode(report.active_node)) setShowCustomNode(true);
      if (report.switched) {
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

      <div className="language-settings-block">
        <h3>{t("more.language")}</h3>
        <LanguageSwitcher />
      </div>

      <AppUpdateSection onInfo={onInfo} onError={onError} />

      <hr className="divider" />

      <h3>Node</h3>
      <p className="muted">
        Network: <strong>{settings?.network_mode ?? "mainnet"}</strong>. Mainnet candidates are
        verified against the Hacash genesis chain before the wallet switches nodes.
      </p>

      <label>{t("node.official")}</label>
      <p className="muted">
        {activeIsOfficial ? (
          <>
            {t("node.usingOfficial")} <code>{OFFICIAL_NODE_URL}</code>
          </>
        ) : (
          <>
            Active node: <code>{nodeUrl}</code>
          </>
        )}
      </p>

      {!showCustomNode ? (
        <div className="actions-row">
          <button type="button" disabled={busy} onClick={() => setShowCustomNode(true)}>
            {t("node.change")}
          </button>
          {!activeIsOfficial ? (
            <button type="button" className="primary" disabled={busy} onClick={applyOfficial}>
              {t("node.useOfficial")}
            </button>
          ) : null}
        </div>
      ) : (
        <>
          <p className="muted small">{t("node.customHint")}</p>
          <label>{t("node.customTitle")}</label>
          <input
            value={nodeUrl}
            onChange={(e) => setNodeUrl(e.target.value)}
            placeholder={OFFICIAL_NODE_URL}
          />
          <button type="button" disabled={busy} onClick={applyOfficial}>
            {t("node.useOfficial")}
          </button>
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
        </>
      )}

      <div className="actions-row">
        <button
          className="primary"
          disabled={busy}
          onClick={() =>
            onSave(
              showCustomNode ? nodeUrl : OFFICIAL_NODE_URL,
              showCustomNode ? fallbackUrls : (settings?.node_fallback_urls ?? []),
              showCustomNode ? autoFailover : (settings?.auto_node_failover ?? true),
            )
          }
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

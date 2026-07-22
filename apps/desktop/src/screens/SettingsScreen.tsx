import { OFFICIAL_NODE_URL, isOfficialNodeUrl } from "@hacash/wallet-ui";
import { useEffect, useMemo, useState } from "react";
import { api, type NodeDiscoveryReport, type WalletSettings } from "../api";
import AppUpdateSection from "../components/AppUpdateSection";
import { LanguageSwitcher, useLocale } from "../locale";

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
    setShowCustomNode(!isOfficialNodeUrl(settings.node_url));
  }, [settings]);

  const activeIsOfficial = useMemo(() => isOfficialNodeUrl(nodeUrl), [nodeUrl]);

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
      if (!isOfficialNodeUrl(report.active_node)) setShowCustomNode(true);
      if (report.switched) {
        onInfo(t("settings.connectedTo", { node: report.active_node }));
      } else if (
        report.candidates.some(
          (candidate) =>
            candidate.url === report.active_node && candidate.online && candidate.network_match,
        )
      ) {
        onInfo(t("settings.activeHealthy"));
      } else {
        onError(t("settings.noCompatibleNode"));
      }
    } catch (error) {
      onError(String(error));
    } finally {
      setDiscovering(false);
    }
  };

  return (
    <section className="panel">
      <h2>{t("settings.title")}</h2>

      <div className="language-settings-block">
        <h3>{t("more.language")}</h3>
        <LanguageSwitcher />
      </div>

      <AppUpdateSection onInfo={onInfo} onError={onError} />

      <hr className="divider" />

      <h3>{t("settings.network")}</h3>
      <p className="muted">
        {t("settings.desktopNetworkNotice", {
          network: settings?.network_mode ?? "mainnet",
        })}
      </p>

      <label>{t("node.official")}</label>
      <p className="muted">
        {activeIsOfficial ? (
          <>
            {t("node.usingOfficial")} <code>{OFFICIAL_NODE_URL}</code>
          </>
        ) : (
          <>
            {t("settings.activeNode")}: <code>{nodeUrl}</code>
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
          <label>{t("settings.fallbackNodes")}</label>
          <textarea
            className="textarea mono"
            rows={3}
            value={fallbackText}
            onChange={(event) => setFallbackText(event.target.value)}
            placeholder="https://your-node.example"
          />
          <label className="check-row">
            <input
              type="checkbox"
              checked={autoFailover}
              onChange={(event) => setAutoFailover(event.target.checked)}
            />
            {t("settings.autoFailover")}
          </label>
          <p className="muted small">
            {t("settings.testnetFailoverNotice")}
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
          {t("settings.saveNode")}
        </button>
        <button disabled={busy || discovering} onClick={() => void findActiveNode()}>
          {discovering ? t("settings.searching") : t("settings.findActive")}
        </button>
      </div>
      {discovery ? (
        <div className="relay-status-list">
          <strong>{t("settings.nodeCheck")}</strong>
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
                    ? t("settings.readyHeight", {
                        height: candidate.height ?? t("common.notAvailable"),
                      })
                    : t("settings.wrongNetwork")
                  : candidate.error ?? t("common.offline")}
              </span>
            </div>
          ))}
        </div>
      ) : null}
    </section>
  );
}

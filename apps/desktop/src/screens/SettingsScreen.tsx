import {
  HOW_IT_WORKS_URL,
  OFFICIAL_NODE_URL,
  isOfficialNodeUrl,
  mainnetSigningTransportIsEligible,
} from "@hacash/wallet-ui";
import { open } from "@tauri-apps/plugin-shell";
import { useEffect, useMemo, useState } from "react";
import { api, type NodeDiscoveryReport, type WalletSettings } from "../api";
import AppUpdateSection from "../components/AppUpdateSection";
import NodeSupervisorPanel from "../components/NodeSupervisorPanel";
import { formatInvokeError } from "../formatInvokeError";
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
  /**
   * Whether the node in this field can sign, judged the way the core judges it.
   *
   * `settings.officialHttpNotice` already existed and already said the truth.
   * On desktop it rendered nowhere at all, and on mobile only inside the
   * "Change node" branch, so it appeared only to somebody who had already
   * worked out that the node was the problem. The one person who needed it was
   * the one sitting on the default, reading "Using the official public node
   * API" next to a primary button offering "Use official node".
   */
  const nodeCanSign = useMemo(
    () => mainnetSigningTransportIsEligible(nodeUrl, settings?.network_mode ?? "mainnet"),
    [nodeUrl, settings?.network_mode],
  );

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
      // A working node was found and deliberately not adopted, because
      // adopting it would have left this wallet unable to sign on mainnet.
      // Declining silently was half the defect.
      if (report.failover_declined) {
        onError(report.failover_declined);
      } else if (report.switched) {
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

      <h3>{t("docs.howItWorks")}</h3>
      <p className="muted">{t("docs.howItWorksHint")}</p>
      <button
        type="button"
        onClick={() => {
          void open(HOW_IT_WORKS_URL).catch((error) => onError(formatInvokeError(error)));
        }}
      >
        {t("docs.howItWorks")}
      </button>

      <hr className="divider" />

      {/*
        Above the node URL box on purpose. The question "which node should I
        type in here" only exists because the wallet does not run one, so the
        offer to run one belongs before the box, not after it.
      */}
      <NodeSupervisorPanel onInfo={onInfo} onError={onError} />

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

      {!nodeCanSign ? (
        <p className="alert" role="note">
          {t("settings.officialHttpNotice")}
        </p>
      ) : null}

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

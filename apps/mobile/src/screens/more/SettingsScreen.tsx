import { useEffect, useMemo, useState } from "react";
import {
  api,
  type HubDiscoveryEntry,
  type HubHealth,
  type NodeDiscoveryReport,
  type WalletSettings,
  type WalletStatus,
} from "../../api";
import AppUpdateSection from "../../components/AppUpdateSection";
import HubDiscoveryPanel from "../../components/HubDiscoveryPanel";
import { formatInvokeError } from "../../formatInvokeError";
import { useLocale } from "../../locale";

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
  status: WalletStatus | null;
  settings: WalletSettings | null;
  hubHealth: HubHealth | null;
  busy: boolean;
  setBusy: (b: boolean) => void;
  onSave: (
    nodeUrl: string,
    hubUrl: string,
    fallbackUrls: string[],
    autoFailover: boolean,
  ) => void;
  onApplyHub: (entry: HubDiscoveryEntry) => Promise<void>;
  onToast: (msg: string, kind: "success" | "info" | "error") => void;
};

export default function SettingsScreen({
  status,
  settings,
  hubHealth,
  busy,
  setBusy,
  onSave,
  onApplyHub,
  onToast,
}: Props) {
  const { t } = useLocale();
  const [nodeUrl, setNodeUrl] = useState(settings?.node_url ?? OFFICIAL_NODE_URL);
  const [hubUrl, setHubUrl] = useState(settings?.l2_hub_url ?? "");
  const [fallbackText, setFallbackText] = useState(
    (settings?.node_fallback_urls ?? []).join("\n"),
  );
  const [autoFailover, setAutoFailover] = useState(settings?.auto_node_failover ?? true);
  const [nodeTestMsg, setNodeTestMsg] = useState<string | null>(null);
  const [discovery, setDiscovery] = useState<NodeDiscoveryReport | null>(null);
  const [showCustomNode, setShowCustomNode] = useState(
    () => !isOfficialNode(settings?.node_url ?? OFFICIAL_NODE_URL),
  );

  useEffect(() => {
    if (settings) {
      setNodeUrl(settings.node_url);
      setHubUrl(settings.l2_hub_url ?? "");
      setFallbackText((settings.node_fallback_urls ?? []).join("\n"));
      setAutoFailover(settings.auto_node_failover ?? true);
      setShowCustomNode(!isOfficialNode(settings.node_url));
    }
  }, [settings]);

  const activeIsOfficial = useMemo(
    () => isOfficialNode(status?.node_url ?? nodeUrl),
    [status?.node_url, nodeUrl],
  );

  const applyOfficial = () => {
    setNodeUrl(OFFICIAL_NODE_URL);
    setShowCustomNode(false);
    setNodeTestMsg(null);
  };

  return (
    <>
      <AppUpdateSection onToast={onToast} />
      <div className="card">
        <h2>Network</h2>
        <p className="muted small">
          Network: <strong>{settings?.network_mode ?? "mainnet"}</strong>
        </p>

        <label className="label">{t("node.official")}</label>
        <p className="muted">
          {activeIsOfficial ? (
            <>
              {t("node.usingOfficial")}{" "}
              <code>{OFFICIAL_NODE_URL}</code>
            </>
          ) : (
            <>
              Active node: <code>{status?.node_url ?? nodeUrl}</code>
            </>
          )}
        </p>

        {!showCustomNode ? (
          <div className="row-btns">
            <button type="button" className="small" disabled={busy} onClick={() => setShowCustomNode(true)}>
              {t("node.change")}
            </button>
            {!activeIsOfficial ? (
              <button type="button" className="small primary" disabled={busy} onClick={applyOfficial}>
                {t("node.useOfficial")}
              </button>
            ) : null}
          </div>
        ) : (
          <>
            <p className="muted small">{t("node.customHint")}</p>
            <label className="label">{t("node.customTitle")}</label>
            <input
              value={nodeUrl}
              onChange={(e) => setNodeUrl(e.target.value)}
              placeholder={OFFICIAL_NODE_URL}
              autoCapitalize="none"
              autoCorrect="off"
              spellCheck={false}
            />
            <p className="muted">
              Official Hacash node uses <strong>http://</strong> (not https). Tap Save after editing.
            </p>
            <button type="button" className="small" disabled={busy} onClick={applyOfficial}>
              {t("node.useOfficial")}
            </button>
            <label className="label">Fallback nodes (one per line)</label>
            <textarea
              rows={3}
              value={fallbackText}
              onChange={(event) => setFallbackText(event.target.value)}
              placeholder="http://your-node.example:8081"
              autoCapitalize="none"
              autoCorrect="off"
              spellCheck={false}
            />
            <label className="check-row">
              <input
                type="checkbox"
                checked={autoFailover}
                onChange={(event) => setAutoFailover(event.target.checked)}
              />
              Automatically switch to a verified fallback node
            </label>
          </>
        )}

        <label className="label">L2 Hub URL</label>
        <input
          value={hubUrl}
          onChange={(e) => setHubUrl(e.target.value)}
          placeholder="https://hub.example (optional)"
        />
        {hubHealth ? (
          <p className="muted">
            Hub: {hubHealth.ok ? "online" : "offline"}
            {hubHealth.hub_fee_mei != null ? ` · fee ${hubHealth.hub_fee_mei} HAC` : ""}
          </p>
        ) : null}
        <HubDiscoveryPanel
          settings={settings}
          activeHubUrl={hubUrl}
          busy={busy}
          setBusy={setBusy}
          onApplyHub={onApplyHub}
          onToast={onToast}
        />
        <div className="row-btns">
          <button
            type="button"
            className="primary"
            disabled={busy}
            onClick={() =>
              onSave(
                showCustomNode ? nodeUrl : OFFICIAL_NODE_URL,
                hubUrl,
                showCustomNode
                  ? fallbackText
                      .split(/\r?\n/)
                      .map((value) => value.trim())
                      .filter(Boolean)
                  : settings?.node_fallback_urls ?? [],
                showCustomNode ? autoFailover : (settings?.auto_node_failover ?? true),
              )
            }
          >
            Save settings
          </button>
          <button
            type="button"
            disabled={busy}
            onClick={() => {
              setNodeTestMsg(null);
              setBusy(true);
              void api
                .discoverNodes()
                .then((report) => {
                  setDiscovery(report);
                  setNodeUrl(report.active_node);
                  if (!isOfficialNode(report.active_node)) setShowCustomNode(true);
                  onToast(
                    report.switched ? `Connected to ${report.active_node}` : "Active node is healthy.",
                    "success",
                  );
                })
                .catch((error) => onToast(formatInvokeError(error), "error"))
                .finally(() => setBusy(false));
            }}
          >
            Find active node
          </button>
          <button
            type="button"
            disabled={busy}
            onClick={() => {
              setNodeTestMsg(null);
              setBusy(true);
              const pingUrl = showCustomNode ? nodeUrl.trim() : OFFICIAL_NODE_URL;
              void api
                .pingNodeUrl(pingUrl || undefined)
                .then((r) => {
                  setNodeTestMsg(`Node OK (${String(r.reachable ?? "true")})`);
                  onToast("Node connection OK.", "success");
                })
                .catch((e) => {
                  const msg = formatInvokeError(e);
                  setNodeTestMsg(msg);
                  onToast(msg, "error");
                })
                .finally(() => setBusy(false));
            }}
          >
            Test node
          </button>
        </div>
        {nodeTestMsg ? <p className="muted small">{nodeTestMsg}</p> : null}
        {discovery ? (
          <div className="relay-status-list">
            {discovery.candidates.map((candidate) => (
              <div
                key={candidate.url}
                className={`relay-status-row ${candidate.online && candidate.network_match ? "online" : "offline"}`}
              >
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
        <p className="muted small">
          If Test node fails: turn VPN off, try Wi‑Fi and mobile data, open{" "}
          <code>http://nodeapi.hacash.org/query/latest</code> in Chrome on the phone.
        </p>
        <p className="label" style={{ marginTop: "1rem" }}>
          {t("node.grapheneTitle")}
        </p>
        <p className="muted small">{t("node.grapheneHelp")}</p>
        <p className="muted small">
          Mobile DUST requires a remote relay configured for the same node. Changing the node does
          not reconfigure a relay that is operated by somebody else.
        </p>
      </div>
    </>
  );
}

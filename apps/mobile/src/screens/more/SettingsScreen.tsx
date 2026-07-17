import { useEffect, useState } from "react";
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
  const [nodeUrl, setNodeUrl] = useState(settings?.node_url ?? "");
  const [hubUrl, setHubUrl] = useState(settings?.l2_hub_url ?? "");
  const [fallbackText, setFallbackText] = useState(
    (settings?.node_fallback_urls ?? []).join("\n"),
  );
  const [autoFailover, setAutoFailover] = useState(settings?.auto_node_failover ?? true);
  const [nodeTestMsg, setNodeTestMsg] = useState<string | null>(null);
  const [discovery, setDiscovery] = useState<NodeDiscoveryReport | null>(null);

  useEffect(() => {
    if (settings) {
      setNodeUrl(settings.node_url);
      setHubUrl(settings.l2_hub_url ?? "");
      setFallbackText((settings.node_fallback_urls ?? []).join("\n"));
      setAutoFailover(settings.auto_node_failover ?? true);
    }
  }, [settings]);

  return (
    <>
      <AppUpdateSection onToast={onToast} />
      <div className="card">
        <h2>Network</h2>
        {status?.node_url ? (
          <p className="muted">
            Active node: <code>{status.node_url}</code>
          </p>
        ) : null}
        <label className="label">Node URL</label>
        <input
          value={nodeUrl}
          onChange={(e) => setNodeUrl(e.target.value)}
          placeholder="http://nodeapi.hacash.org"
          autoCapitalize="none"
          autoCorrect="off"
          spellCheck={false}
        />
        <p className="muted">
          Official Hacash node uses <strong>http://</strong> (not https). Tap Save after editing.
        </p>
        <button
          type="button"
          className="small"
          disabled={busy}
          onClick={() => setNodeUrl("http://nodeapi.hacash.org")}
        >
          Use official node
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
        <p className="muted small">
          Network: <strong>{settings?.network_mode ?? "mainnet"}</strong>. Mainnet nodes are checked
          against the Hacash genesis chain. Testnet never falls back to mainnet.
        </p>
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
                nodeUrl,
                hubUrl,
                fallbackText
                  .split(/\r?\n/)
                  .map((value) => value.trim())
                  .filter(Boolean),
                autoFailover,
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
              void api
                .pingNodeUrl(nodeUrl.trim() || undefined)
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
        <p className="muted small">
          Mobile DUST requires a remote relay configured for the same node. Changing the node does
          not reconfigure a relay that is operated by somebody else.
        </p>
      </div>
    </>
  );
}

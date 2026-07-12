import { useState } from "react";
import { api, type HubDiscoveryEntry, type HubDiscoveryReport, type WalletSettings } from "../api";
import { formatInvokeError } from "../formatInvokeError";

type Props = {
  settings: WalletSettings | null;
  activeHubUrl?: string;
  busy: boolean;
  setBusy: (b: boolean) => void;
  onApplyHub: (entry: HubDiscoveryEntry) => Promise<void>;
  onToast: (msg: string, kind: "success" | "info" | "error") => void;
};

export default function HubDiscoveryPanel({
  settings,
  activeHubUrl,
  busy,
  setBusy,
  onApplyHub,
  onToast,
}: Props) {
  const [report, setReport] = useState<HubDiscoveryReport | null>(null);
  const [scanning, setScanning] = useState(false);

  async function handleDiscover() {
    if (!settings) {
      onToast("Unlock wallet first.", "error");
      return;
    }
    setScanning(true);
    setReport(null);
    try {
      const next = await api.discoverHubs();
      setReport(next);
      if (next.online_count === 0) {
        onToast("No online hubs found.", "info");
      } else {
        onToast(`${next.online_count} online hub(s) found.`, "success");
      }
    } catch (e) {
      onToast(formatInvokeError(e), "error");
    } finally {
      setScanning(false);
    }
  }

  async function handleUse(entry: HubDiscoveryEntry) {
    if (!entry.online) return;
    setBusy(true);
    try {
      await onApplyHub(entry);
    } catch (e) {
      onToast(formatInvokeError(e), "error");
    } finally {
      setBusy(false);
    }
  }

  const normalizedActive = activeHubUrl?.trim().replace(/\/$/, "") ?? "";

  return (
    <div className="hub-discovery">
      <button
        type="button"
        className="primary"
        style={{ width: "100%" }}
        disabled={busy || scanning || !settings}
        onClick={() => void handleDiscover()}
      >
        {scanning ? "Scanning…" : "Discover hubs"}
      </button>
      <p className="muted small" style={{ marginTop: "0.5rem" }}>
        Scans known Fast Pay providers and your configured hub URL.
      </p>
      {report && (
        <div className="hub-discovery-list">
          {report.hubs.map((hub) => {
            const isActive = normalizedActive !== "" && hub.hub_url === normalizedActive;
            return (
              <div key={`${hub.id}:${hub.hub_url}`} className="hub-discovery-item">
                <div className="hub-discovery-head">
                  <strong>{hub.name}</strong>
                  <span className={hub.online ? "badge badge-ok" : "badge badge-warn"}>
                    {hub.online ? "online" : "offline"}
                  </span>
                </div>
                <p className="muted small hub-discovery-url">{hub.hub_url}</p>
                {hub.online && hub.hub_fee_mei != null && (
                  <p className="muted small">Fee ~{hub.hub_fee_mei} HAC per pay</p>
                )}
                {!hub.online && hub.error && (
                  <p className="muted small">{hub.error}</p>
                )}
                {hub.online && (
                  <button
                    type="button"
                    className={isActive ? undefined : "primary"}
                    disabled={busy || isActive}
                    onClick={() => void handleUse(hub)}
                  >
                    {isActive ? "In use" : "Use this hub"}
                  </button>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
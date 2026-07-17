import { useEffect, useState } from "react";
import {
  ChannelInfo,
  ChannelSetupPreview,
  HubDiscoveryEntry,
  HubHealth,
  WalletSettings,
  WalletStatus,
} from "../api";
import BillsPanel from "../components/BillsPanel";
import HubDiscoveryPanel from "../components/HubDiscoveryPanel";
import {
  fastPayStatusHeadline,
  fastPayStatusTitle,
  type FastPayStatus,
} from "../fastPayUi";
import type { Screen } from "./types";

type Props = {
  status: WalletStatus | null;
  settings: WalletSettings | null;
  fastPayDetail: FastPayStatus | null;
  channelInfo: ChannelInfo | null;
  hubHealth: HubHealth | null | undefined;
  billsCount: number;
  fastPayReady: boolean;
  fastPayNeedsSetup: boolean;
  hideAddresses: boolean;
  busy: boolean;
  setBusy: (b: boolean) => void;
  onNavigate: (screen: Screen) => void;
  onEnableFastPay: (userDeposit: string) => void;
  onApplyHub: (entry: HubDiscoveryEntry) => Promise<void>;
  onSaveL2Settings: (nodeUrl: string, hubUrl: string, hubAddress: string) => void;
  onHubHealth: () => void;
  onPreviewChannel: (
    hubAddress: string,
    userDeposit: string,
    hubDeposit: string,
    setChannelPreview: (p: ChannelSetupPreview | null) => void,
  ) => void;
  onOpenChannel: (
    hubAddress: string,
    userDeposit: string,
    hubDeposit: string,
    setChannelPreview: (p: ChannelSetupPreview | null) => void,
  ) => void;
  onCloseChannel: (setChannelPreview: (p: ChannelSetupPreview | null) => void) => void;
  onNotify: (msg: string, kind: "error" | "info" | "success") => void;
  clearMessages: () => void;
};

export default function FastPayScreen({
  status,
  settings,
  fastPayDetail,
  channelInfo,
  hubHealth,
  billsCount,
  fastPayReady,
  fastPayNeedsSetup,
  hideAddresses,
  busy,
  setBusy,
  onNavigate,
  onEnableFastPay,
  onApplyHub,
  onSaveL2Settings,
  onHubHealth,
  onPreviewChannel,
  onOpenChannel,
  onCloseChannel,
  onNotify,
  clearMessages,
}: Props) {
  const [userDeposit, setUserDeposit] = useState("10");
  const [hubDeposit, setHubDeposit] = useState("0");
  const [nodeUrl, setNodeUrl] = useState("");
  const [hubUrl, setHubUrl] = useState("");
  const [hubAddress, setHubAddress] = useState("");
  const [channelPreview, setChannelPreview] = useState<ChannelSetupPreview | null>(null);
  const [showFastPayAdvanced, setShowFastPayAdvanced] = useState(false);

  useEffect(() => {
    if (!settings) return;
    setNodeUrl(settings.node_url);
    setHubUrl(settings.l2_hub_url ?? "");
    setHubAddress(settings.hub_right_address ?? "");
  }, [settings?.node_url, settings?.l2_hub_url, settings?.hub_right_address, settings]);

  return (
    <section className="panel">
      <h2>Fast Pay</h2>
      <p className="muted">
        Instant fee-free payments on the Hacash payment network. Check this tab to see whether
        your sends will be Fast Pay or on-chain.
      </p>

      <div className={`fp-status-banner ${fastPayReady ? "fp-status-on" : "fp-status-off"}`}>
        <div className="fp-status-pill">{fastPayReady ? "ON" : "OFF"}</div>
        <div>
          <h3>{fastPayStatusTitle(status?.fast_pay_state ?? "no_provider")}</h3>
          <p>
            {fastPayDetail?.message ??
              status?.fast_pay_message ??
              fastPayStatusHeadline(status?.fast_pay_state ?? "no_provider")}
          </p>
        </div>
      </div>

      <div className="fp-route-hint">
        <strong>When you tap Send:</strong>{" "}
        {fastPayReady
          ? "payments go via Fast Pay (instant)."
          : "payments go on-chain (standard, few minutes)."}
      </div>

      {(fastPayNeedsSetup || fastPayDetail?.can_enable) && !status?.watch_only && (
        <div className="fast-pay-card">
          <h3>Turn Fast Pay ON</h3>
          <p className="muted">One-time setup. Deposit stays in your channel until you close it.</p>
          <label>Your channel deposit (HAC)</label>
          <input
            value={userDeposit}
            onChange={(e) => setUserDeposit(e.target.value)}
            type="number"
            min="1"
            step="1"
          />
          <button className="primary" disabled={busy} onClick={() => onEnableFastPay(userDeposit)}>
            Enable Fast Pay
          </button>
        </div>
      )}

      {fastPayReady && (
        <div className="success-box">
          <p>
            Provider: <strong>{fastPayDetail?.provider_name ?? "connected"}</strong>
            {status?.channel_id && (
              <>
                {" "}
                · Channel active · {billsCount} bill{billsCount === 1 ? "" : "s"} backed up
              </>
            )}
          </p>
          <button className="primary" onClick={() => onNavigate("send")}>
            Go to Send
          </button>
        </div>
      )}

      <div className="fp-how-it-works">
        <h3>How it works</h3>
        <ul>
          <li>
            <strong>Fast Pay ON:</strong> Send tab uses instant routing with no Fast Pay fee.
          </li>
          <li>
            <strong>Fast Pay OFF:</strong> Send tab uses on-chain (dynamic L1 fee from node).
          </li>
          <li>You always see which route is used before you confirm a payment.</li>
        </ul>
      </div>

      <div className="fast-pay-card">
        <h3>Find a hub</h3>
        <p className="muted small">
          Scan for online Fast Pay providers, then pick one to use.
        </p>
        <HubDiscoveryPanel
          settings={settings}
          activeHubUrl={hubUrl}
          busy={busy}
          setBusy={setBusy}
          onApplyHub={onApplyHub}
          onToast={(msg, kind) => {
            clearMessages();
            onNotify(msg, kind);
          }}
        />
      </div>

      <BillsPanel
        hideAddresses={hideAddresses}
        onError={(msg) => onNotify(msg, "error")}
        onInfo={(msg) => onNotify(msg, "info")}
      />

      <button
        type="button"
        className="collapse-toggle"
        onClick={() => setShowFastPayAdvanced((v) => !v)}
      >
        {showFastPayAdvanced ? "▾" : "▸"} Technical settings (advanced)
      </button>
      {showFastPayAdvanced && (
        <>
          <label>Node API URL</label>
          <input
            value={nodeUrl}
            onChange={(e) => setNodeUrl(e.target.value)}
            placeholder="https://node.example.com"
          />
          <label>Hub API URL</label>
          <input
            value={hubUrl}
            onChange={(e) => setHubUrl(e.target.value)}
            placeholder="https://hub.example.com"
          />
          <div className="actions-row">
            <button disabled={busy} onClick={() => onSaveL2Settings(nodeUrl, hubUrl, hubAddress)}>
              Save settings
            </button>
            <button disabled={busy || !hubUrl.trim()} onClick={onHubHealth}>
              Hub health check
            </button>
          </div>
          {hubHealth !== undefined && (
            <div className={hubHealth?.ok ? "success-box" : "alert"}>
              {hubHealth === null && "Hub unreachable or misconfigured."}
              {hubHealth && hubHealth.ok && (
                <>
                  Hub OK. <strong>{hubHealth.name ?? "hub"}</strong> (protocol v
                  {hubHealth.version})
                </>
              )}
              {hubHealth && !hubHealth.ok && "Hub returned unhealthy status."}
            </div>
          )}
          <hr className="divider" />
          <h3>Payment channel (L1)</h3>
          <label>Provider address (hub)</label>
          <input
            value={hubAddress}
            onChange={(e) => setHubAddress(e.target.value)}
            placeholder="1Hub..."
          />
          <div className="two-col">
            <div>
              <label>Your deposit (HAC)</label>
              <input
                value={userDeposit}
                onChange={(e) => setUserDeposit(e.target.value)}
                type="number"
                min="0"
              />
            </div>
            <div>
              <label>Hub deposit (HAC)</label>
              <input
                value={hubDeposit}
                onChange={(e) => setHubDeposit(e.target.value)}
                type="number"
                min="0"
              />
            </div>
          </div>
          <div className="actions-row">
            <button
              disabled={busy || !hubAddress}
              onClick={() => onPreviewChannel(hubAddress, userDeposit, hubDeposit, setChannelPreview)}
            >
              Preview channel
            </button>
            <button
              className="primary"
              disabled={busy || !channelPreview}
              onClick={() => onOpenChannel(hubAddress, userDeposit, hubDeposit, setChannelPreview)}
            >
              Sign & open channel
            </button>
            <button
              disabled={busy || !status?.channel_id}
              onClick={() => onCloseChannel(setChannelPreview)}
            >
              Close channel
            </button>
          </div>
          {channelPreview && (
            <div className="preview-card">
              <p>
                <strong>Channel ID:</strong> <code>{channelPreview.channel_id}</code>
              </p>
            </div>
          )}
          {status?.channel_id && channelInfo && (
            <p className="muted">
              Channel {channelInfo.status} · Left {channelInfo.left.hacash} · Right{" "}
              {channelInfo.right.hacash}
            </p>
          )}
        </>
      )}
    </section>
  );
}

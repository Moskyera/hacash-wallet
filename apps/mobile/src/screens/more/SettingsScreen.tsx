import {
  HOW_IT_WORKS_URL,
  IstanbulSafetyPanel,
  OFFICIAL_NODE_URL,
  isOfficialNodeUrl,
  mainnetSigningTransportIsEligible,
} from "@hacash/wallet-ui";
import { openUrl } from "@tauri-apps/plugin-opener";
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
import NodeSyncSection from "../../components/NodeSyncSection";
import { formatInvokeError } from "../../formatInvokeError";
import { useLocale } from "../../locale";

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
  const [currentHubHealth, setCurrentHubHealth] = useState<HubHealth | null>(hubHealth);
  const [showCustomNode, setShowCustomNode] = useState(
    () => !isOfficialNodeUrl(settings?.node_url ?? OFFICIAL_NODE_URL),
  );

  useEffect(() => {
    if (settings) {
      setNodeUrl(settings.node_url);
      setHubUrl(settings.l2_hub_url ?? "");
      setFallbackText((settings.node_fallback_urls ?? []).join("\n"));
      setAutoFailover(settings.auto_node_failover ?? true);
      setShowCustomNode(!isOfficialNodeUrl(settings.node_url));
    }
  }, [settings]);

  useEffect(() => {
    setCurrentHubHealth(hubHealth);
  }, [hubHealth]);

  useEffect(() => {
    if (!settings?.l2_hub_url) {
      setCurrentHubHealth(null);
      return;
    }
    let active = true;
    void api
      .hubHealth()
      .then((health) => {
        if (active) setCurrentHubHealth(health);
      })
      .catch(() => {
        if (active) setCurrentHubHealth(null);
      });
    return () => {
      active = false;
    };
  }, [settings?.l2_hub_url]);

  const activeIsOfficial = useMemo(
    () => isOfficialNodeUrl(status?.node_url ?? nodeUrl),
    [status?.node_url, nodeUrl],
  );

  /**
   * Whether this node can carry everything, judged the way the core judges it.
   *
   * Deliberately the STRICT rule and not the payment rule. An ordinary payment
   * goes through the official node now, but Fast Pay setup and channel closes
   * do not, and the notice this gates says both halves. Keying it off the
   * payment rule would hide the sentence that explains the next refusal.
   */
  const nodeCanSign = useMemo(
    () =>
      mainnetSigningTransportIsEligible(
        status?.node_url ?? nodeUrl,
        settings?.network_mode ?? "mainnet",
      ),
    [status?.node_url, nodeUrl, settings?.network_mode],
  );

  const applyOfficial = () => {
    setNodeUrl(OFFICIAL_NODE_URL);
    setShowCustomNode(false);
    setNodeTestMsg(null);
  };

  return (
    <>
      <AppUpdateSection onToast={onToast} />
      <IstanbulSafetyPanel
        commands={api}
        networkMode={settings?.network_mode ?? status?.network_mode ?? "mainnet"}
        currentAddress={status?.address}
        containerClassName="card"
        formatError={formatInvokeError}
      />
      {/* Every build ships the same file name and the same version name, so without
          this a field report cannot distinguish an unchanged app from an old file
          having been installed. It cost a round of confusion to learn that. */}
      <div className="card">
        <h2>{t("settings.buildId")}</h2>
        <p className="muted small">{t("settings.buildIdHint")}</p>
        <code className="mono wrap">{__BUILD_ID__}</code>
      </div>
      <div className="card">
        <h2>{t("docs.howItWorks")}</h2>
        <p className="muted small">{t("docs.howItWorksHint")}</p>
        <button
          type="button"
          onClick={() => {
            void openUrl(HOW_IT_WORKS_URL).catch((error) =>
              onToast(formatInvokeError(error), "error"),
            );
          }}
        >
          {t("docs.howItWorks")}
        </button>
      </div>
      <div className="card">
        <h2>{t("settings.network")}</h2>
        <p className="muted small">
          {t("settings.networkValue", { network: settings?.network_mode ?? "mainnet" })}
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
              {t("settings.activeNode")}: <code>{status?.node_url ?? nodeUrl}</code>
            </>
          )}
        </p>

        {/*
          WHICH CHAIN, HOW FAR ALONG, HOW MUCH LONGER, in that order.

          It sits directly under the node this wallet is pointed at because the
          first of those three questions is the one that decides whether the
          other two are worth waiting on, and a person who is reading a node URL
          is exactly the person who needs it. There is no spinner here on
          purpose: a node catching up and a node on a private chain of its own
          both climb, and a spinner turns the same way for both.
        */}
        <NodeSyncSection />

        {/*
          Said to the person sitting on the default, not only to the person who
          already worked out that the node was the thing to look at.

          This notice used to render only inside the "Change node" branch
          below, which is the branch somebody reaches after diagnosing the
          problem. The one reader who needed it was the one who had pressed
          nothing.
        */}
        {!nodeCanSign ? (
          <p className="muted small" role="note">
            {t("settings.officialHttpNotice")}
          </p>
        ) : null}

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
            <button type="button" className="small" disabled={busy} onClick={applyOfficial}>
              {t("node.useOfficial")}
            </button>
            <label className="label">{t("settings.fallbackNodes")}</label>
            <textarea
              rows={3}
              value={fallbackText}
              onChange={(event) => setFallbackText(event.target.value)}
              placeholder="https://your-node.example"
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
              {t("settings.autoFailover")}
            </label>
          </>
        )}

        <label className="label">{t("settings.l2HubUrl")}</label>
        <input
          value={hubUrl}
          onChange={(e) => setHubUrl(e.target.value)}
          placeholder={t("settings.optionalHubPlaceholder")}
        />
        {currentHubHealth ? (
          <p className="muted">
            {t("settings.hubStatus", {
              status: t(currentHubHealth.ok ? "common.online" : "common.offline"),
              fee: currentHubHealth.hub_fee_mei ?? t("common.notAvailable"),
            })}
          </p>
        ) : null}
        <HubDiscoveryPanel
          settings={settings}
          activeHubUrl={hubUrl}
          busy={busy}
          setBusy={setBusy}
          onApplyHub={onApplyHub}
          onHubUrlChange={setHubUrl}
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
            {t("settings.save")}
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
                  if (!isOfficialNodeUrl(report.active_node)) setShowCustomNode(true);
                  // A working node was found and deliberately not adopted,
                  // because adopting it would have left this wallet unable to
                  // sign on mainnet. Declining silently was half the defect.
                  if (report.failover_declined) {
                    onToast(report.failover_declined, "error");
                  } else {
                    onToast(
                      report.switched
                        ? t("settings.connectedTo", { node: report.active_node })
                        : t("settings.activeHealthy"),
                      "success",
                    );
                  }
                })
                .catch((error) => onToast(formatInvokeError(error), "error"))
                .finally(() => setBusy(false));
            }}
          >
            {t("settings.findActive")}
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
                  setNodeTestMsg(t("settings.nodeOk", { reachable: String(r.reachable ?? true) }));
                  onToast(t("settings.nodeConnectionOk"), "success");
                })
                .catch((e) => {
                  const msg = formatInvokeError(e);
                  setNodeTestMsg(msg);
                  onToast(msg, "error");
                })
                .finally(() => setBusy(false));
            }}
          >
            {t("settings.testNode")}
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
        <p className="muted small">
          {t("settings.testHint")} <code>http://nodeapi.hacash.org/query/latest</code>
        </p>
        <p className="label" style={{ marginTop: "1rem" }}>
          {t("node.grapheneTitle")}
        </p>
        <p className="muted small">{t("node.grapheneHelp")}</p>
        <p className="muted small">
          {t("settings.dustRelayNotice")}
        </p>
      </div>
    </>
  );
}

import { useEffect, useRef, useState } from "react";
import {
  api,
  ChannelInfo,
  ChannelSetupPreview,
  FastPayInboxItem,
  HubDiscoveryEntry,
  HubHealth,
  NativeRailPreflight,
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
import { open } from "@tauri-apps/plugin-shell";
import {
  FAST_PAY_MAINNET_CEILINGS,
  FAST_PAY_MAINNET_CONSENT,
  MAINNET_SIGNING_TRANSPORT_NOTICE,
  NativeRailPreflightCard,
  mainnetSigningTransportIsEligible,
  preflightShowsPass,
} from "@hacash/wallet-ui";

/**
 * What the bounded pilot consent block's own submit control should do.
 *
 * Pulled out as a function so the rule can be tested without a DOM. The
 * ceremony had no submit control at all: the consent text, the checkbox and
 * the passphrase field rendered here while the only caller of
 * onSaveL2Settings sat inside the collapsed "Technical settings (advanced)"
 * section, which renders nothing until it is expanded.
 *
 * The asymmetry is deliberate and matches the core. GRANTING consent chooses
 * the settlement model every later mainnet payment is judged under, so it
 * needs the passphrase and goes through the authenticated consent command.
 * WITHDRAWING is a tightening and needs nothing.
 */
export function consentSubmitState(
  ticked: boolean,
  saved: boolean,
  passphrase: string,
  busy: boolean,
) {
  const granting = ticked && !saved;
  return {
    // Nothing to submit while the tick already matches what is saved.
    visible: ticked !== saved,
    needsPassphrase: granting,
    disabled: busy || (granting && passphrase.length === 0),
    label: ticked ? "Confirm this choice" : "Withdraw consent",
  };
}

/**
 * The payment the preflight judges the Hub's per-payment cap against.
 *
 * 0.1 HAC, which is the single payment this bounded pilot is sized for. It is
 * a fixed number rather than a field because the cap question is "will this
 * Hub take the payment I am about to make", and inventing a larger one here
 * would produce a red item for a payment nobody intends to send.
 */
const FAST_PAY_PREFLIGHT_PAYMENT_HAC = "0.1";

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
  onSaveL2Settings: (
    nodeUrl: string,
    hubUrl: string,
    hubAddress: string,
    trustedMainnetFastPayPilot: boolean,
    currentPassphrase: string,
  ) => void;
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
  onRefresh: () => Promise<void>;
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
  onRefresh,
  onNotify,
  clearMessages,
}: Props) {
  const [userDeposit, setUserDeposit] = useState("10");
  const [hubDeposit, setHubDeposit] = useState("0");
  const [nodeUrl, setNodeUrl] = useState("");
  const [hubUrl, setHubUrl] = useState("");
  const [hubAddress, setHubAddress] = useState("");
  const [trustedMainnetPilot, setTrustedMainnetPilot] = useState(false);
  // Turning the pilot on is an authenticated change, so the screen has to be
  // able to ask for the passphrase. Turning it off needs nothing.
  const [mainnetPilotPassphrase, setMainnetPilotPassphrase] = useState("");
  const [channelPreview, setChannelPreview] = useState<ChannelSetupPreview | null>(null);
  const [preflight, setPreflight] = useState<NativeRailPreflight | null>(null);
  const [preflightRunning, setPreflightRunning] = useState(false);
  const [showFastPayAdvanced, setShowFastPayAdvanced] = useState(false);
  const [inbox, setInbox] = useState<FastPayInboxItem[]>([]);
  const inboxRequestRef = useRef<Promise<void> | null>(null);
  useEffect(() => {
    const recommended = fastPayDetail?.default_deposit_mei;
    if (recommended != null && Number.isFinite(recommended) && recommended > 0) {
      setUserDeposit(String(recommended));
    }
  }, [fastPayDetail?.default_deposit_mei]);

  useEffect(() => {
    if (!fastPayReady || status?.locked) {
      setInbox([]);
      return;
    }
    let cancelled = false;
    const load = (): Promise<void> => {
      if (inboxRequestRef.current) return inboxRequestRef.current;
      const request = (async () => {
        try {
          const items = await api.fastPayInbox();
          if (!cancelled) setInbox(items);
        } catch {
          if (!cancelled) setInbox([]);
        }
      })().finally(() => {
        if (inboxRequestRef.current === request) inboxRequestRef.current = null;
      });
      inboxRequestRef.current = request;
      return request;
    };
    void load();
    const timer = window.setInterval(() => void load(), 5000);
    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, [fastPayReady, status?.locked, status?.address]);

  const acceptIncoming = async (item: FastPayInboxItem) => {
    setBusy(true);
    clearMessages();
    try {
      const result = await api.acceptFastPay(item.payment_id);
      setInbox((current) => current.filter((entry) => entry.payment_id !== item.payment_id));
      onNotify(result.summary, "success");
      await onRefresh();
    } catch (error) {
      onNotify(String(error), "error");
    } finally {
      setBusy(false);
    }
  };

  const finishPendingOpen = async () => {
    setBusy(true);
    clearMessages();
    try {
      const result = await api.recoverChannelOpen();
      onNotify(result, "success");
      await onRefresh();
    } catch (error) {
      onNotify(String(error), "error");
    } finally {
      setBusy(false);
    }
  };

  const finishPendingClose = async () => {
    setBusy(true);
    clearMessages();
    try {
      const result = await api.recoverChannelClose();
      onNotify(result, "success");
      await onRefresh();
    } catch (error) {
      onNotify(String(error), "error");
    } finally {
      setBusy(false);
    }
  };
  useEffect(() => {
    if (!settings) return;
    setNodeUrl(settings.node_url);
    setHubUrl(settings.l2_hub_url ?? "");
    setHubAddress(settings.hub_right_address ?? "");
    setTrustedMainnetPilot(settings.trusted_mainnet_fast_pay_pilot);
  }, [
    settings?.node_url,
    settings?.l2_hub_url,
    settings?.hub_right_address,
    settings?.trusted_mainnet_fast_pay_pilot,
    settings,
  ]);

  // Mirrors validate_signing_node_url. Used only to SAY the rule on screen
  // before the ceremony; the core still enforces it at prepare and at signing.
  const signingTransportEligible = mainnetSigningTransportIsEligible(
    settings?.node_url,
    settings?.network_mode,
  );
  const providerAddressChosen = Boolean(settings?.hub_right_address?.trim());
  /**
   * Run the read-only preflight for the values on this screen.
   *
   * It sends the deposit the person has actually typed and a payment sized to
   * the deposit, so the Hub's declared caps are judged against the real
   * numbers rather than against a placeholder. Nothing is saved and nothing is
   * signed.
   */
  const runPreflight = async () => {
    setPreflightRunning(true);
    clearMessages();
    try {
      setPreflight(
        await api.nativeRailPreflight({
          nodeUrl: settings?.node_url,
          hubUrl,
          hubAddress: settings?.hub_right_address ?? hubAddress,
          ownerAddress: status?.address ?? undefined,
          channelDepositHac: userDeposit,
          paymentHac: FAST_PAY_PREFLIGHT_PAYMENT_HAC,
        }),
      );
    } catch (error) {
      setPreflight(null);
      onNotify(String(error), "error");
    } finally {
      setPreflightRunning(false);
    }
  };

  const consentSubmit = consentSubmitState(
    trustedMainnetPilot,
    settings?.trusted_mainnet_fast_pay_pilot ?? false,
    mainnetPilotPassphrase,
    busy,
  );

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

      {settings?.network_mode === "mainnet" && (
        <div className="alert" role="note">
          <strong>Bounded mainnet pilot</strong>
          <p>{FAST_PAY_MAINNET_CEILINGS}</p>
          <label>
            <input
              type="checkbox"
              checked={trustedMainnetPilot}
              onChange={(event) => setTrustedMainnetPilot(event.target.checked)}
            />
            {FAST_PAY_MAINNET_CONSENT}
          </label>
          {consentSubmit.needsPassphrase && (
            <>
              <label htmlFor="mainnet-pilot-passphrase">
                Wallet passphrase, to confirm this choice
              </label>
              <input
                id="mainnet-pilot-passphrase"
                type="password"
                autoComplete="current-password"
                value={mainnetPilotPassphrase}
                onChange={(event) => setMainnetPilotPassphrase(event.target.value)}
              />
            </>
          )}
          {/*
            The ceremony's own submit control.

            The consent text, the checkbox and the passphrase field all render
            here, and the only button that submitted them lived inside the
            collapsed "Technical settings (advanced)" section further down. So
            a person read the consent, ticked the box, typed their wallet
            passphrase, and there was no control on screen that did anything
            with it.

            No gate moves. This calls the same onSaveL2Settings path the
            advanced Save settings button calls, which still refuses to grant
            consent without a passphrase and still routes granting through the
            authenticated api.setMainnetFastPayConsent rather than
            wallet_update_settings. The advanced button stays exactly as it is.
          */}
          {consentSubmit.visible && (
            <button
              type="button"
              className="primary"
              disabled={consentSubmit.disabled}
              onClick={() =>
                // Consent only. Every other argument is the value already
                // saved, so this ceremony cannot carry a half-typed node or
                // hub URL along with it and cannot fail for a reason that has
                // nothing to do with consent. The advanced Save settings
                // button remains the place that submits the form.
                onSaveL2Settings(
                  settings?.node_url ?? "",
                  settings?.l2_hub_url ?? "",
                  settings?.hub_right_address ?? "",
                  trustedMainnetPilot,
                  mainnetPilotPassphrase,
                )
              }
            >
              {consentSubmit.label}
            </button>
          )}
        </div>
      )}

      {!signingTransportEligible && (
        <div className="alert" role="note">
          <strong>This node cannot sign on mainnet</strong>
          <p>{MAINNET_SIGNING_TRANSPORT_NOTICE}</p>
          <p className="small">
            Current node: <code>{settings?.node_url}</code>
          </p>
        </div>
      )}

      <div className="fast-pay-card">
        <h3>Find a hub</h3>
        <HubDiscoveryPanel
          settings={settings}
          activeHubUrl={hubUrl}
          busy={busy}
          setBusy={setBusy}
          onApplyHub={onApplyHub}
          onHubUrlChange={setHubUrl}
          openExternal={(url) => open(url)}
          onToast={(msg, kind) => {
            clearMessages();
            onNotify(msg, kind);
          }}
        />
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
            min="0.001"
            step="0.001"
          />
          {/*
            can_enable is set from the discovery branch of evaluate_fast_pay,
            which has no hub address in hand, so the button could be offered
            when handleEnableFastPay was guaranteed to throw "Choose an online
            Fast Pay provider first." Say the missing step instead of throwing
            it. This tightens what the button claims; it removes no check, and
            hub_right_address is still required and still re-verified against
            the live Hub at funding time.
          */}
          <NativeRailPreflightCard
            report={preflight}
            running={preflightRunning}
            disabled={busy}
            onRun={() => void runPreflight()}
          />
          <button
            className="primary"
            disabled={busy || !providerAddressChosen || !signingTransportEligible}
            onClick={() => onEnableFastPay(userDeposit)}
          >
            Enable Fast Pay
          </button>
          {/*
            The button is NOT disabled on a red preflight. The preflight is a
            read-only opinion about the infrastructure, not a gate, and every
            gate it previews runs again for real inside enable and inside the
            channel open. Wiring the button to it would swap a real refusal
            with a reason for a greyed-out control with none. Saying it plainly
            is the honest half.
          */}
          {preflight && !preflightShowsPass(preflight.checks) && (
            <p className="small">
              The check above is not green. You can still continue, and the same
              gates will refuse you again with a reason when the money actually
              moves. Fixing what it named first is the cheaper order.
            </p>
          )}
          {!providerAddressChosen && (
            <p className="muted small">
              Pick a provider first. Use "Check this hub" or "Scan for hubs"
              above, then "Use this hub" so the wallet has the provider's
              on-chain address. A channel binds to an exact counterparty and
              the wallet will not guess one.
            </p>
          )}
          {providerAddressChosen && !signingTransportEligible && (
            <p className="muted small">{MAINNET_SIGNING_TRANSPORT_NOTICE}</p>
          )}
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

      {fastPayReady && (
        <div className="fast-pay-card">
          <h3>Incoming Fast Pay requests</h3>
          <p className="muted small">
            A routed payment settles only after you verify and sign your recipient channel update.
          </p>
          {inbox.length === 0 ? (
            <p className="muted">No payment is waiting for your signature.</p>
          ) : (
            inbox.map((item) => (
              <div className="preview-card" key={item.payment_id}>
                <p>
                  <strong>{item.amount} HAC</strong> from{" "}
                  {hideAddresses ? `${item.payer.slice(0, 7)}...` : item.payer}
                </p>
                <p className="muted small">
                  No Fast Pay fee. Both channel updates are verified locally before signing.
                </p>
                <button
                  className="primary"
                  disabled={busy}
                  onClick={() => void acceptIncoming(item)}
                >
                  Verify and accept
                </button>
              </div>
            ))
          )}
        </div>
      )}

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
          <p className="muted small">
            There is no public hub, so this is somebody's machine. It can be yours:{" "}
            <code>docs/HUB-OPERATOR.md</code>.
          </p>
          <div className="actions-row">
            <button
              disabled={busy}
              onClick={() =>
                onSaveL2Settings(
                  nodeUrl,
                  hubUrl,
                  hubAddress,
                  trustedMainnetPilot,
                  mainnetPilotPassphrase,
                )
              }
            >
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
            <button disabled={busy} onClick={() => void finishPendingOpen()}>
              Finish pending setup
            </button>
            <button
              disabled={busy || !status?.channel_id}
              onClick={() => onCloseChannel(setChannelPreview)}
            >
              Close channel
            </button>
            <button
              disabled={busy || !status?.channel_id}
              onClick={() => void finishPendingClose()}
            >
              Finish pending close
            </button>
          </div>
          {channelPreview && (
            <div className="preview-card">
              <p>
                <strong>Channel ID:</strong> <code>{channelPreview.channel_id}</code>
              </p>
              <p>
                <strong>Hacash incarnation:</strong> {channelPreview.reuse_version}
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

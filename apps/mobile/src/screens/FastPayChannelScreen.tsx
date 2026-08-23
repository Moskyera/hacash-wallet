import { useCallback, useEffect, useRef, useState } from "react";
import HubDiscoveryPanel from "../components/HubDiscoveryPanel";
import {
  api,
  type ChannelInfo,
  type ChannelSetupPreview,
  type FastPayInboxItem,
  type FastPayStatus,
  type HubDiscoveryEntry,
  type WalletSettings,
} from "../api";
import { formatInvokeError } from "../formatInvokeError";
import { authorizePreparedOperation } from "../preparedAuthorization";
import {
  fastPayHowItWorks,
  fastPayMenuBadge,
  fastPayStatusLine,
  fastPayStatusTitle,
} from "../fastPayUi";
import { maskAddress } from "../privacy";
import {
  failedProbe,
  loadingProbe,
  readyProbe,
  type AsyncProbe,
} from "../asyncProbe";
import {
  FAST_PAY_MAINNET_CEILINGS,
  FAST_PAY_MAINNET_CONSENT,
  MAINNET_SIGNING_TRANSPORT_NOTICE,
  mainnetSigningTransportIsEligible,
} from "@hacash/wallet-ui";

type Props = {
  fastPay: FastPayStatus | null;
  settings: WalletSettings | null;
  hubUrl: string;
  hubAddress: string;
  userAddress: string | null | undefined;
  hideAddresses: boolean;
  watchOnly: boolean;
  busy: boolean;
  setBusy: (b: boolean) => void;
  onRefresh: () => Promise<void>;
  onApplyHub: (entry: HubDiscoveryEntry) => Promise<void>;
  onToast: (msg: string, kind: "success" | "info" | "error") => void;
};

export default function FastPayChannelScreen({
  fastPay,
  settings,
  hubUrl,
  hubAddress,
  userAddress,
  hideAddresses,
  watchOnly,
  busy,
  setBusy,
  onRefresh,
  onApplyHub,
  onToast,
}: Props) {
  const [channelProbe, setChannelProbe] = useState<AsyncProbe<ChannelInfo | null>>(
    () => loadingProbe(null),
  );
  const [userDeposit, setUserDeposit] = useState("10");
  const [hubDeposit, setHubDeposit] = useState("0");
  const [trustedMainnetPilot, setTrustedMainnetPilot] = useState(false);
  // Turning the pilot on is an authenticated change, so the screen has to be
  // able to ask for the passphrase. Turning it off needs nothing.
  const [mainnetPilotPassphrase, setMainnetPilotPassphrase] = useState("");
  const [preview, setPreview] = useState<ChannelSetupPreview | null>(null);
  const [inboxProbe, setInboxProbe] = useState<AsyncProbe<FastPayInboxItem[]>>(
    () => loadingProbe([]),
  );
  const inboxRequestRef = useRef<Promise<void> | null>(null);
  const channelRequestRef = useRef<Promise<void> | null>(null);
  const channel = channelProbe.value;
  const inbox = inboxProbe.value;

  useEffect(() => {
    const recommended = fastPay?.default_deposit_mei;
    if (recommended != null && Number.isFinite(recommended) && recommended > 0) {
      setUserDeposit(String(recommended));
    }
  }, [fastPay?.default_deposit_mei]);

  useEffect(() => {
    setTrustedMainnetPilot(settings?.trusted_mainnet_fast_pay_pilot ?? false);
  }, [settings?.trusted_mainnet_fast_pay_pilot]);
  const loadInbox = useCallback((): Promise<void> => {
    if (inboxRequestRef.current) return inboxRequestRef.current;
    const request = (async () => {
      if (fastPay?.state !== "ready") {
        setInboxProbe(readyProbe([]));
        return;
      }
      setInboxProbe((previous) => loadingProbe(previous.value));
      try {
        setInboxProbe(readyProbe(await api.fastPayInbox()));
      } catch (error) {
        setInboxProbe((previous) =>
          failedProbe(previous.value, formatInvokeError(error)),
        );
      }
    })().finally(() => {
      if (inboxRequestRef.current === request) inboxRequestRef.current = null;
    });
    inboxRequestRef.current = request;
    return request;
  }, [fastPay?.state]);

  useEffect(() => {
    void loadInbox();
    if (fastPay?.state !== "ready") return;
    const timer = window.setInterval(() => void loadInbox(), 5000);
    return () => window.clearInterval(timer);
  }, [fastPay?.state, loadInbox]);

  async function handleAcceptFastPay(item: FastPayInboxItem) {
    setBusy(true);
    try {
      const result = await api.acceptFastPay(item.payment_id);
      onToast(result.summary, "success");
      await Promise.all([loadInbox(), loadChannel(), onRefresh()]);
    } catch (error) {
      onToast(formatInvokeError(error), "error");
    } finally {
      setBusy(false);
    }
  }

  const loadChannel = useCallback((): Promise<void> => {
    if (channelRequestRef.current) return channelRequestRef.current;
    const request = (async () => {
      setChannelProbe((previous) => loadingProbe(previous.value));
      try {
        setChannelProbe(readyProbe(await api.channelInfo()));
      } catch (error) {
        setChannelProbe((previous) =>
          failedProbe(previous.value, formatInvokeError(error)),
        );
      }
    })().finally(() => {
      if (channelRequestRef.current === request) channelRequestRef.current = null;
    });
    channelRequestRef.current = request;
    return request;
  }, []);

  useEffect(() => {
    void loadChannel();
  }, [loadChannel, fastPay?.state]);

  async function handlePreviewOpen() {
    const hub = hubAddress.trim();
    if (!hub) {
      onToast("Set hub right address in Network settings first.", "error");
      return;
    }
    setBusy(true);
    setPreview(null);
    try {
      const p = await api.previewChannelOpen(hub, userDeposit, hubDeposit);
      setPreview(p);
    } catch (e) {
      onToast(formatInvokeError(e), "error");
    } finally {
      setBusy(false);
    }
  }

  async function openReviewedChannel(depositMei: string) {
    const hub = hubAddress.trim();
    if (!hub) {
      throw new Error("Choose an online Fast Pay provider first.");
    }
    if (
      settings?.network_mode === "mainnet"
      && !settings.trusted_mainnet_fast_pay_pilot
    ) {
      throw new Error(
        "Review and save the bounded mainnet pilot consent before opening a channel.",
      );
    }
    const prepared = await api.prepareChannelOpen(hub, depositMei, "0");
    const security = await api.platformSecurity();
    await authorizePreparedOperation(
      prepared,
      security.native_biometric_available,
      settings?.biometric_send_enabled ?? true,
    );
    const tx = await api.executePreparedChannelOpen(prepared.id);
    setPreview(null);
    onToast("Channel open submitted (" + tx.slice(0, 12) + "…)", "success");
    await loadChannel();
    await onRefresh();
  }

  async function handleOpenChannel() {
    setBusy(true);
    try {
      await openReviewedChannel(userDeposit);
    } catch (e) {
      onToast(formatInvokeError(e), "error");
    } finally {
      setBusy(false);
    }
  }

  async function handleEnableFastPay() {
    setBusy(true);
    try {
      await openReviewedChannel(String(fastPay?.default_deposit_mei ?? userDeposit));
    } catch (e) {
      onToast(formatInvokeError(e), "error");
    } finally {
      setBusy(false);
    }
  }

  async function handleSaveMainnetPilotConsent() {
    if (!settings || settings.network_mode !== "mainnet") return;
    // Giving consent chooses the settlement model every later mainnet payment
    // and channel open is judged under, so it goes through its own
    // authenticated command; wallet_update_settings refuses it. Withdrawing
    // consent is a tightening and stays on the generic path, so a user can
    // always step back out.
    const grantingConsent =
      trustedMainnetPilot && !settings.trusted_mainnet_fast_pay_pilot;
    if (grantingConsent && !mainnetPilotPassphrase) {
      onToast(
        "Enter your wallet passphrase to turn on the bounded mainnet pilot.",
        "error",
      );
      return;
    }
    setBusy(true);
    try {
      if (grantingConsent) {
        await api.setMainnetFastPayConsent(true, mainnetPilotPassphrase);
      } else {
        await api.updateSettings({
          ...settings,
          trusted_mainnet_fast_pay_pilot: trustedMainnetPilot,
        });
      }
      setMainnetPilotPassphrase("");
      await onRefresh();
      onToast(
        trustedMainnetPilot
          ? "Bounded mainnet Fast Pay consent saved."
          : "Bounded mainnet Fast Pay disabled. Channel recovery remains available.",
        "success",
      );
    } catch (error) {
      onToast(formatInvokeError(error), "error");
    } finally {
      setBusy(false);
    }
  }
  async function handleDisableFastPay() {
    setBusy(true);
    try {
      const prepared = await api.prepareChannelClose();
      const security = await api.platformSecurity();
      await authorizePreparedOperation(
        prepared,
        security.native_biometric_available,
        settings?.biometric_send_enabled ?? true,
      );
      const tx = await api.executePreparedChannelClose(prepared.id);
      onToast(`Fast Pay disabled (${tx.slice(0, 12)}…)`, "success");
      await loadChannel();
      await onRefresh();
    } catch (e) {
      onToast(formatInvokeError(e), "error");
    } finally {
      setBusy(false);
    }
  }

  async function handleFinishPendingOpen() {
    setBusy(true);
    try {
      const result = await api.recoverChannelOpen();
      onToast(result, "success");
      await Promise.all([loadChannel(), onRefresh()]);
    } catch (error) {
      onToast(formatInvokeError(error), "error");
    } finally {
      setBusy(false);
    }
  }

  async function handleFinishPendingClose() {
    setBusy(true);
    try {
      const result = await api.recoverChannelClose();
      onToast(result, "success");
      await Promise.all([loadChannel(), onRefresh()]);
    } catch (error) {
      onToast(formatInvokeError(error), "error");
    } finally {
      setBusy(false);
    }
  }
  // Mirrors validate_signing_node_url. Only used to SAY the rule on screen
  // before the ceremony; the core still enforces it at prepare and at signing.
  const signingTransportEligible = mainnetSigningTransportIsEligible(
    settings?.node_url,
    settings?.network_mode,
  );

  if (watchOnly) {
    return (
      <div className="card">
        <h2>Fast Pay</h2>
        <p className="muted">Watch-only mode cannot set up or change Fast Pay.</p>
      </div>
    );
  }

  return (
    <>
      <div className="card">
        <h2>Fast Pay</h2>
        <p className="muted small">{fastPayHowItWorks()}</p>
        {settings?.network_mode === "mainnet" ? (
          <div className="warning-box" role="note">
            <strong>Bounded mainnet pilot</strong>
            <p className="muted small">{FAST_PAY_MAINNET_CEILINGS}</p>
            <label>
              <input
                type="checkbox"
                checked={trustedMainnetPilot}
                onChange={(event) => setTrustedMainnetPilot(event.target.checked)}
              />
              {FAST_PAY_MAINNET_CONSENT}
            </label>
            {trustedMainnetPilot && !settings.trusted_mainnet_fast_pay_pilot ? (
              <>
                <label htmlFor="mainnet-pilot-passphrase" className="muted small">
                  Wallet passphrase, to confirm this choice
                </label>
                <input
                  id="mainnet-pilot-passphrase"
                  type="password"
                  autoComplete="current-password"
                  style={{ width: "100%" }}
                  value={mainnetPilotPassphrase}
                  onChange={(event) =>
                    setMainnetPilotPassphrase(event.target.value)}
                />
              </>
            ) : null}
            <button
              type="button"
              style={{ marginTop: "0.75rem", width: "100%" }}
              disabled={
                busy
                || trustedMainnetPilot
                  === settings.trusted_mainnet_fast_pay_pilot
              }
              onClick={() => void handleSaveMainnetPilotConsent()}
            >
              Save mainnet choice
            </button>
          </div>
        ) : null}
        <div className="toggle-row" style={{ marginTop: "0.75rem" }}>
          <strong>{fastPay ? fastPayStatusTitle(fastPay.state) : "Loading…"}</strong>
          <span
            className={
              fastPay?.state === "ready" ? "badge badge-ok" : "badge badge-warn"
            }
          >
            {fastPay ? fastPayMenuBadge(fastPay.state) : "…"}
          </span>
        </div>
        {fastPay && (
          <>
            <p className="muted" style={{ marginTop: "0.5rem" }}>
              {fastPayStatusLine(fastPay.state, fastPay.default_deposit_mei ?? 10)}
            </p>
            {fastPay.state !== "ready" && fastPay.can_enable && (
              <button
                type="button"
                className="primary"
                style={{ marginTop: "0.75rem", width: "100%" }}
                disabled={
                  busy
                  || (settings?.network_mode === "mainnet"
                    && !settings.trusted_mainnet_fast_pay_pilot)
                }
                onClick={() => void handleEnableFastPay()}
              >
                Enable
              </button>
            )}
            {fastPay.state !== "ready" && (
              <button
                type="button"
                style={{ marginTop: "0.5rem", width: "100%" }}
                disabled={busy}
                onClick={() => void handleFinishPendingOpen()}
              >
                Finish pending setup
              </button>
            )}
            {fastPay.state === "ready" && (
              <>
                <button
                  type="button"
                  style={{ marginTop: "0.75rem", width: "100%" }}
                  disabled={busy}
                  onClick={() => void handleDisableFastPay()}
                >
                  Disable
                </button>
                {channel ? (
                  <button
                    type="button"
                    style={{ marginTop: "0.5rem", width: "100%" }}
                    disabled={busy}
                    onClick={() => void handleFinishPendingClose()}
                  >
                    Finish pending close
                  </button>
                ) : null}
              </>
            )}
          </>
        )}
        {hubUrl && <p className="muted small">Hub: {hubUrl}</p>}
      </div>

      {fastPay?.state === "ready" && (
        <div className="card">
          <h2>Incoming payments</h2>
          <p className="muted small">
            Routed Fast Pay requests settle only after your wallet verifies and signs the recipient channel update.
          </p>
          {inboxProbe.status === "loading" && inbox.length === 0 ? (
            <p className="muted small">Checking for incoming payments…</p>
          ) : null}
          {inboxProbe.status === "failed" ? (
            <div className="error-box" role="alert">
              <p>Incoming payments could not be checked: {inboxProbe.message}</p>
              <button
                type="button"
                className="small"
                disabled={busy}
                onClick={() => void loadInbox()}
              >
                Retry inbox
              </button>
            </div>
          ) : null}
          {inboxProbe.status === "ready" && inbox.length === 0 ? (
            <p className="muted small">No payment is waiting for your signature.</p>
          ) : null}
          {inbox.length > 0 ? (
            inbox.map((item) => (
              <div className="preview-box" key={item.payment_id}>
                <p><strong>{item.amount} HAC</strong></p>
                <p className="muted small">
                  From {maskAddress(item.payer, hideAddresses)}. No Fast Pay fee.
                </p>
                <button
                  type="button"
                  className="primary"
                  disabled={busy}
                  onClick={() => void handleAcceptFastPay(item)}
                >
                  Verify and accept
                </button>
              </div>
            ))
          ) : null}
        </div>
      )}

      {/*
        The transport rule, said as visible state rather than delivered as an
        exception after the fingerprint prompt.

        On a plain install this is mainnet plus the official plaintext node,
        and the wallet cannot sign anything: not a send, not a channel open,
        not a channel close. The rule is right and stays. What was wrong is
        that no screen mentioned it, and the refusal arrived from inside
        execution, after authorizePreparedOperation had already taken the
        fingerprint or passphrase. Note that on a phone the loopback escape
        hatch is not practical, so HTTPS is the door.
      */}
      {!signingTransportEligible ? (
        <div className="card" role="note">
          <h2>This node cannot sign on mainnet</h2>
          <p className="muted small">{MAINNET_SIGNING_TRANSPORT_NOTICE}</p>
          {/*
            The shared sentence offers two doors, and only one of them opens
            from a phone. Saying so here stops a person hunting for a way to
            run a full node on their handset.
          */}
          <p className="muted small">
            On a phone the second option is not realistic: a full node does not
            run here. That leaves an HTTPS address for a node you or your
            operator runs elsewhere.
          </p>
          <p className="muted small">Current node: {settings?.node_url}</p>
        </div>
      ) : null}

      <div className="card">
        <h2>Find a hub</h2>
        <HubDiscoveryPanel
          settings={settings}
          activeHubUrl={hubUrl}
          busy={busy}
          setBusy={setBusy}
          onApplyHub={async (entry) => {
            await onApplyHub(entry);
            await onRefresh();
          }}
          onToast={onToast}
        />
      </div>

      {channelProbe.status === "loading" && !channel ? (
        <div className="card" aria-live="polite">
          <h2>Channel</h2>
          <p className="muted small">Checking channel state…</p>
        </div>
      ) : null}

      {channelProbe.status === "failed" ? (
        <div className="card" role="alert">
          <h2>Channel unavailable</h2>
          <p className="error">{channelProbe.message}</p>
          <button type="button" disabled={busy} onClick={() => void loadChannel()}>
            Retry channel check
          </button>
        </div>
      ) : null}

      {channel && (
        <div className="card">
          <h2>Active channel</h2>
          <p className="muted small">ID: {channel.id.slice(0, 16)}…</p>
          <div className="balance-assets">
            <div className="balance-asset">
              <span className="label">Left</span>
              <span className="value">{channel.left.hacash} HAC</span>
              {channel.left.satoshi > 0 && (
                <span className="hint">{(channel.left.satoshi / 1e8).toFixed(8)} BTC</span>
              )}
              <span className="hint">{maskAddress(channel.left.address, hideAddresses)}</span>
            </div>
            <div className="balance-asset">
              <span className="label">Right</span>
              <span className="value">{channel.right.hacash} HAC</span>
              {channel.right.satoshi > 0 && (
                <span className="hint">{(channel.right.satoshi / 1e8).toFixed(8)} BTC</span>
              )}
              <span className="hint">{maskAddress(channel.right.address, hideAddresses)}</span>
            </div>
          </div>
          {userAddress && (
            <p className="muted small">
              You are on the{" "}
              {channel.left.address === userAddress
                ? "left"
                : channel.right.address === userAddress
                  ? "right"
                  : "unknown"}{" "}
              side.
            </p>
          )}

        </div>
      )}

      {channelProbe.status === "ready" && !channel && (
        <div className="card">
          <h2>Setup</h2>
          <p className="muted small">
            Deposit HAC once to turn on instant sends. You can change the amount below.
          </p>
          <label className="label">Your deposit (HAC)</label>
          <input
            type="number"
            min="0"
            step="0.001"
            value={userDeposit}
            onChange={(e) => {
              setUserDeposit(e.target.value);
              setPreview(null);
            }}
          />
          <label className="label">Hub deposit (HAC)</label>
          <input
            type="number"
            min="0"
            step="0.001"
            value={hubDeposit}
            onChange={(e) => {
              setHubDeposit(e.target.value);
              setPreview(null);
            }}
          />
          <button type="button" disabled={busy || !hubAddress.trim()} onClick={() => void handlePreviewOpen()}>
            Preview channel open
          </button>
          {preview && (
            <div className="preview-box">
              <p>
                Channel <code>{preview.channel_id.slice(0, 16)}…</code>
              </p>
              <p className="muted small">Hacash incarnation {preview.reuse_version}</p>
              <p className="muted small">
                You {preview.left_deposit} HAC, hub {preview.right_deposit} HAC
              </p>
              <button type="button" className="primary" disabled={busy} onClick={() => void handleOpenChannel()}>
                Confirm open channel
              </button>
            </div>
          )}
        </div>
      )}
    </>
  );
}

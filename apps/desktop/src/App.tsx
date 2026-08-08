import { useEffect, useMemo, useState } from "react";
import { getCurrentWindow } from "@tauri-apps/api/window";
import WalletLogo from "./components/WalletLogo";
import { useToast } from "./hooks/useToast";
import { useLocale } from "./locale";
import { useDesktopWallet } from "./hooks/useDesktopWallet";
import { useHacSend } from "./hooks/useHacSend";
import DappApprovalPanel from "./components/DappApprovalPanel";
import PreparedOperationConfirm from "./components/PreparedOperationConfirm";
import AgentWalletApp from "./agent/AgentWalletApp";
import DesktopRouter from "./screens/DesktopRouter";
import { NAV_GROUPS, formatCountdown, type Screen } from "./screens/types";
import {
  fastPayChipLabel,
  fastPayNavHint,
} from "./fastPayUi";
import { maskAddress } from "./privacy";
import "./quantum.css";
const SCREEN_SUBTITLES: Partial<Record<Screen, string>> = {
  home: "Portfolio overview",
  send: "Review and send assets",
  receive: "Addresses and payment requests",
  fastpay: "Hacash L2 channel payments",
  hacd: "Owned diamond metadata",
  history: "Local wallet activity",
  quantum: "Experimental lab, not for mainnet",
  airgap: "Offline transaction signing",
  security: "Vault and signing controls",
  privacy: "Local privacy controls",
  settings: "Network and wallet preferences",
  advanced: "Node-gated protocol tools",
};

function PersonalWalletApp({ onOpenAgent }: { onOpenAgent: () => void }) {
  const [screen, setScreen] = useState<Screen>("welcome");
  const [privacyShield, setPrivacyShield] = useState(false);
  const { toast, showToast } = useToast();
  const { t } = useLocale();

  const wallet = useDesktopWallet(showToast, screen, setScreen);

  const hacSend = useHacSend({
    settings: wallet.settings,
    status: wallet.status,
    nativeBioAvailable: wallet.nativeBioAvailable,
    setScreen,
    refreshBalance: wallet.refreshBalance,
    refreshHistory: wallet.refreshHistory,
    refreshSettings: wallet.refreshSettings,
    setLastTxHash: wallet.setLastTxHash,
    clearMessages: wallet.clearMessages,
    onError: wallet.onError,
    onInfo: wallet.onInfo,
    setBusy: wallet.setBusy,
    busy: wallet.busy,
  });

  const hideBalances = wallet.privacy.hide_balances;
  const hideAddresses = wallet.privacy.hide_addresses;
  const fastPayReady = wallet.status?.fast_pay_state === "ready";
  const fastPayNeedsSetup = wallet.status?.fast_pay_state === "needs_channel";

  const whisperRelayOnline =
    wallet.relayHealth.length > 0 && wallet.relayHealth.some((row) => row.online);

  useEffect(() => {
    if (!wallet.privacy.screen_privacy) {
      setPrivacyShield(false);
      return;
    }
    const onVis = () => setPrivacyShield(document.hidden);
    document.addEventListener("visibilitychange", onVis);
    let unlisten: (() => void) | undefined;
    if ("__TAURI_INTERNALS__" in window) {
      try {
        getCurrentWindow()
          .onFocusChanged(({ payload: focused }) => setPrivacyShield(!focused))
          .then((fn) => {
            unlisten = fn;
          })
          .catch(() => undefined);
      } catch {
        // Browser preview: visibilitychange still protects the UI.
      }
    }
    return () => {
      document.removeEventListener("visibilitychange", onVis);
      unlisten?.();
    };
  }, [wallet.privacy.screen_privacy]);

  const handleLock = () => {
    hacSend.setPreview(null);
    void wallet.handleLock();
  };
  const handleOpenAgent = async () => {
    hacSend.setPreview(null);
    try {
      await wallet.handleLock();
      onOpenAgent();
    } catch (error) {
      wallet.onError(
        error instanceof Error
          ? error.message
          : "My Wallet lock could not be confirmed. Agent Wallet was not opened.",
      );
    }
  };

  const handleValidateHip23 = async (
    params: Parameters<typeof wallet.handleValidateHip23>[0],
  ) => wallet.handleValidateHip23(params);

  const routerData = useMemo(
    () => ({
      status: wallet.status,
      settings: wallet.settings,
      assets: wallet.assets,
      assetTrends: wallet.assetTrends,
      fastPayDetail: wallet.fastPayDetail,
      channelInfo: wallet.channelInfo,
      hubHealth: wallet.hubHealth,
      billsCount: wallet.billsCount,
      txHistory: wallet.txHistory,
      lastTx: wallet.lastTx,
      webauthnReady: wallet.webauthnReady,
      nativeBioAvailable: wallet.nativeBioAvailable,
      relayHealth: wallet.relayHealth,
      privacy: wallet.privacy,
      dustWhisper: wallet.dustWhisper,
      busy: wallet.busy,
      fastPayReady,
      fastPayNeedsSetup,
      hideBalances,
      hideAddresses,
      sendActive: screen === "send",
      sendTo: hacSend.sendTo,
      sendAmount: hacSend.sendAmount,
      sendHubFeePayer: hacSend.sendHubFeePayer,
      sendForceL1: hacSend.sendForceL1,
      sendL1FeeSpeed: hacSend.sendL1FeeSpeed,
      sendServiceFeeEnabled: hacSend.sendServiceFeeEnabled,
      serviceFeeRate: hacSend.serviceFeeRate,
      showSendOptions: hacSend.showSendOptions,
      sendQrScanOpen: hacSend.sendQrScanOpen,
      preview: hacSend.preview,
    }),
    [
      wallet.status,
      wallet.settings,
      wallet.assets,
      wallet.assetTrends,
      wallet.fastPayDetail,
      wallet.channelInfo,
      wallet.hubHealth,
      wallet.billsCount,
      wallet.txHistory,
      wallet.lastTx,
      wallet.webauthnReady,
      wallet.nativeBioAvailable,
      wallet.relayHealth,
      wallet.privacy,
      wallet.dustWhisper,
      wallet.busy,
      fastPayReady,
      fastPayNeedsSetup,
      hideBalances,
      hideAddresses,
      screen,
      hacSend.sendTo,
      hacSend.sendAmount,
      hacSend.sendHubFeePayer,
      hacSend.sendForceL1,
      hacSend.sendL1FeeSpeed,
      hacSend.sendServiceFeeEnabled,
      hacSend.serviceFeeRate,
      hacSend.showSendOptions,
      hacSend.sendQrScanOpen,
      hacSend.preview,
    ],
  );

  const routerActions = useMemo(
    () => ({
      setBusy: wallet.setBusy,
      setScreen,
      clearMessages: wallet.clearMessages,
      onError: wallet.onError,
      onInfo: wallet.onInfo,
      onNotify: (msg: string, kind: "error" | "info" | "success") => {
        wallet.clearMessages();
        if (kind === "error") wallet.onError(msg);
        else wallet.onInfo(msg);
      },
      onCreate: (p: string) => void wallet.handleCreate(p),
      onImport: (s: string, p: string, expected: string) =>
        void wallet.handleImport(s, p, expected),
      onImportBackup: (j: string, p: string, d?: string | null, allowLegacy = false) =>
        void wallet.handleImportBackup(j, p, d, allowLegacy),
      onWatchOnly: (a: string) => void wallet.handleWatchOnlyImport(a),
      onUnlock: (p: string) => void wallet.handleUnlock(p),
      onLock: handleLock,
      onOpenQrPay: hacSend.openQrPay,
      onEnableFastPay: (d: string) => void wallet.handleEnableFastPay(d),
      onApplyHub: wallet.handleApplyHub,
      onSaveL2Settings: (n: string, h: string, a: string) =>
        void wallet.handleSaveL2Settings(n, h, a),
      onHubHealth: () => void wallet.handleHubHealth(),
      onPreviewChannel: (...args: Parameters<typeof wallet.handlePreviewChannel>) =>
        void wallet.handlePreviewChannel(...args),
      onOpenChannel: (...args: Parameters<typeof wallet.handleOpenChannel>) =>
        void wallet.handleOpenChannel(...args),
      onCloseChannel: (cb: Parameters<typeof wallet.handleCloseChannel>[0]) =>
        void wallet.handleCloseChannel(cb),
      onRegisterWebAuthn: (currentPassphrase: string) =>
        void wallet.handleRegisterWebAuthn(currentPassphrase),
      onSetProfile: (p: string, currentPassphrase: string) =>
        void wallet.handleSetProfile(p, currentPassphrase),
      onSetSecondFactorThreshold: (amountMei: number | null, currentPassphrase: string) =>
        void wallet.handleSetSecondFactorThreshold(amountMei, currentPassphrase),
      onSetHardwareMode: (
        m: "software" | "webauthn_gate" | "airgap_only" | "watch_only",
        currentPassphrase: string,
      ) =>
        void wallet.handleSetHardwareMode(m, currentPassphrase),
      onSaveSettings: (nodeUrl: string, fallbackUrls: string[], autoFailover: boolean) =>
        void wallet.handleSaveSettings(nodeUrl, fallbackUrls, autoFailover),
      onChangePassphrase: (o: string, n: string, c: string) =>
        wallet.handleChangePassphrase(o, n, c),
      onExportBackup: wallet.handleExportBackup,
      onValidateHip23: handleValidateHip23,
      onSavePrivacy: (d: import("./api").PrivacySettings) => void wallet.handleSavePrivacy(d),
      onSaveWhisper: wallet.handleSaveWhisper,
      onClearHistory: () => void wallet.handleClearHistory(),
      onCopyAddress: () => void wallet.handleCopyAddress(),
      refreshUnlockedData: wallet.refreshUnlockedData,
      setSendTo: hacSend.setSendTo,
      setSendAmount: hacSend.setSendAmount,
      setSendForceL1: hacSend.setSendForceL1,
      setSendL1FeeSpeed: hacSend.setSendL1FeeSpeed,
      setSendServiceFeeEnabled: hacSend.setSendServiceFeeEnabled,
      setShowSendOptions: hacSend.setShowSendOptions,
      setSendQrScanOpen: hacSend.setSendQrScanOpen,
      clearPreview: hacSend.clearPreview,
      persistSendPreferences: hacSend.persistSendPreferences,
      onPaymentQr: (p: import("./paymentQr").PaymentQrPayload) => void hacSend.handlePaymentQr(p),
      onPreviewSend: (speed?: import("./api").L1FeeSpeed) => void hacSend.handlePreviewSend(speed),
      onConfirmSend: () => void hacSend.handleConfirmSend(),
    }),
    [
      wallet,
      hacSend,
      handleLock,
      handleValidateHip23,
      setScreen,
    ],
  );

  const isAuthScreen = screen === "welcome" || screen === "unlock";
  const screenTitle = screen === "home" ? "My Wallet" : t(`nav.${screen}`);
  const screenSubtitle = SCREEN_SUBTITLES[screen] ?? "HPAY Wallet";
  const nodeReady = Boolean(wallet.status && !wallet.status.locked && wallet.assets);

  return (
    <div className={`app${isAuthScreen ? " app-auth" : ""}`}>
      {privacyShield && (
        <div className="privacy-shield" aria-hidden="true">
          <div className="privacy-shield-inner">
            <strong>{t("privacy.hidden")}</strong>
            {t("privacy.focus")}
          </div>
        </div>
      )}
      {isAuthScreen && (
        <div className="auth-space-switcher wallet-space-switcher" role="group" aria-label="Wallet space">
          <button type="button" className="active" aria-current="page">
            My Wallet
          </button>
          <button type="button" onClick={() => void handleOpenAgent()}>
            AI Agent Wallet
          </button>
        </div>
      )}
      {!isAuthScreen && (
      <aside className="sidebar">
        <div className="brand">
          <WalletLogo size="sm" />
          <div className="brand-copy">
            <strong>HPAY Wallet</strong>
            <span>Powered by Hacash</span>
          </div>
        </div>
        <div className="wallet-space-switcher" role="group" aria-label="Wallet space">
          <button type="button" className="active" aria-current="page">
            My Wallet
          </button>
          <button type="button" onClick={() => void handleOpenAgent()}>
            AI Agent Wallet
          </button>
        </div>
        {wallet.status && !wallet.status.locked && (
          <nav>
            {NAV_GROUPS.map((group) => (
              <div className="nav-group" key={group.id}>
                <span className="nav-group-label">{t(`group.${group.id}`)}</span>
                {group.items.map((item) => (
                  <button
                    key={item.id}
                    type="button"
                    className={screen === item.id ? "active" : ""}
                    aria-current={screen === item.id ? "page" : undefined}
                    onClick={() => {
                      wallet.clearMessages();
                      setScreen(item.id);
                    }}
                  >
                    <span className="nav-item-mark" aria-hidden>{item.mark}</span>
                    <span className="nav-item-label">{t(`nav.${item.id}`)}</span>
                    {item.id === "fastpay" && (
                      <span className={`nav-fp-badge ${fastPayReady ? "nav-fp-on" : "nav-fp-off"}`}>
                        {fastPayNavHint(wallet.status?.fast_pay_state ?? "no_provider")}
                      </span>
                    )}
                  </button>
                ))}
              </div>
            ))}
          </nav>
        )}
        <div className="sidebar-foot">
          {wallet.status?.node_url && (
            <span className="muted">{wallet.status.node_url}</span>
          )}
          {wallet.status && !wallet.status.locked && (
            <div className="status-chips">
              <span
                className={`chip ${fastPayReady ? "chip-accent" : fastPayNeedsSetup ? "chip-ok" : ""}`}
                title={wallet.status.fast_pay_message}
              >
                {fastPayChipLabel(wallet.status.fast_pay_state)}
              </span>
              {wallet.status.webauthn_enabled && (
                <span className="chip chip-accent">WebAuthn</span>
              )}
              {wallet.status.watch_only && <span className="chip">Watch-only</span>}
              {(wallet.privacy.hide_balances || wallet.privacy.hide_addresses) && (
                <span className="chip chip-accent">Privacy on</span>
              )}
              {wallet.dustWhisper.enabled && (
                <span
                  className={`chip ${whisperRelayOnline ? "chip-ok" : "chip-bad"}`}
                  title={
                    whisperRelayOnline
                      ? "Whisper relay online"
                      : "Whisper relay offline. Sends may fail or fall back."
                  }
                >
                  Whisper {whisperRelayOnline ? "online" : "offline"}
                </span>
              )}
              {wallet.status.hardware_signing_mode === "webauthn_gate" && (
                <span className="chip chip-accent">2FA gate</span>
              )}
              {wallet.status.hardware_signing_mode === "airgap_only" && (
                <span className="chip chip-accent">Cold Vault</span>
              )}
              {wallet.status.legacy_key_derivation != null && (
                <span
                  className="chip chip-warn"
                  title="This key was derived from a recovery phrase with one unsalted SHA-256. Anyone who guesses the phrase can spend from it without this device. Move the funds to a newly generated wallet."
                >
                  Guessable key
                </span>
              )}
              {wallet.status.seconds_until_lock != null && (
                <span className="chip">
                  Lock {formatCountdown(wallet.status.seconds_until_lock)}
                </span>
              )}
            </div>
          )}
        </div>
      </aside>
      )}

      <main className="content">
        {!isAuthScreen && (
          <header className="desktop-topbar">
            <div className="desktop-topbar-copy">
              <h1>{screenTitle}</h1>
              <p>{screenSubtitle}</p>
            </div>
            <div className="desktop-topbar-actions">
              <span className="desktop-topbar-pill">{wallet.status?.network_mode === "testnet" ? "Testnet" : "Mainnet"}</span>
              <span className={`desktop-topbar-pill${nodeReady ? " ready" : ""}`}>
                {nodeReady ? "Node connected" : "Node checking"}
              </span>
              {wallet.status?.address ? (
                <code className="desktop-topbar-address">
                  {maskAddress(wallet.status.address, hideAddresses)}
                </code>
              ) : null}
              {wallet.status?.address ? (
                <button type="button" className="desktop-topbar-button" onClick={() => void wallet.handleCopyAddress()}>
                  Copy
                </button>
              ) : null}
              <button type="button" className="desktop-topbar-button" onClick={() => setScreen("privacy")}>
                Privacy
              </button>
              <button type="button" className="desktop-topbar-button" onClick={handleLock}>
                Lock
              </button>
            </div>
          </header>
        )}
        {wallet.error && <div className="alert">{wallet.error}</div>}
        {wallet.info && <div className="info-box">{wallet.info}</div>}
        {toast && (
          <div className={`toast toast-${toast.kind}`} role="status">
            {toast.msg}
          </div>
        )}

        <DesktopRouter screen={screen} data={routerData} actions={routerActions} />
      </main>

      <DappApprovalPanel
        unlocked={
          !!wallet.status &&
          !wallet.status.locked &&
          wallet.status.hardware_signing_mode !== "airgap_only"
        }
        onNotify={(msg, kind) => {
          if (kind === "error") wallet.onError(msg);
          else wallet.onInfo(msg);
        }}
      />

      <PreparedOperationConfirm />
    </div>
  );
}


type WalletSpace = "personal" | "agent";

function WalletSpaceWelcome({ onSelect }: { onSelect: (space: WalletSpace) => void }) {
  return (
    <main className="space-welcome">
      <section className="space-welcome-card">
        <WalletLogo size="lg" />
        <span className="agent-eyebrow">Independent wallet spaces</span>
        <h1>Welcome to HPAY Wallet</h1>
        <p>Choose the wallet space you want to open. You can enable or open the other space later.</p>
        <div className="space-choice-grid">
          <button type="button" onClick={() => onSelect("personal")}>
            <strong>My Wallet</strong>
            <span>Store, send and receive HAC, HACD and BTC.</span>
          </button>
          <button type="button" onClick={() => onSelect("agent")}>
            <strong>AI Agent Wallet</strong>
            <span>Create an independent limited wallet for approved local AI services.</span>
          </button>
        </div>
        <p className="space-security-note">
          The two spaces use different addresses, private keys, vaults and unlock sessions.
        </p>
      </section>
    </main>
  );
}

export default function App() {
  const [walletSpace, setWalletSpace] = useState<WalletSpace | null>(() => {
    try {
      const saved = window.localStorage.getItem("hpay.wallet-space.v1");
      return saved === "personal" || saved === "agent" ? saved : null;
    } catch {
      return null;
    }
  });

  const selectSpace = (space: WalletSpace) => {
    setWalletSpace(space);
    try {
      window.localStorage.setItem("hpay.wallet-space.v1", space);
    } catch {
      // This stores only a UI preference. Wallet secrets remain in isolated Rust vaults.
    }
  };

  if (walletSpace === null) {
    return <WalletSpaceWelcome onSelect={selectSpace} />;
  }
  if (walletSpace === "agent") {
    return <AgentWalletApp onOpenPersonal={() => selectSpace("personal")} />;
  }
  return <PersonalWalletApp onOpenAgent={() => selectSpace("agent")} />;
}

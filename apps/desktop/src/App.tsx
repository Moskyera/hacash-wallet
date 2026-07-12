import { useEffect, useMemo, useState } from "react";
import { getCurrentWindow } from "@tauri-apps/api/window";
import WalletLogo from "./components/WalletLogo";
import { useToast } from "./hooks/useToast";
import { useDesktopWallet } from "./hooks/useDesktopWallet";
import { useHacSend } from "./hooks/useHacSend";
import DesktopRouter from "./screens/DesktopRouter";
import { NAV_ITEMS, formatCountdown, type Screen } from "./screens/types";
import {
  fastPayChipLabel,
  fastPayNavHint,
} from "./fastPayUi";
import "./quantum.css";

export default function App() {
  const [screen, setScreen] = useState<Screen>("welcome");
  const [privacyShield, setPrivacyShield] = useState(false);
  const { toast, showToast } = useToast();

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
    getCurrentWindow()
      .onFocusChanged(({ payload: focused }) => setPrivacyShield(!focused))
      .then((fn) => {
        unlisten = fn;
      })
      .catch(() => undefined);
    return () => {
      document.removeEventListener("visibilitychange", onVis);
      unlisten?.();
    };
  }, [wallet.privacy.screen_privacy]);

  const handleLock = () => {
    hacSend.setPreview(null);
    void wallet.handleLock();
  };

  const handleValidateHip23 = async (
    params: Parameters<typeof wallet.handleValidateHip23>[0],
  ) => wallet.handleValidateHip23(params);

  const routerData = useMemo(
    () => ({
      status: wallet.status,
      settings: wallet.settings,
      assets: wallet.assets,
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
      showSendOptions: hacSend.showSendOptions,
      sendQrScanOpen: hacSend.sendQrScanOpen,
      preview: hacSend.preview,
    }),
    [
      wallet.status,
      wallet.settings,
      wallet.assets,
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
      onImport: (s: string, p: string) => void wallet.handleImport(s, p),
      onImportBackup: (j: string, p: string, d?: string | null) =>
        void wallet.handleImportBackup(j, p, d),
      onWatchOnly: (a: string) => void wallet.handleWatchOnlyImport(a),
      onUnlock: (p: string) => void wallet.handleUnlock(p),
      onLock: handleLock,
      onOpenQrPay: hacSend.openQrPay,
      onWebAuthnSession: () => void wallet.handleWebAuthnSession(),
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
      onRegisterWebAuthn: () => void wallet.handleRegisterWebAuthn(),
      onSetProfile: (p: string) => void wallet.handleSetProfile(p),
      onSetHardwareMode: (m: "software" | "webauthn_gate" | "watch_only") =>
        void wallet.handleSetHardwareMode(m),
      onSaveSettings: (n: string) => void wallet.handleSaveSettings(n),
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
      setSendHubFeePayer: hacSend.setSendHubFeePayer,
      setSendForceL1: hacSend.setSendForceL1,
      setShowSendOptions: hacSend.setShowSendOptions,
      setSendQrScanOpen: hacSend.setSendQrScanOpen,
      clearPreview: hacSend.clearPreview,
      persistSendPreferences: hacSend.persistSendPreferences,
      onPaymentQr: (p: import("./paymentQr").PaymentQrPayload) => void hacSend.handlePaymentQr(p),
      onPreviewSend: () => void hacSend.handlePreviewSend(),
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

  return (
    <div className="app">
      {privacyShield && (
        <div className="privacy-shield" aria-hidden="true">
          <div className="privacy-shield-inner">
            <strong>Wallet hidden</strong>
            Focus the window to view balances and addresses.
          </div>
        </div>
      )}
      <aside className="sidebar">
        <div className="brand">
          <WalletLogo size="sm" />
          <div>
            <div className="brand-sub">Secure Smart Send</div>
          </div>
        </div>
        {wallet.status && !wallet.status.locked && (
          <nav>
            {NAV_ITEMS.map((item) => (
              <button
                key={item.id}
                className={screen === item.id ? "active" : ""}
                onClick={() => {
                  wallet.clearMessages();
                  setScreen(item.id);
                }}
              >
                {item.id === "fastpay" ? (
                  <>
                    Fast Pay{" "}
                    <span
                      className={`nav-fp-badge ${fastPayReady ? "nav-fp-on" : "nav-fp-off"}`}
                    >
                      {fastPayNavHint(wallet.status?.fast_pay_state ?? "no_provider")}
                    </span>
                  </>
                ) : (
                  item.label
                )}
              </button>
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
                <span className="chip chip-accent">HW gate</span>
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

      <main className="content">
        {wallet.error && <div className="alert">{wallet.error}</div>}
        {wallet.info && <div className="info-box">{wallet.info}</div>}
        {toast && (
          <div className={`toast toast-${toast.kind}`} role="status">
            {toast.msg}
          </div>
        )}

        <DesktopRouter screen={screen} data={routerData} actions={routerActions} />
      </main>
    </div>
  );
}
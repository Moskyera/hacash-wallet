import { useCallback, useEffect, useRef, useState } from "react";
import { api, BillSummary, type BiometricUnlockStatus } from "./api";
import BottomNav, { type TabId } from "./components/BottomNav";
import BillDetailModal from "./components/BillDetailModal";
import DappApprovalPanel from "./components/DappApprovalPanel";
import PrivacyShield from "./components/PrivacyShield";
import Toast from "./components/Toast";
import PreparedOperationConfirm from "./components/PreparedOperationConfirm";
import SplashScreen from "./components/SplashScreen";
import WalletLogo from "./components/WalletLogo";
import { usePaymentFlow } from "./hooks/usePaymentFlow";
import { useToast } from "./hooks/useToast";
import { useWalletSession } from "./hooks/useWalletSession";
import HomeTab from "./screens/HomeTab";
import HacdTab from "./screens/HacdTab";
import PayTab from "./screens/PayTab";
import ReceiveTab from "./screens/ReceiveTab";
import UnlockScreen from "./screens/UnlockScreen";
import WelcomeScreen from "./screens/WelcomeScreen";
import MoreRouter, { type MorePage } from "./screens/more/MoreRouter";
import { loadContacts, type SavedContact } from "./contacts";
import { formatInvokeError } from "./formatInvokeError";
import {
  clearSystemDialogExpectation,
  systemDialogInFlight,
} from "./utils/systemDialogGuard";
import { openUrl } from "@tauri-apps/plugin-opener";
import { HowItWorksPrompt } from "@hacash/wallet-ui";
import { useLocale } from "./locale";
import { encodePaymentUri } from "./paymentQr";
import { clearSensitiveClipboard, copyWithPrivacyClear, maskAddress } from "./privacy";
import { clearAllWalletNames, saveWalletName, walletDisplayName } from "./walletName";
import { MIN_WALLET_PASS } from "./quantumMeta";
import { clearDeepLink, parseDeepLinkPay, stashDeepLinkUrl } from "./utils/deepLink";
import { hapticSuccess } from "./utils/haptic";
import { PULL_THRESHOLD } from "./utils/appConstants";

export default function MobileApp({ onOpenAgent }: { onOpenAgent?: () => void }) {
  const { t } = useLocale();
  const { toast, showToast } = useToast();
  const session = useWalletSession(showToast);

  const [tab, setTab] = useState<TabId>("home");
  const [morePage, setMorePage] = useState<MorePage>("menu");
  const [contacts, setContacts] = useState<SavedContact[]>(loadContacts);
  const [privacyHidden, setPrivacyHidden] = useState(false);
  const [passphrase, setPassphrase] = useState("");
  const [seed, setSeed] = useState("");
  const [watchAddress, setWatchAddress] = useState("");
  const [receiveAmount, setReceiveAmount] = useState("");
  const [selectedBill, setSelectedBill] = useState<BillSummary | null>(null);

  const pullStartY = useRef(0);
  const pullOffset = useRef(0);
  const deepLinkHandled = useRef(false);
  const bioUnlockPrompted = useRef(false);
  const backgroundLockRequested = useRef(false);
  const [deepLinkTick, setDeepLinkTick] = useState(0);
  const [biometricUnlock, setBiometricUnlock] = useState<BiometricUnlockStatus | null>(null);

  const clipboardSecs = session.privacy.clipboard_clear_secs;
  const displayName = walletDisplayName(session.status?.address, session.walletName);

  const payment = usePaymentFlow({
    settings: session.settings,
    setSettings: session.setSettings,
    platformSec: session.platformSec,
    secondFactorThresholdMei: session.status?.require_second_factor_above_mei ?? null,
    watchOnly: session.watchOnly,
    busy: session.busy,
    setBusy: session.setBusy,
    refresh: session.refresh,
    showToast,
    onSent: () => setTab("home"),
  });

  const { syncSendPrefsFromSettings, loadPaymentPayload } = payment;

  useEffect(() => {
    if (session.settings) {
      syncSendPrefsFromSettings(session.settings);
    }
  }, [session.settings, syncSendPrefsFromSettings]);

  useEffect(() => {
    if (session.authScreen !== "app") {
      backgroundLockRequested.current = false;
      setPrivacyHidden(document.visibilityState === "hidden");
    }

    const lockForBackground = () => {
      // Conceal synchronously before any asynchronous IPC can yield.
      setPrivacyHidden(true);
      setPassphrase("");
      setSeed("");
      void clearSensitiveClipboard();

      if (session.authScreen !== "app" || backgroundLockRequested.current) return;
      // A system dialog the user just asked for is not the app being backgrounded.
      // Concealing already happened above; locking here would eject them from a scan
      // they started one tap earlier.
      if (systemDialogInFlight()) return;
      backgroundLockRequested.current = true;
      void api
        .lock()
        .then(() => session.refresh())
        .catch((error) => {
          // Fail closed: keep the shield visible until a restart can confirm lock state.
          showToast("Wallet background lock could not be confirmed: " + formatInvokeError(error), "error");
        });
    };
    const onVisibilityChange = () => {
      if (document.visibilityState === "hidden") {
        lockForBackground();
      } else if (!backgroundLockRequested.current) {
        setPrivacyHidden(false);
      }
    };
    const onBlur = () => {
      if (session.privacy.screen_privacy) setPrivacyHidden(true);
    };
    const onFocus = () => {
      clearSystemDialogExpectation();
      if (document.visibilityState !== "hidden" && !backgroundLockRequested.current) {
        setPrivacyHidden(false);
      }
    };
    document.addEventListener("visibilitychange", onVisibilityChange);
    document.addEventListener("freeze", lockForBackground);
    window.addEventListener("pagehide", lockForBackground);
    window.addEventListener("blur", onBlur);
    window.addEventListener("focus", onFocus);
    if (document.visibilityState === "hidden") {
      lockForBackground();
    }
    return () => {
      document.removeEventListener("visibilitychange", onVisibilityChange);
      document.removeEventListener("freeze", lockForBackground);
      window.removeEventListener("pagehide", lockForBackground);
      window.removeEventListener("blur", onBlur);
      window.removeEventListener("focus", onFocus);
    };
  }, [session.authScreen, session.privacy.screen_privacy, session.refresh, showToast]);

  const navigateToPay = useCallback(
    (opts?: { openCamera?: boolean }) => {
      if (session.status?.hardware_signing_mode === "airgap_only") {
        payment.setPayScanMode(false);
        setMorePage("airgap");
        setTab("more");
        showToast(t("airgap.coldVaultSignerHint"), "info");
        return;
      }
      payment.setPayScanMode(false);
      if (opts?.openCamera) {
        // Show the scanner, but never start the camera on the user's behalf. A wallet
        // that switches the camera on by itself is unpleasant on its own terms, and it
        // used to raise the Android permission dialog before the user had chosen to
        // scan anything. The scanner renders its own Open camera button.
        payment.setPayScanMode(true);
      }
      setTab("pay");
    },
    [payment, session.status?.hardware_signing_mode, showToast, t],
  );

  useEffect(() => {
    if (tab !== "pay") {
      payment.setPayScanMode(false);
    }
  }, [tab, payment]);

  useEffect(() => {
    let unlisten: (() => void) | undefined;
    void (async () => {
      try {
        const { getCurrent, onOpenUrl } = await import("@tauri-apps/plugin-deep-link");
        const current = await getCurrent();
        if (current?.length) {
          for (const url of current) stashDeepLinkUrl(url);
          setDeepLinkTick((t) => t + 1);
        }
        unlisten = await onOpenUrl((urls) => {
          for (const url of urls) stashDeepLinkUrl(url);
          deepLinkHandled.current = false;
          setDeepLinkTick((t) => t + 1);
        });
      } catch {
        /* desktop preview without deep-link permissions */
      }
    })();
    return () => {
      unlisten?.();
    };
  }, []);

  useEffect(() => {
    if (deepLinkHandled.current || session.authScreen !== "app") return;
    if (!session.status || session.status.locked || !session.status.has_wallet) return;
    const payload = parseDeepLinkPay();
    if (!payload) return;
    deepLinkHandled.current = true;
    clearDeepLink();
    if (!session.watchOnly) {
      navigateToPay();
      void loadPaymentPayload(payload, "deeplink");
    }
  }, [
    session.status,
    session.authScreen,
    session.watchOnly,
    loadPaymentPayload,
    navigateToPay,
    deepLinkTick,
  ]);

  const onBalanceTouchStart = (e: React.TouchEvent) => {
    pullStartY.current = e.touches[0].clientY;
  };
  const onBalanceTouchMove = (e: React.TouchEvent) => {
    const dy = e.touches[0].clientY - pullStartY.current;
    if (dy > 0 && window.scrollY <= 0) pullOffset.current = Math.min(dy, 100);
  };
  const onBalanceTouchEnd = () => {
    if (pullOffset.current >= PULL_THRESHOLD) void session.handlePullRefresh();
    pullOffset.current = 0;
  };

  const handleCreate = async () => {
    session.setBusy(true);
    try {
      const address = await api.create(passphrase);
      if (session.walletNameDraft.trim()) {
        saveWalletName(address, session.walletNameDraft);
      }
      setPassphrase("");
      await session.refresh();
      showToast(
        "Wallet created! Back up your secret in More → Security.",
        "success",
      );
      hapticSuccess();
    } catch (e) {
      showToast(formatInvokeError(e), "error");
    } finally {
      session.setBusy(false);
    }
  };

  const handleWatchOnly = async () => {
    session.setBusy(true);
    try {
      const address = await api.importWatchOnly(watchAddress.trim());
      if (session.walletNameDraft.trim()) {
        saveWalletName(address, session.walletNameDraft);
      }
      await api.openWatchOnly();
      setWatchAddress("");
      await session.refresh();
      showToast("Watch-only wallet ready.", "success");
      hapticSuccess();
    } catch (e) {
      showToast(formatInvokeError(e), "error");
    } finally {
      session.setBusy(false);
    }
  };

  const handleImport = async (expectedAddress: string) => {
    session.setBusy(true);
    try {
      const address = await api.import(seed, passphrase, expectedAddress);
      if (session.walletNameDraft.trim()) {
        saveWalletName(address, session.walletNameDraft);
      }
      setSeed("");
      setPassphrase("");
      await session.refresh();
      showToast("Wallet imported!", "success");
      hapticSuccess();
    } catch (e) {
      showToast(formatInvokeError(e), "error");
    } finally {
      session.setBusy(false);
    }
  };

  const handleRestoreBackup = async (
    json: string,
    backupPassphrase: string,
    allowLegacy: boolean,
  ) => {
    session.setBusy(true);
    try {
      const address = await api.importBackup(json, backupPassphrase, null, allowLegacy);
      if (session.walletNameDraft.trim()) {
        saveWalletName(address, session.walletNameDraft);
      }
      setPassphrase("");
      await session.refresh();
      showToast("Authenticated wallet backup restored.", "success");
      hapticSuccess();
    } catch (error) {
      showToast(formatInvokeError(error), "error");
    } finally {
      session.setBusy(false);
    }
  };

  const handleUnlock = async () => {
    session.setBusy(true);
    try {
      await api.unlock(passphrase);
      setPassphrase("");
      setPrivacyHidden(false);
      session.setAuthScreen("app");
      await session.refresh();
      setTab("home");
    } catch (e) {
      showToast(formatInvokeError(e), "error");
    } finally {
      session.setBusy(false);
    }
  };

  const handleBiometricUnlock = async () => {
    session.setBusy(true);
    try {
      await api.unlockBiometric();
      setPassphrase("");
      setPrivacyHidden(false);
      session.setAuthScreen("app");
      await session.refresh();
      setTab("home");
      hapticSuccess();
    } catch (e) {
      showToast(formatInvokeError(e), "error");
    } finally {
      session.setBusy(false);
    }
  };

  useEffect(() => {
    if (session.authScreen !== "unlock") {
      bioUnlockPrompted.current = false;
      return;
    }
    void api
      .biometricUnlockStatus()
      .then(setBiometricUnlock)
      .catch(() => setBiometricUnlock(null));
  }, [session.authScreen]);

  const bioUnlockReady =
    session.authScreen === "unlock" &&
    !!session.platformSec?.native_biometric_available &&
    !!biometricUnlock?.enabled &&
    !!biometricUnlock?.configured;

  useEffect(() => {
    if (!bioUnlockReady || bioUnlockPrompted.current || session.busy) return;
    // Arm the once-only latch when the prompt actually fires, not when it is
    // scheduled. This effect depends on `busy`, so any unrelated busy change
    // during the delay runs the cleanup and cancels the pending timeout. Setting
    // the latch up front made that cancellation permanent: the effect re-ran,
    // saw the latch, and returned, so the prompt never appeared at all.
    const t = window.setTimeout(() => {
      if (bioUnlockPrompted.current) return;
      bioUnlockPrompted.current = true;
      void handleBiometricUnlock();
    }, 400);
    return () => window.clearTimeout(t);
  }, [bioUnlockReady, session.busy]);

  const handleShareReceive = async () => {
    if (!session.status?.address) return;
    const amount =
      receiveAmount && Number(receiveAmount) > 0 ? Number(receiveAmount) : undefined;
    const uri = encodePaymentUri(session.status.address, amount);
    try {
      if (navigator.share) {
        await navigator.share({ title: "Hacash payment", text: uri, url: uri });
        showToast("Shared!", "success");
      } else {
        await copyWithPrivacyClear(uri, clipboardSecs);
        showToast("Payment link copied.", "success");
      }
    } catch (e) {
      if ((e as Error).name !== "AbortError") {
        showToast(formatInvokeError(e), "error");
      }
    }
  };

  const handleCopyAddress = async () => {
    if (!session.status?.address) return;
    await copyWithPrivacyClear(session.status.address, clipboardSecs);
    showToast("Address copied.", "success");
  };

  const handleResetWallet = async (
    currentPassphrase: string | null,
    confirmationAddress: string,
  ): Promise<boolean> => {
    session.setBusy(true);
    try {
      try {
        await api.resetWallet(currentPassphrase, confirmationAddress);
      } catch (error) {
        showToast(formatInvokeError(error), "error");
        return false;
      }
      try {
        clearAllWalletNames();
        setPassphrase("");
        setSeed("");
        await session.refresh();
        showToast("Wallet removed. You can create or import a new one.", "success");
      } catch (error) {
        showToast(
          `Wallet was removed, but the screen could not refresh. Restart the app. ${formatInvokeError(error)}`,
          "error",
        );
      }
      return true;
    } finally {
      session.setBusy(false);
    }
  };

  const handleSaveSettings = async (
    nodeUrl: string,
    hubUrl: string,
    fallbackUrls: string[],
    autoFailover: boolean,
  ) => {
    if (!session.settings) return;
    session.setBusy(true);
    try {
      const next = {
        ...session.settings,
        node_url: nodeUrl.trim(),
        node_fallback_urls: fallbackUrls,
        auto_node_failover: autoFailover,
        l2_hub_url: hubUrl.trim() || null,
      };
      await api.updateSettings(next);
      session.setSettings(next);
      await session.refresh();
      showToast("Settings saved.", "success");
    } catch (e) {
      showToast(formatInvokeError(e), "error");
    } finally {
      session.setBusy(false);
    }
  };

  const handleApplyHub = async (entry: import("./api").HubDiscoveryEntry) => {
    if (!session.settings || !entry.online) return;
    session.setBusy(true);
    try {
      const next = {
        ...session.settings,
        l2_hub_url: entry.hub_url,
        hub_right_address: entry.hub_address ?? session.settings.hub_right_address,
      };
      await api.updateSettings(next);
      session.setSettings(next);
      await session.refresh();
      showToast(`Using ${entry.name}`, "success");
    } catch (e) {
      showToast(formatInvokeError(e), "error");
      throw e;
    } finally {
      session.setBusy(false);
    }
  };

  const handleChangePassphrase = async (oldPass: string, newPass: string) => {
    if (newPass.length < MIN_WALLET_PASS) {
      showToast(`New passphrase must be at least ${MIN_WALLET_PASS} characters.`, "error");
      return;
    }
    session.setBusy(true);
    try {
      let outcome;
      try {
        outcome = await api.changePassphrase(oldPass, newPass);
      } catch (error) {
        showToast(formatInvokeError(error), "error");
        return;
      }
      let refreshWarning: string | null = null;
      try {
        await session.refresh();
      } catch (error) {
        refreshWarning = ` Wallet state refresh failed: ${formatInvokeError(error)}`;
      }
      if (outcome.nativeBiometricSecretCleared && !refreshWarning) {
        showToast(
          "Passphrase changed. Biometric unlock was disabled and its stored unlock secret was removed.",
          "success",
        );
      } else {
        const cleanupMessage = outcome.nativeBiometricSecretCleared
          ? "Passphrase changed. Biometric unlock was disabled and its stored unlock secret was removed."
          : outcome.warning ??
            "Passphrase changed and biometric unlock was disabled. Open Security and disable biometric unlock again to retry Android Keystore cleanup.";
        showToast(
          cleanupMessage + (refreshWarning ?? ""),
          "error",
        );
      }
    } finally {
      session.setBusy(false);
    }
  };

  const handleTabChange = useCallback(
    (next: TabId) => {
      if (next === "pay") {
        navigateToPay();
        return;
      }
      setTab(next);
      if (next === "more") setMorePage("menu");
    },
    [navigateToPay],
  );

  if (session.booting) {
    return (
      <>
        <SplashScreen />
        <PrivacyShield active={privacyHidden} />
      </>
    );
  }

  if (session.authScreen === "welcome") {
    return (
      <>
        <WelcomeScreen
          busy={session.busy}
          walletNameDraft={session.walletNameDraft}
          setWalletNameDraft={session.setWalletNameDraft}
          passphrase={passphrase}
          setPassphrase={setPassphrase}
          seed={seed}
          setSeed={setSeed}
          watchAddress={watchAddress}
          setWatchAddress={setWatchAddress}
          onCreate={() => void handleCreate()}
          onImport={(expected) => void handleImport(expected)}
          onRestoreBackup={(json, value, allowLegacy) => void handleRestoreBackup(json, value, allowLegacy)}
          onWatchOnly={() => void handleWatchOnly()}
          toast={toast}
        />
        <PrivacyShield active={privacyHidden} />
      </>
    );
  }

  if (session.authScreen === "unlock") {
    const bioReady = bioUnlockReady;
    return (
      <>
        <UnlockScreen
          busy={session.busy}
          displayName={displayName}
          addressHint={maskAddress(session.status?.address, false)}
          passphrase={passphrase}
          setPassphrase={setPassphrase}
          onUnlock={() => void handleUnlock()}
          biometricUnlockAvailable={bioReady}
          biometricKind={session.platformSec?.biometric_kind}
          onBiometricUnlock={() => void handleBiometricUnlock()}
          toast={toast}
        />
        <PrivacyShield active={privacyHidden} />
      </>
    );
  }

  return (
    <div className="app-shell">
      <header className="app-header">
        <div className="app-header-row">
          <div className="mobile-header-brand">
            <WalletLogo size="sm" variant="mark" />
            <div>
              <h1>HPAY</h1>
              <p className="sub">{displayName}</p>
            </div>
          </div>
          <span className="mobile-header-security" title={maskAddress(session.status?.address, session.privacy.hide_addresses)} aria-label="Encrypted wallet">
            <svg viewBox="0 0 24 24" aria-hidden><path d="M7 11V8a5 5 0 0 1 10 0v3M6 11h12v10H6z" /></svg>
          </span>
        </div>
      </header>

      <main className={tab === "home" ? "app-main app-main-home" : "app-main"}>
        {tab === "home" && (
          <HowItWorksPrompt
            copy={{
              title: t("docs.readPromptTitle"),
              body: t("docs.readPromptBody"),
              open: t("docs.howItWorks"),
              later: t("docs.readPromptLater"),
              never: t("docs.readPromptNever"),
            }}
            openExternal={openUrl}
            onError={(error) => showToast(formatInvokeError(error), "error")}
          />
        )}
        {tab === "home" && (
          <HomeTab
            assets={session.assets}
            status={session.status}
            history={session.history}
            hideBalances={session.privacy.hide_balances}
            refreshing={session.refreshing}
            watchOnly={session.watchOnly}
            fastPayReady={session.status?.fast_pay_state === "ready"}
            onOpenHistory={() => {
              setMorePage("history");
              setTab("more");
            }}
            onOpenAgent={onOpenAgent}
            onPullStart={onBalanceTouchStart}
            onPullMove={onBalanceTouchMove}
            onPullEnd={onBalanceTouchEnd}
            onSend={() => setTab("pay")}
            onReceive={() => setTab("receive")}
            onHacd={() => setTab("hacd")}
            onOpenFastPay={() => {
              setMorePage("fastpay");
              setTab("more");
            }}
          />
        )}

        {tab === "pay" && !session.watchOnly && (
          <PayTab
            assets={session.assets}
            busy={session.busy}
            contacts={contacts}
            sendTo={payment.sendTo}
            setSendTo={payment.setSendTo}
            sendAmount={payment.sendAmount}
            setSendAmount={payment.setSendAmount}
            sendHubFeePayer={payment.sendHubFeePayer}
            sendForceL1={payment.sendForceL1}
            setSendForceL1={payment.setSendForceL1}
            sendL1FeeSpeed={payment.sendL1FeeSpeed}
            setSendL1FeeSpeed={payment.setSendL1FeeSpeed}
            sendServiceFeeEnabled={payment.sendServiceFeeEnabled}
            setSendServiceFeeEnabled={payment.setSendServiceFeeEnabled}
            serviceFeeRate={payment.serviceFeeRate}
            preview={payment.preview}
            payScanMode={payment.payScanMode}
            setPayScanMode={payment.setPayScanMode}
            hideAddresses={session.privacy.hide_addresses}
            hideBalances={session.privacy.hide_balances}
            settings={session.settings}
            platformSec={session.platformSec}
            secondFactorThresholdMei={
              session.status?.require_second_factor_above_mei ?? null
            }
            dustWhisper={session.dustWhisper}
            onPersistSendPrefs={(h, f, s, svc) => void payment.persistSendPrefs(h, f, s, svc)}
            onPersistDustWhisper={(patch) => void session.persistDustWhisper(patch)}
            onResetPreview={payment.resetPreview}
            onPreviewSend={(speed) => void payment.handlePreviewSend(speed)}
            onConfirmSend={() => void payment.handleConfirmSend()}
            onPaymentQr={(p) => void payment.loadPaymentPayload(p, "qr")}
            onToast={showToast}
            onRefresh={() => session.refresh()}
            setBusy={session.setBusy}
          />
        )}

        {tab === "receive" && (
          <ReceiveTab
            address={session.status?.address}
            ownedHacdNames={session.assets?.hacd_names ?? []}
            receiveAmount={receiveAmount}
            setReceiveAmount={setReceiveAmount}
            hideAddresses={session.privacy.hide_addresses}
            clipboardSecs={clipboardSecs}
            onCopyAddress={() => void handleCopyAddress()}
            onShare={() => void handleShareReceive()}
            onToast={showToast}
          />
        )}

        {tab === "hacd" && (
          <HacdTab
            busy={session.busy}
            locked={!session.status || session.status.locked}
            onToast={showToast}
            onGoPay={() => navigateToPay()}
          />
        )}

        {tab === "more" && (
          <MoreRouter
            page={morePage}
            data={{
              history: session.history,
              bills: session.bills,
              contacts,
              dustWhisper: session.dustWhisper,
              privacy: session.privacy,
              settings: session.settings,
              hubHealth: session.hubHealth,
              platformSec: session.platformSec,
              status: session.status,
              fastPay: session.fastPay,
              watchOnly: session.watchOnly,
              statusAddress: session.status?.address,
              clipboardSecs,
              busy: session.busy,
            }}
            actions={{
              onBack: () => setMorePage("menu"),
              onNavigate: setMorePage,
              onClearHistory: () => void session.handleClearHistory(),
              onSaveSettings: (nodeUrl, hubUrl, fallbackUrls, autoFailover) =>
                void handleSaveSettings(nodeUrl, hubUrl, fallbackUrls, autoFailover),
              onApplyHub: (entry) => handleApplyHub(entry),
              onSaveWalletName: session.handleSaveWalletName,
              onChangePassphrase: (old, neu) => void handleChangePassphrase(old, neu),
              onResetWallet: handleResetWallet,
              onLock: () => void session.handleLock(),
              onPersistPrivacy: (p) => void session.persistPrivacy(p),
              onSelectContact: (c) => {
                payment.goToPayContact(c.address, c.label);
                navigateToPay();
              },
              onGoPayPeer: (peer) => {
                payment.goToPayContact(peer);
                navigateToPay();
                setMorePage("menu");
              },
              onGoLegacySend: () => {
                navigateToPay();
                setMorePage("menu");
              },
              onToast: showToast,
              onSelectBill: setSelectedBill,
              onRefresh: session.refresh,
              setBusy: session.setBusy,
              setContacts,
              walletNameDraft: session.walletNameDraft,
              setWalletNameDraft: session.setWalletNameDraft,
            }}
          />
        )}
      </main>

      <BottomNav active={tab} onChange={handleTabChange} onOpenAgent={onOpenAgent} watchOnly={session.watchOnly} />
      {session.status?.hardware_signing_mode !== "airgap_only" ? (
        <DappApprovalPanel onNotify={showToast} />
      ) : null}
      <PrivacyShield active={privacyHidden} />
      {toast && <Toast message={toast.msg} kind={toast.kind} />}
      <BillDetailModal
        bill={selectedBill}
        clipboardClearSecs={clipboardSecs}
        onClose={() => setSelectedBill(null)}
        onExportJson={(id) => api.exportBillJson(id)}
        onGetHex={(id) => api.getBillHex(id)}
      />

      <PreparedOperationConfirm />
    </div>
  );
}

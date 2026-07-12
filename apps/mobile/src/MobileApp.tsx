import { useCallback, useEffect, useRef, useState } from "react";
import { api, BillSummary, type BiometricUnlockStatus } from "./api";
import BottomNav, { type TabId } from "./components/BottomNav";
import BillDetailModal from "./components/BillDetailModal";
import MessengerScreen from "./components/MessengerScreen";
import PrivacyShield from "./components/PrivacyShield";
import Toast from "./components/Toast";
import WalletLogo from "./components/WalletLogo";
import { usePaymentFlow } from "./hooks/usePaymentFlow";
import { useToast } from "./hooks/useToast";
import { useWalletSession } from "./hooks/useWalletSession";
import HomeTab from "./screens/HomeTab";
import PayTab from "./screens/PayTab";
import ReceiveTab from "./screens/ReceiveTab";
import UnlockScreen from "./screens/UnlockScreen";
import WelcomeScreen from "./screens/WelcomeScreen";
import MoreRouter, { type MorePage } from "./screens/more/MoreRouter";
import { loadContacts, type SavedContact } from "./contacts";
import { formatInvokeError } from "./formatInvokeError";
import { encodePaymentUri } from "./paymentQr";
import { copyWithPrivacyClear, maskAddress } from "./privacy";
import { clearAllWalletNames, saveWalletName, walletDisplayName } from "./walletName";
import { MIN_WALLET_PASS } from "./quantumMeta";
import { clearDeepLink, parseDeepLinkPay, stashDeepLinkUrl } from "./utils/deepLink";
import { downloadJson } from "./utils/downloadJson";
import { hapticSuccess } from "./utils/haptic";
import { PULL_THRESHOLD } from "./utils/appConstants";

export default function MobileApp() {
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
  const [settingsNodeUrl, setSettingsNodeUrl] = useState("");
  const [settingsHubUrl, setSettingsHubUrl] = useState("");
  const [oldPass, setOldPass] = useState("");
  const [newPass, setNewPass] = useState("");
  const [backupPass, setBackupPass] = useState("");
  const [contactLabel, setContactLabel] = useState("");
  const [contactAddress, setContactAddress] = useState("");
  const [payCameraIntent, setPayCameraIntent] = useState(false);

  const pullStartY = useRef(0);
  const pullOffset = useRef(0);
  const deepLinkHandled = useRef(false);
  const bioUnlockPrompted = useRef(false);
  const [deepLinkTick, setDeepLinkTick] = useState(0);
  const [biometricUnlock, setBiometricUnlock] = useState<BiometricUnlockStatus | null>(null);

  const clipboardSecs = session.privacy.clipboard_clear_secs;
  const displayName = walletDisplayName(session.status?.address, session.walletName);

  const payment = usePaymentFlow({
    settings: session.settings,
    setSettings: session.setSettings,
    platformSec: session.platformSec,
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
      setSettingsNodeUrl(session.settings.node_url);
      setSettingsHubUrl(session.settings.l2_hub_url ?? "");
    }
  }, [session.settings, syncSendPrefsFromSettings]);

  useEffect(() => {
    if (!session.privacy.screen_privacy || session.authScreen !== "app") {
      setPrivacyHidden(false);
      return;
    }
    const onHide = () => setPrivacyHidden(document.hidden);
    const onBlur = () => setPrivacyHidden(true);
    const onFocus = () => setPrivacyHidden(false);
    document.addEventListener("visibilitychange", onHide);
    window.addEventListener("blur", onBlur);
    window.addEventListener("focus", onFocus);
    return () => {
      document.removeEventListener("visibilitychange", onHide);
      window.removeEventListener("blur", onBlur);
      window.removeEventListener("focus", onFocus);
    };
  }, [session.privacy.screen_privacy, session.authScreen]);

  const navigateToPay = useCallback(
    (opts?: { openCamera?: boolean }) => {
      payment.setPayScanMode(false);
      setPayCameraIntent(false);
      if (opts?.openCamera) {
        payment.setPayScanMode(true);
        setPayCameraIntent(true);
      }
      setTab("pay");
    },
    [payment],
  );

  useEffect(() => {
    if (tab !== "pay") {
      payment.setPayScanMode(false);
      setPayCameraIntent(false);
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
      showToast("Wallet created!", "success");
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

  const handleImport = async () => {
    session.setBusy(true);
    try {
      const address = await api.import(seed, passphrase);
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
    bioUnlockPrompted.current = true;
    const t = window.setTimeout(() => void handleBiometricUnlock(), 400);
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

  const handleResetWallet = async () => {
    const ok1 = window.confirm(
      "Delete this wallet from the phone? You will need your seed/backup to recover funds.",
    );
    if (!ok1) return;
    const ok2 = window.confirm("This cannot be undone. Delete wallet now?");
    if (!ok2) return;
    session.setBusy(true);
    try {
      await api.resetWallet();
      clearAllWalletNames();
      setPassphrase("");
      setSeed("");
      await session.refresh();
      showToast("Wallet removed. You can create or import a new one.", "success");
    } catch (e) {
      showToast(formatInvokeError(e), "error");
    } finally {
      session.setBusy(false);
    }
  };

  const handleSaveSettings = async () => {
    if (!session.settings) return;
    session.setBusy(true);
    try {
      const next = {
        ...session.settings,
        node_url: settingsNodeUrl.trim(),
        l2_hub_url: settingsHubUrl.trim() || null,
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
      setSettingsHubUrl(entry.hub_url);
      await session.refresh();
      showToast(`Using ${entry.name}`, "success");
    } catch (e) {
      showToast(formatInvokeError(e), "error");
      throw e;
    } finally {
      session.setBusy(false);
    }
  };

  const handleExportBackup = async () => {
    session.setBusy(true);
    try {
      const json = await api.exportBackup(backupPass);
      downloadJson(`hacash-backup-${Date.now()}.json`, json);
      setBackupPass("");
      showToast("Backup downloaded.", "success");
    } catch (e) {
      showToast(formatInvokeError(e), "error");
    } finally {
      session.setBusy(false);
    }
  };

  const handleChangePassphrase = async () => {
    if (newPass.length < MIN_WALLET_PASS) {
      showToast(`New passphrase must be at least ${MIN_WALLET_PASS} characters.`, "error");
      return;
    }
    session.setBusy(true);
    try {
      await api.changePassphrase(oldPass, newPass);
      setOldPass("");
      setNewPass("");
      showToast("Passphrase changed.", "success");
    } catch (e) {
      showToast(formatInvokeError(e), "error");
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

  if (session.authScreen === "welcome") {
    return (
      <WelcomeScreen
        walletNameDraft={session.walletNameDraft}
        setWalletNameDraft={session.setWalletNameDraft}
        passphrase={passphrase}
        setPassphrase={setPassphrase}
        seed={seed}
        setSeed={setSeed}
        watchAddress={watchAddress}
        setWatchAddress={setWatchAddress}
        busy={session.busy}
        onCreate={() => void handleCreate()}
        onImport={() => void handleImport()}
        onWatchOnly={() => void handleWatchOnly()}
        toast={toast}
      />
    );
  }

  if (session.authScreen === "unlock") {
    const bioReady = bioUnlockReady;
    return (
      <UnlockScreen
        displayName={displayName}
        addressHint={maskAddress(session.status?.address, false)}
        passphrase={passphrase}
        setPassphrase={setPassphrase}
        busy={session.busy}
        onUnlock={() => void handleUnlock()}
        biometricUnlockAvailable={bioReady}
        biometricKind={session.platformSec?.biometric_kind}
        onBiometricUnlock={() => void handleBiometricUnlock()}
        toast={toast}
      />
    );
  }

  return (
    <div className="app-shell">
      <header className="app-header">
        <div className="app-header-row">
          <WalletLogo size="sm" />
          <div>
            <h1>{displayName}</h1>
            <p className="sub">{maskAddress(session.status?.address, session.privacy.hide_addresses)}</p>
          </div>
        </div>
      </header>

      <main className="app-main">
        {tab === "home" && (
          <HomeTab
            assets={session.assets}
            hideBalances={session.privacy.hide_balances}
            refreshing={session.refreshing}
            fastPay={session.fastPay}
            watchOnly={session.watchOnly}
            busy={session.busy}
            history={session.history}
            onPullStart={onBalanceTouchStart}
            onPullMove={onBalanceTouchMove}
            onPullEnd={onBalanceTouchEnd}
            onEnableFastPay={() => void session.handleEnableFastPay()}
            onDisableFastPay={() => void session.handleDisableFastPay()}
            onScanPay={() => navigateToPay({ openCamera: true })}
            onReceive={() => setTab("receive")}
            onContacts={() => {
              setMorePage("contacts");
              setTab("more");
            }}
            onHistory={() => {
              setMorePage("history");
              setTab("more");
            }}
            onQuantum={() => {
              setMorePage("quantum");
              setTab("more");
            }}
            onLaunchpad={() => {
              setMorePage("launchpad");
              setTab("more");
            }}
          />
        )}

        {tab === "pay" && !session.watchOnly && (
          <PayTab
            contacts={contacts}
            sendTo={payment.sendTo}
            setSendTo={payment.setSendTo}
            sendAmount={payment.sendAmount}
            setSendAmount={payment.setSendAmount}
            sendHubFeePayer={payment.sendHubFeePayer}
            setSendHubFeePayer={payment.setSendHubFeePayer}
            sendForceL1={payment.sendForceL1}
            setSendForceL1={payment.setSendForceL1}
            preview={payment.preview}
            payScanMode={payment.payScanMode}
            setPayScanMode={payment.setPayScanMode}
            payCameraIntent={payCameraIntent}
            onCameraIntentConsumed={() => setPayCameraIntent(false)}
            hideAddresses={session.privacy.hide_addresses}
            settings={session.settings}
            platformSec={session.platformSec}
            busy={session.busy}
            onPersistSendPrefs={(h, f) => void payment.persistSendPrefs(h, f)}
            onResetPreview={payment.resetPreview}
            onPreviewSend={() => void payment.handlePreviewSend()}
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
            receiveAmount={receiveAmount}
            setReceiveAmount={setReceiveAmount}
            clipboardSecs={clipboardSecs}
            onCopyAddress={() => void handleCopyAddress()}
            onShare={() => void handleShareReceive()}
            onToast={showToast}
          />
        )}

        {tab === "messages" && (
          <MessengerScreen
            myAddress={session.status?.address}
            hideAddresses={session.privacy.hide_addresses}
            whisperEnabled={session.dustWhisper?.enabled}
            contacts={contacts}
            onToast={showToast}
            onGoPay={(peer) => {
              payment.goToPayContact(peer);
              navigateToPay();
            }}
          />
        )}

        {tab === "more" && (
          <MoreRouter
            page={morePage}
            onBack={() => setMorePage("menu")}
            onNavigate={setMorePage}
            history={session.history}
            bills={session.bills}
            contacts={contacts}
            setContacts={setContacts}
            dustWhisper={session.dustWhisper}
            privacy={session.privacy}
            settings={session.settings}
            hubHealth={session.hubHealth}
            platformSec={session.platformSec}
            status={session.status}
            fastPay={session.fastPay}
            watchOnly={session.watchOnly}
            statusAddress={session.status?.address}
            clipboardSecs={clipboardSecs}
            busy={session.busy}
            settingsNodeUrl={settingsNodeUrl}
            setSettingsNodeUrl={setSettingsNodeUrl}
            settingsHubUrl={settingsHubUrl}
            setSettingsHubUrl={setSettingsHubUrl}
            walletNameDraft={session.walletNameDraft}
            setWalletNameDraft={session.setWalletNameDraft}
            backupPass={backupPass}
            setBackupPass={setBackupPass}
            oldPass={oldPass}
            setOldPass={setOldPass}
            newPass={newPass}
            setNewPass={setNewPass}
            contactLabel={contactLabel}
            setContactLabel={setContactLabel}
            contactAddress={contactAddress}
            setContactAddress={setContactAddress}
            onClearHistory={() => void session.handleClearHistory()}
            onSaveSettings={() => void handleSaveSettings()}
            onApplyHub={(entry) => handleApplyHub(entry)}
            onSaveWalletName={session.handleSaveWalletName}
            onExportBackup={() => void handleExportBackup()}
            onChangePassphrase={() => void handleChangePassphrase()}
            onResetWallet={() => void handleResetWallet()}
            onLock={() => void session.handleLock()}
            onPersistPrivacy={(p) => void session.persistPrivacy(p)}
            onSelectContact={(c) => {
              payment.goToPayContact(c.address, c.label);
              navigateToPay();
            }}
            onGoPayPeer={(peer) => {
              payment.goToPayContact(peer);
              navigateToPay();
              setMorePage("menu");
            }}
            onGoLegacySend={() => {
              navigateToPay();
              setMorePage("menu");
            }}
            onToast={showToast}
            onSelectBill={setSelectedBill}
            onRefresh={session.refresh}
            setBusy={session.setBusy}
          />
        )}
      </main>

      <BottomNav active={tab} onChange={handleTabChange} watchOnly={session.watchOnly} />
      <PrivacyShield active={session.privacy.screen_privacy && privacyHidden} />
      {toast && <Toast message={toast.msg} kind={toast.kind} />}
      <BillDetailModal
        bill={selectedBill}
        clipboardClearSecs={clipboardSecs}
        onClose={() => setSelectedBill(null)}
        onExportJson={(id) => api.exportBillJson(id)}
        onGetHex={(id) => api.getBillHex(id)}
      />
    </div>
  );
}
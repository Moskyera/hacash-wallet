import { useCallback, useEffect, useState } from "react";
import {
  api,
  AssetSummary,
  ChannelInfo,
  ChannelSetupPreview,
  DustWhisperSettings,
  HubDiscoveryEntry,
  HubHealth,
  PrivacySettings,
  RelayHealthStatus,
  TxRecord,
  WalletSettings,
  WalletStatus,
} from "../api";
import { formatInvokeError } from "../formatInvokeError";
import { DEFAULT_DUST_WHISPER, DEFAULT_PRIVACY, copyWithPrivacyClear } from "../privacy";
import { runWebAuthnAuth, runWebAuthnRegister, webAuthnAvailable } from "../webauthn";
import type { ToastKind } from "./useToast";
import type { Screen } from "../screens/types";
import type { FastPayStatus } from "../fastPayUi";

type ShowToast = (msg: string, kind?: ToastKind) => void;

export function useDesktopWallet(
  showToast: ShowToast,
  screen: Screen,
  setScreen: (s: Screen) => void,
) {
  const [status, setStatus] = useState<WalletStatus | null>(null);
  const [settings, setSettings] = useState<WalletSettings | null>(null);
  const [balance, setBalance] = useState<number | null>(null);
  const [assets, setAssets] = useState<AssetSummary | null>(null);
  const [error, setError] = useState("");
  const [info, setInfo] = useState("");
  const [busy, setBusy] = useState(false);

  const [fastPayDetail, setFastPayDetail] = useState<FastPayStatus | null>(null);
  const [channelInfo, setChannelInfo] = useState<ChannelInfo | null>(null);
  const [hubHealth, setHubHealth] = useState<HubHealth | null | undefined>(undefined);
  const [billsCount, setBillsCount] = useState(0);
  const [txHistory, setTxHistory] = useState<TxRecord[]>([]);
  const [lastTx, setLastTx] = useState("");

  const [webauthnReady, setWebauthnReady] = useState(false);
  const [nativeBioAvailable, setNativeBioAvailable] = useState(false);
  const [relayHealth, setRelayHealth] = useState<RelayHealthStatus[]>([]);

  const privacy = status?.privacy ?? DEFAULT_PRIVACY;
  const dustWhisper = status?.dust_whisper ?? DEFAULT_DUST_WHISPER;

  const onError = useCallback(
    (msg: string) => {
      setError(msg);
      showToast(msg, "error");
    },
    [showToast],
  );

  const onInfo = useCallback(
    (msg: string) => {
      setInfo(msg);
      showToast(msg, "info");
    },
    [showToast],
  );

  const clearMessages = useCallback(() => {
    setError("");
    setInfo("");
  }, []);

  const refreshStatus = useCallback(async () => {
    let s = await api.status();
    if (s.has_wallet && s.watch_only && s.locked) {
      await api.openWatchOnly();
      s = await api.status();
    }
    setStatus(s);
    if (!s.has_wallet) setScreen("welcome");
    else if (s.locked) setScreen("unlock");
    return s;
  }, [setScreen]);

  const refreshSettings = useCallback(async () => {
    const s = await api.getSettings();
    setSettings(s);
    return s;
  }, []);

  const refreshBalance = useCallback(async () => {
    try {
      const summary = await api.assetSummary();
      setAssets(summary);
      setBalance(summary.hac_mei);
    } catch {
      setAssets(null);
      setBalance(null);
    }
  }, []);

  const refreshChannel = useCallback(async () => {
    try {
      const info = await api.channelInfo();
      setChannelInfo(info);
    } catch {
      setChannelInfo(null);
    }
  }, []);

  const refreshBills = useCallback(async () => {
    try {
      const bills = await api.listBills();
      setBillsCount(bills.length);
    } catch {
      setBillsCount(0);
    }
  }, []);

  const refreshHistory = useCallback(async () => {
    try {
      const rows = await api.txHistory();
      setTxHistory(rows);
      if (rows.length > 0) setLastTx(rows[0].tx_hash);
    } catch {
      setTxHistory([]);
    }
  }, []);

  const refreshFastPay = useCallback(async () => {
    try {
      const fp = await api.fastPayStatus();
      setFastPayDetail(fp);
    } catch {
      setFastPayDetail(null);
    }
  }, []);

  const refreshUnlockedData = useCallback(async () => {
    await Promise.all([
      refreshBalance(),
      refreshSettings(),
      refreshChannel(),
      refreshBills(),
      refreshHistory(),
      refreshFastPay(),
    ]);
  }, [refreshBalance, refreshSettings, refreshChannel, refreshBills, refreshHistory, refreshFastPay]);

  const refreshRelayHealth = useCallback(async () => {
    if (!dustWhisper.enabled || dustWhisper.relay_urls.length === 0) {
      setRelayHealth([]);
      return;
    }
    try {
      const rows = await api.whisperRelayHealth();
      setRelayHealth(rows);
    } catch {
      setRelayHealth([]);
    }
  }, [dustWhisper.enabled, dustWhisper.relay_urls.join("|")]);

  useEffect(() => {
    setWebauthnReady(webAuthnAvailable());
    api.platformSecurityStatus()
      .then((p) => setNativeBioAvailable(p.native_biometric_available))
      .catch(() => {});
    refreshStatus().catch((e) => onError(String(e)));
  }, [refreshStatus, onError]);

  const relayUrlsKey = dustWhisper.relay_urls.join("|");

  useEffect(() => {
    if (!dustWhisper.enabled) {
      setRelayHealth([]);
      return;
    }
    refreshRelayHealth().catch(() => undefined);
    const id = window.setInterval(() => {
      refreshRelayHealth().catch(() => undefined);
    }, 5000);
    return () => window.clearInterval(id);
  }, [dustWhisper.enabled, relayUrlsKey, refreshRelayHealth]);

  // Load wallet data when unlocking or switching wallets — NOT on every tab click.
  useEffect(() => {
    if (!status || status.locked) return;
    refreshUnlockedData().catch(() => undefined);
  }, [status?.locked, status?.address, refreshUnlockedData]);

  useEffect(() => {
    if (status && !status.locked && (screen === "welcome" || screen === "unlock")) {
      setScreen("home");
    }
  }, [status?.locked, screen, setScreen]);

  // Tick auto-lock countdown locally; full status sync stays on the 5s poll.
  useEffect(() => {
    if (!status || status.locked || status.seconds_until_lock == null) return;
    const id = window.setInterval(() => {
      setStatus((prev) => {
        if (!prev || prev.locked || prev.seconds_until_lock == null) return prev;
        if (prev.seconds_until_lock <= 0) return prev;
        return { ...prev, seconds_until_lock: prev.seconds_until_lock - 1 };
      });
    }, 1000);
    return () => window.clearInterval(id);
  }, [status?.locked, status?.seconds_until_lock]);

  useEffect(() => {
    if (!status || status.locked) return;
    const timer = window.setInterval(() => {
      refreshStatus().catch(() => undefined);
    }, 5000);
    return () => window.clearInterval(timer);
  }, [status?.locked, refreshStatus]);

  useEffect(() => {
    if (screen !== "history" || !status || status.locked) return;
    const id = window.setTimeout(() => {
      refreshHistory().catch(() => undefined);
    }, 0);
    return () => window.clearTimeout(id);
  }, [screen, status?.locked, refreshHistory]);

  useEffect(() => {
    if (screen !== "fastpay" || !status || status.locked) return;
    const id = window.setTimeout(() => {
      void Promise.all([refreshFastPay(), refreshChannel(), refreshBills()]);
    }, 0);
    return () => window.clearTimeout(id);
  }, [screen, status?.locked, refreshFastPay, refreshChannel, refreshBills]);

  const handleCreate = useCallback(
    async (passphrase: string) => {
      setBusy(true);
      clearMessages();
      try {
        await api.create(passphrase);
        await refreshStatus();
        onInfo(
          "Wallet created. Back up your secret in Security. Your passphrase only unlocks this device.",
        );
      } catch (e) {
        onError(String(e));
      } finally {
        setBusy(false);
      }
    },
    [clearMessages, refreshStatus, onInfo, onError],
  );

  const handleWatchOnlyImport = useCallback(
    async (watchAddress: string) => {
      setBusy(true);
      clearMessages();
      try {
        await api.importWatchOnly(watchAddress.trim());
        await refreshStatus();
        onInfo("Watch-only wallet added. You can monitor balance — signing requires a hardware device.");
      } catch (e) {
        onError(String(e));
      } finally {
        setBusy(false);
      }
    },
    [clearMessages, refreshStatus, onInfo, onError],
  );

  const handleSetHardwareMode = useCallback(
    async (mode: "software" | "webauthn_gate" | "watch_only") => {
      setBusy(true);
      clearMessages();
      try {
        await api.setHardwareMode(mode);
        await refreshStatus();
        onInfo(`Hardware signing mode: ${mode}`);
      } catch (e) {
        onError(String(e));
      } finally {
        setBusy(false);
      }
    },
    [clearMessages, refreshStatus, onInfo, onError],
  );

  const handleImport = useCallback(
    async (importSeed: string, importPassphrase: string) => {
      setBusy(true);
      clearMessages();
      try {
        await api.import(importSeed.trim(), importPassphrase);
        await refreshStatus();
        onInfo("Wallet imported. Unlock with your new passphrase.");
      } catch (e) {
        onError(String(e));
      } finally {
        setBusy(false);
      }
    },
    [clearMessages, refreshStatus, onInfo, onError],
  );

  const handleImportBackup = useCallback(
    async (json: string, passphrase: string, deleteSource?: string | null) => {
      setBusy(true);
      clearMessages();
      try {
        await api.importBackup(json.trim(), passphrase, deleteSource);
        await refreshStatus();
        onInfo(
          "Wallet restored from backup. The backup file was removed when possible — check Downloads if you imported from there.",
        );
      } catch (e) {
        onError(String(e));
      } finally {
        setBusy(false);
      }
    },
    [clearMessages, refreshStatus, onInfo, onError],
  );

  const handleUnlock = useCallback(
    async (passphrase: string) => {
      setBusy(true);
      clearMessages();
      try {
        await api.unlock(passphrase);
        await refreshStatus();
        await refreshUnlockedData();
        setScreen("home");
      } catch (e) {
        onError(String(e));
      } finally {
        setBusy(false);
      }
    },
    [clearMessages, refreshStatus, refreshUnlockedData, setScreen, onError],
  );

  const handleLock = useCallback(async () => {
    try {
      await api.dappBridgeStop();
    } catch {
      /* bridge may not be running */
    }
    clearMessages();
    await api.lock();
    setBalance(null);
    setHubHealth(undefined);
    setWebauthnReady(webAuthnAvailable());
    await refreshStatus();
  }, [clearMessages, refreshStatus]);

  const handleEnableFastPay = useCallback(
    async (userDeposit: string) => {
      setBusy(true);
      clearMessages();
      try {
        const fp = await api.enableFastPay(Number(userDeposit) || 10);
        setFastPayDetail(fp);
        await refreshStatus();
        await refreshUnlockedData();
        onInfo("Fast Pay is ready — your next send can be instant.");
      } catch (e) {
        onError(formatInvokeError(e));
      } finally {
        setBusy(false);
      }
    },
    [clearMessages, refreshStatus, refreshUnlockedData, onInfo, onError],
  );

  const handleApplyHub = useCallback(
    async (entry: HubDiscoveryEntry) => {
      if (!settings || !entry.online) return;
      setBusy(true);
      clearMessages();
      try {
        const next: WalletSettings = {
          ...settings,
          l2_hub_url: entry.hub_url,
          hub_right_address: entry.hub_address ?? settings.hub_right_address,
        };
        await api.updateSettings(next);
        setSettings(next);
        await refreshStatus();
        await refreshFastPay();
        setHubHealth(undefined);
        onInfo(`Using ${entry.name}`);
      } catch (e) {
        onError(formatInvokeError(e));
        throw e;
      } finally {
        setBusy(false);
      }
    },
    [settings, clearMessages, refreshStatus, refreshFastPay, onInfo, onError],
  );

  const handleSaveL2Settings = useCallback(
    async (nodeUrl: string, hubUrl: string, hubAddress: string) => {
      if (!settings) return;
      setBusy(true);
      clearMessages();
      try {
        const next: WalletSettings = {
          ...settings,
          node_url: nodeUrl.trim(),
          l2_hub_url: hubUrl.trim() || null,
          hub_right_address: hubAddress.trim() || settings.hub_right_address,
        };
        await api.updateSettings(next);
        await refreshSettings();
        await refreshStatus();
        setHubHealth(undefined);
        onInfo("L2 settings saved.");
      } catch (e) {
        onError(String(e));
      } finally {
        setBusy(false);
      }
    },
    [settings, clearMessages, refreshSettings, refreshStatus, onInfo, onError],
  );

  const handleHubHealth = useCallback(async () => {
    setBusy(true);
    clearMessages();
    try {
      const health = await api.hubHealth();
      setHubHealth(health);
      if (!health) onInfo("No hub URL configured.");
      else if (health.ok)
        onInfo(`Hub healthy: ${health.name ?? "unknown"} (v${health.version})`);
      else onError("Hub health check failed.");
    } catch (e) {
      onError(String(e));
      setHubHealth(null);
    } finally {
      setBusy(false);
    }
  }, [clearMessages, onInfo, onError]);

  const handlePreviewChannel = useCallback(
    async (
      hubAddress: string,
      userDeposit: string,
      hubDeposit: string,
      setChannelPreview: (p: ChannelSetupPreview | null) => void,
    ) => {
      setBusy(true);
      clearMessages();
      setChannelPreview(null);
      try {
        const p = await api.previewChannelOpen(
          hubAddress.trim(),
          Number(userDeposit),
          Number(hubDeposit),
        );
        setChannelPreview(p);
      } catch (e) {
        onError(String(e));
      } finally {
        setBusy(false);
      }
    },
    [clearMessages, onError],
  );

  const handleOpenChannel = useCallback(
    async (
      hubAddress: string,
      userDeposit: string,
      hubDeposit: string,
      setChannelPreview: (p: ChannelSetupPreview | null) => void,
    ) => {
      setBusy(true);
      clearMessages();
      try {
        const hash = await api.openChannel(
          hubAddress.trim(),
          Number(userDeposit),
          Number(hubDeposit),
        );
        onInfo(`Channel open submitted: ${hash}`);
        setChannelPreview(null);
        await refreshStatus();
        await refreshChannel();
        await refreshBills();
      } catch (e) {
        onError(String(e));
      } finally {
        setBusy(false);
      }
    },
    [clearMessages, refreshStatus, refreshChannel, refreshBills, onInfo, onError],
  );

  const handleCloseChannel = useCallback(
    async (setChannelPreview: (p: ChannelSetupPreview | null) => void) => {
      setBusy(true);
      clearMessages();
      try {
        const hash = await api.closeChannel();
        onInfo(`Channel close submitted: ${hash}`);
        setChannelPreview(null);
        await refreshStatus();
        await refreshChannel();
      } catch (e) {
        onError(String(e));
      } finally {
        setBusy(false);
      }
    },
    [clearMessages, refreshStatus, refreshChannel, onInfo, onError],
  );

  const handleRegisterWebAuthn = useCallback(async () => {
    if (!webauthnReady) {
      onError("WebAuthn not available in this environment.");
      return;
    }
    setBusy(true);
    clearMessages();
    try {
      const options = await api.webauthnRegisterBegin();
      const cred = await runWebAuthnRegister(options);
      await api.webauthnRegisterFinish(cred);
      await refreshStatus();
      onInfo("YubiKey / Windows Hello registered.");
    } catch (e) {
      onError(String(e));
    } finally {
      setBusy(false);
    }
  }, [webauthnReady, clearMessages, refreshStatus, onInfo, onError]);

  const handleWebAuthnSession = useCallback(async () => {
    if (!webauthnReady || !status?.webauthn_enabled) return;
    setBusy(true);
    clearMessages();
    try {
      const options = await api.webauthnAuthBegin();
      const assertion = await runWebAuthnAuth(options);
      await api.webauthnAuthFinish(assertion);
      await refreshStatus();
      onInfo("WebAuthn verified for this session.");
    } catch (e) {
      onError(String(e));
    } finally {
      setBusy(false);
    }
  }, [webauthnReady, status?.webauthn_enabled, clearMessages, refreshStatus, onInfo, onError]);

  const handleSaveSettings = useCallback(
    async (nodeUrl: string) => {
      if (!settings) return;
      setBusy(true);
      clearMessages();
      try {
        const next: WalletSettings = { ...settings, node_url: nodeUrl.trim() };
        await api.updateSettings(next);
        await refreshSettings();
        await refreshStatus();
        onInfo("Node URL saved.");
      } catch (e) {
        onError(String(e));
      } finally {
        setBusy(false);
      }
    },
    [settings, clearMessages, refreshSettings, refreshStatus, onInfo, onError],
  );

  const handleChangePassphrase = useCallback(
    async (oldPassphrase: string, newPassphrase: string, confirmPassphrase: string) => {
      if (newPassphrase !== confirmPassphrase) {
        onError("New passphrase and confirmation do not match.");
        return false;
      }
      if (newPassphrase.length < 8) {
        onError("New passphrase must be at least 8 characters.");
        return false;
      }
      setBusy(true);
      clearMessages();
      try {
        await api.changePassphrase(oldPassphrase, newPassphrase);
        onInfo("Passphrase changed.");
        return true;
      } catch (e) {
        onError(String(e));
        return false;
      } finally {
        setBusy(false);
      }
    },
    [clearMessages, onInfo, onError],
  );

  const handleExportBackup = useCallback(
    async (exportPassphrase: string) => {
      setBusy(true);
      clearMessages();
      try {
        const json = await api.exportBackup(exportPassphrase);
        const blob = new Blob([json], { type: "application/json" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = "hacash-wallet-backup.json";
        a.click();
        URL.revokeObjectURL(url);
        onInfo("Backup exported and shown below.");
        return json;
      } catch (e) {
        onError(String(e));
        return null;
      } finally {
        setBusy(false);
      }
    },
    [clearMessages, onInfo, onError],
  );

  const handleValidateHip23 = useCallback(
    async (params: {
      hipTxType: string;
      hipChainHeight: string;
      hipGasMax: string;
      hipHasAssetTex: boolean;
      hipAstDepth: string;
      hipGuardOnly: boolean;
      hipActionCount: string;
      includeP2: boolean;
      hipP2Start: string;
      hipP2End: string;
      hipP2GuardBeforeDebit: boolean;
      includeP3: boolean;
      hipP3Floor: string;
      hipP3DebitBeforeFloor: boolean;
    }) => {
      setBusy(true);
      clearMessages();
      try {
        const universal = {
          tx_type: Number(params.hipTxType),
          chain_height: Number(params.hipChainHeight),
          gas_max: Number(params.hipGasMax),
          has_asset_tex: params.hipHasAssetTex,
          ast_depth: Number(params.hipAstDepth),
          guard_only: params.hipGuardOnly,
          action_count: Number(params.hipActionCount),
        };
        const p2 = params.includeP2
          ? {
              start: Number(params.hipP2Start),
              end: Number(params.hipP2End),
              guard_before_debit: params.hipP2GuardBeforeDebit,
            }
          : null;
        const p3 = params.includeP3
          ? {
              floor_hacash_mei: Number(params.hipP3Floor),
              debit_before_floor: params.hipP3DebitBeforeFloor,
            }
          : null;
        const results = await api.validateHip23(universal, p2, p3);
        onInfo("HIP-23 pattern validation complete.");
        return results;
      } catch (e) {
        onError(String(e));
        return null;
      } finally {
        setBusy(false);
      }
    },
    [clearMessages, onInfo, onError],
  );

  const handleSavePrivacy = useCallback(
    async (privacyDraft: PrivacySettings) => {
      setBusy(true);
      clearMessages();
      try {
        await api.updatePrivacySettings(privacyDraft);
        await refreshStatus();
        onInfo("Privacy settings saved.");
      } catch (e) {
        onError(String(e));
      } finally {
        setBusy(false);
      }
    },
    [clearMessages, refreshStatus, onInfo, onError],
  );

  const handleSaveWhisper = useCallback(
    async (whisperDraft: DustWhisperSettings, whisperRelayText: string) => {
      setBusy(true);
      clearMessages();
      try {
        const relay_urls = whisperRelayText
          .split(/\r?\n/)
          .map((line) => line.trim())
          .filter(Boolean);
        const next: DustWhisperSettings = {
          ...whisperDraft,
          relay_urls,
        };
        if (next.enabled && relay_urls.length === 0) {
          onError("Add at least one relay URL to enable DUST Whisper.");
          return null;
        }
        await api.updateDustWhisperSettings(next);
        await refreshStatus();
        await refreshRelayHealth();
        onInfo("DUST Whisper settings saved.");
        return next;
      } catch (e) {
        onError(String(e));
        return null;
      } finally {
        setBusy(false);
      }
    },
    [clearMessages, refreshStatus, refreshRelayHealth, onInfo, onError],
  );

  const handleClearHistory = useCallback(async () => {
    setBusy(true);
    clearMessages();
    try {
      await api.clearTxHistory();
      setTxHistory([]);
      onInfo("Local transaction history cleared.");
    } catch (e) {
      onError(String(e));
    } finally {
      setBusy(false);
    }
  }, [clearMessages, onInfo, onError]);

  const handleCopyAddress = useCallback(async () => {
    if (!status?.address) return;
    clearMessages();
    try {
      await copyWithPrivacyClear(status.address, privacy.clipboard_clear_secs);
      onInfo(
        privacy.clipboard_clear_secs > 0
          ? `Address copied — clipboard clears in ${privacy.clipboard_clear_secs}s.`
          : "Address copied.",
      );
    } catch (e) {
      onError(String(e));
    }
  }, [status?.address, privacy.clipboard_clear_secs, clearMessages, onInfo, onError]);

  const handleSetProfile = useCallback(
    async (profile: string) => {
      setBusy(true);
      clearMessages();
      try {
        await api.setSecurityProfile(profile);
        await refreshStatus();
        onInfo(`Security profile set to ${profile}.`);
      } catch (e) {
        onError(String(e));
      } finally {
        setBusy(false);
      }
    },
    [clearMessages, refreshStatus, onInfo, onError],
  );

  const setLastTxHash = useCallback((hash: string) => {
    setLastTx(hash);
  }, []);

  return {
    status,
    settings,
    balance,
    assets,
    error,
    info,
    busy,
    setBusy,
    fastPayDetail,
    channelInfo,
    hubHealth,
    billsCount,
    txHistory,
    lastTx,
    webauthnReady,
    nativeBioAvailable,
    relayHealth,
    privacy,
    dustWhisper,
    clearMessages,
    onError,
    onInfo,
    refreshStatus,
    refreshSettings,
    refreshBalance,
    refreshChannel,
    refreshBills,
    refreshHistory,
    refreshFastPay,
    refreshUnlockedData,
    refreshRelayHealth,
    handleCreate,
    handleImport,
    handleImportBackup,
    handleWatchOnlyImport,
    handleUnlock,
    handleLock,
    handleEnableFastPay,
    handleApplyHub,
    handleSaveL2Settings,
    handleHubHealth,
    handlePreviewChannel,
    handleOpenChannel,
    handleCloseChannel,
    handleRegisterWebAuthn,
    handleWebAuthnSession,
    handleSaveSettings,
    handleChangePassphrase,
    handleExportBackup,
    handleSavePrivacy,
    handleSaveWhisper,
    handleClearHistory,
    handleCopyAddress,
    handleSetProfile,
    handleSetHardwareMode,
    handleValidateHip23,
    setLastTxHash,
  };
}
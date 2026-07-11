import { useCallback, useEffect, useState } from "react";
import {
  api,
  BillSummary,
  FastPayStatus,
  HubHealth,
  PlatformSecurityStatus,
  TxRecord,
  AssetSummary,
  WalletSettings,
  WalletStatus,
} from "../api";
import { formatInvokeError } from "../formatInvokeError";
import { DEFAULT_PRIVACY } from "../privacy";
import { loadWalletName, saveWalletName } from "../walletName";

export type AuthScreen = "welcome" | "unlock" | "app";

export function useWalletSession(showToast: (msg: string, kind: "success" | "info" | "error") => void) {
  const [authScreen, setAuthScreen] = useState<AuthScreen>("welcome");
  const [status, setStatus] = useState<WalletStatus | null>(null);
  const [settings, setSettings] = useState<WalletSettings | null>(null);
  const [balance, setBalance] = useState<number | null>(null);
  const [assets, setAssets] = useState<AssetSummary | null>(null);
  const [fastPay, setFastPay] = useState<FastPayStatus | null>(null);
  const [hubHealth, setHubHealth] = useState<HubHealth | null>(null);
  const [history, setHistory] = useState<TxRecord[]>([]);
  const [bills, setBills] = useState<BillSummary[]>([]);
  const [platformSec, setPlatformSec] = useState<PlatformSecurityStatus | null>(null);
  const [busy, setBusy] = useState(false);
  const [refreshing, setRefreshing] = useState(false);
  const [walletName, setWalletName] = useState("");
  const [walletNameDraft, setWalletNameDraft] = useState("");

  const privacy = settings?.privacy ?? status?.privacy ?? DEFAULT_PRIVACY;
  const dustWhisper = settings?.dust_whisper ?? status?.dust_whisper;
  const watchOnly = status?.watch_only ?? false;

  const loadWalletData = useCallback(async () => {
    const [summary, fp, hist, billRows, cfg, hub, plat] = await Promise.all([
      api.assetSummary(),
      api.fastPayStatus(),
      api.txHistory(),
      api.listBillSummaries(),
      api.getSettings(),
      api.hubHealth().catch(() => null),
      api.platformSecurity().catch(() => null),
    ]);
    setAssets(summary);
    setBalance(summary.hac_mei);
    setFastPay(fp);
    setHistory(hist);
    setBills(billRows);
    setSettings(cfg);
    setHubHealth(hub);
    setPlatformSec(plat);
    return cfg;
  }, []);

  const refresh = useCallback(async () => {
    const s = await api.status();
    setStatus(s);
    if (!s.has_wallet) {
      setAuthScreen("welcome");
      return;
    }
    if (s.locked) {
      setAuthScreen("unlock");
      setBalance(null);
      setAssets(null);
      setFastPay(null);
      try {
        const cfg = await api.getSettings();
        setSettings(cfg);
      } catch {
        /* settings readable while locked */
      }
      return;
    }
    setAuthScreen("app");
    await loadWalletData();
  }, [loadWalletData]);

  useEffect(() => {
    void refresh().catch((e) => showToast(formatInvokeError(e), "error"));
  }, [refresh, showToast]);

  useEffect(() => {
    setWalletName(loadWalletName(status?.address));
    setWalletNameDraft(loadWalletName(status?.address));
  }, [status?.address]);

  const handlePullRefresh = useCallback(async () => {
    setRefreshing(true);
    try {
      await refresh();
      showToast("Balance updated.", "success");
    } catch (e) {
      showToast(formatInvokeError(e), "error");
    } finally {
      setRefreshing(false);
    }
  }, [refresh, showToast]);

  const handleLock = useCallback(async () => {
    await api.lock();
    setBalance(null);
    setAssets(null);
    await refresh();
    showToast("Wallet locked.", "info");
  }, [refresh, showToast]);

  const handleEnableFastPay = useCallback(async () => {
    setBusy(true);
    try {
      const fp = await api.enableFastPay(fastPay?.default_deposit_mei);
      setFastPay(fp);
      await refresh();
      showToast("Fast Pay enabled!", "success");
    } catch (e) {
      showToast(formatInvokeError(e), "error");
    } finally {
      setBusy(false);
    }
  }, [fastPay?.default_deposit_mei, refresh, showToast]);

  const handleClearHistory = useCallback(async () => {
    setBusy(true);
    try {
      await api.clearHistory();
      setHistory([]);
      showToast("History cleared.", "success");
    } catch (e) {
      showToast(formatInvokeError(e), "error");
    } finally {
      setBusy(false);
    }
  }, [showToast]);

  const handleSaveWalletName = useCallback(() => {
    if (!status?.address) return;
    saveWalletName(status.address, walletNameDraft);
    setWalletName(walletNameDraft.trim());
    showToast("Wallet name saved.", "success");
  }, [status?.address, walletNameDraft, showToast]);

  const persistPrivacy = useCallback(
    async (patch: Partial<typeof privacy>) => {
      const next = { ...privacy, ...patch };
      await api.updatePrivacy(next);
      if (settings) setSettings({ ...settings, privacy: next });
      showToast("Privacy settings saved.", "success");
    },
    [privacy, settings, showToast],
  );

  return {
    authScreen,
    setAuthScreen,
    status,
    settings,
    setSettings,
    balance,
    assets,
    fastPay,
    hubHealth,
    history,
    bills,
    platformSec,
    busy,
    setBusy,
    refreshing,
    walletName,
    walletNameDraft,
    setWalletNameDraft,
    privacy,
    dustWhisper,
    watchOnly,
    refresh,
    loadWalletData,
    handlePullRefresh,
    handleLock,
    handleEnableFastPay,
    handleClearHistory,
    handleSaveWalletName,
    persistPrivacy,
  };
}
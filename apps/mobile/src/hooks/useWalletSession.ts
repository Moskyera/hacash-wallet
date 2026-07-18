import { useCallback, useEffect, useRef, useState } from "react";
import {
  api,
  BillSummary,
  DustWhisperSettings,
  FastPayStatus,
  HubHealth,
  PlatformSecurityStatus,
  TxRecord,
  AssetSummary,
  WalletSettings,
  WalletStatus,
} from "../api";
import { hasWhisperRelays, resolveDustWhisper } from "../dustWhisper";
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
  const [booting, setBooting] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [walletName, setWalletName] = useState("");
  const [walletNameDraft, setWalletNameDraft] = useState("");
  const statusRequestRef = useRef<Promise<WalletStatus> | null>(null);

  const privacy = settings?.privacy ?? status?.privacy ?? DEFAULT_PRIVACY;
  const dustWhisper = settings?.dust_whisper ?? status?.dust_whisper;
  const watchOnly = status?.watch_only ?? false;

  const fetchStatus = useCallback((): Promise<WalletStatus> => {
    if (statusRequestRef.current) return statusRequestRef.current;
    const request = api.status().finally(() => {
      if (statusRequestRef.current === request) statusRequestRef.current = null;
    });
    statusRequestRef.current = request;
    return request;
  }, []);

  const clearUnlockedState = useCallback(() => {
    setBalance(null);
    setAssets(null);
    setFastPay(null);
    setHubHealth(null);
    setHistory([]);
    setBills([]);
  }, []);

  const loadWalletData = useCallback(async () => {
    const results = await Promise.allSettled([
      api.assetSummary(),
      api.fastPayStatus(),
      api.txHistory(),
      api.listBillSummaries(),
      api.getSettings(),
      api.platformSecurity(),
    ]);

    const pick = <T,>(idx: number): T | null =>
      results[idx].status === "fulfilled" ? (results[idx] as PromiseFulfilledResult<T>).value : null;

    const summary = pick<AssetSummary>(0);
    const fp = pick<FastPayStatus>(1);
    const hist = pick<TxRecord[]>(2);
    const billRows = pick<BillSummary[]>(3);
    const cfg = pick<WalletSettings>(4);
    const plat = pick<PlatformSecurityStatus>(5);

    const nodeErr = results
      .slice(0, 2)
      .find((r) => r.status === "rejected") as PromiseRejectedResult | undefined;

    if (summary) {
      setAssets(summary);
      setBalance(summary.hac_mei);
    } else {
      setAssets(null);
      setBalance(null);
      if (nodeErr) {
        throw nodeErr.reason;
      }
    }

    if (fp) setFastPay(fp);
    if (hist) setHistory(hist);
    if (billRows) setBills(billRows);
    if (cfg) setSettings(cfg);
    setPlatformSec(plat);
    return cfg ?? (await api.getSettings());
  }, []);

  const refresh = useCallback(async () => {
    const s = await fetchStatus();
    setStatus(s);
    if (!s.has_wallet) {
      clearUnlockedState();
      setAuthScreen("welcome");
      return;
    }
    if (s.locked) {
      setAuthScreen("unlock");
      clearUnlockedState();
      try {
        const [cfg, plat] = await Promise.all([
          api.getSettings(),
          api.platformSecurity().catch(() => null),
        ]);
        setSettings(cfg);
        if (plat) setPlatformSec(plat);
      } catch {
        /* settings readable while locked */
      }
      return;
    }
    setAuthScreen("app");
    await loadWalletData();
  }, [clearUnlockedState, fetchStatus, loadWalletData]);

  useEffect(() => {
    void refresh()
      .catch((e) => showToast(formatInvokeError(e), "error"))
      .finally(() => setBooting(false));
  }, [refresh, showToast]);

  useEffect(() => {
    if (authScreen !== "app" || !status || status.locked) return;
    let active = true;
    let inFlight = false;

    const pollStatus = async () => {
      if (!active || inFlight || document.visibilityState === "hidden") return;
      inFlight = true;
      try {
        const next = await fetchStatus();
        if (!active) return;
        setStatus(next);
        if (!next.has_wallet) {
          clearUnlockedState();
          setAuthScreen("welcome");
        } else if (next.locked) {
          clearUnlockedState();
          setAuthScreen("unlock");
        }
      } catch {
        // A transient status failure must not interrupt the unlocked screen.
      } finally {
        inFlight = false;
      }
    };

    const id = window.setInterval(() => void pollStatus(), 5_000);
    return () => {
      active = false;
      window.clearInterval(id);
    };
  }, [authScreen, clearUnlockedState, fetchStatus, status?.locked]);

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
    clearUnlockedState();
    await refresh();
    showToast("Wallet locked.", "info");
  }, [clearUnlockedState, refresh, showToast]);

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

  const handleDisableFastPay = useCallback(async () => {
    setBusy(true);
    try {
      await api.closeChannel();
      const fp = await api.fastPayStatus();
      setFastPay(fp);
      await refresh();
      showToast("Fast Pay disabled.", "info");
    } catch (e) {
      showToast(formatInvokeError(e), "error");
    } finally {
      setBusy(false);
    }
  }, [refresh, showToast]);

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

  const persistDustWhisper = useCallback(
    async (patch: Partial<DustWhisperSettings>) => {
      const current = resolveDustWhisper(settings?.dust_whisper, status?.dust_whisper);
      const next: DustWhisperSettings = { ...current, ...patch };
      if (next.enabled && !hasWhisperRelays(next)) {
        showToast("Add a relay URL in More → DUST Whisper first.", "error");
        return;
      }
      try {
        await api.updateDustWhisper(next);
        if (settings) setSettings({ ...settings, dust_whisper: next });
        if (status) setStatus({ ...status, dust_whisper: next });
        showToast(
          next.enabled ? "DUST Whisper on for on-chain sends." : "DUST Whisper off.",
          "success",
        );
      } catch (e) {
        showToast(formatInvokeError(e), "error");
      }
    },
    [settings, status, showToast],
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
    booting,
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
    handleDisableFastPay,
    handleClearHistory,
    handleSaveWalletName,
    persistPrivacy,
    persistDustWhisper,
  };
}

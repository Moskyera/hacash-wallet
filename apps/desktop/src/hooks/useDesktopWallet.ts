import { MIN_NEW_WALLET_PASSPHRASE_LENGTH, handOffTextFile } from "@hacash/wallet-ui";
import { useCallback, useEffect, useRef, useState } from "react";
import {
  api,
  AssetSummary,
  ChannelInfo,
  ChannelSetupPreview,
  DustWhisperSettings,
  HubDiscoveryEntry,
  HubHealth,
  PrivacySettings,
  RelayEndpoint,
  RelayHealthStatus,
  TxRecord,
  WalletSettings,
  WalletStatus,
} from "../api";
import { appendAssetSnapshot, emptyAssetTrends } from "../assetTrends";
import { formatInvokeError } from "../formatInvokeError";
import { authorizePreparedOperation } from "../preparedAuthorization";
import { DEFAULT_DUST_WHISPER, DEFAULT_PRIVACY, copyWithPrivacyClear } from "../privacy";
import {
  runWebAuthnAuth,
  runWebAuthnRegister,
  webAuthnAvailable,
  webAuthnClientOrigin,
} from "../webauthn";
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
  const [assetTrends, setAssetTrends] = useState(emptyAssetTrends);
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
  // What this wallet is serving, and whether anybody else could reach it.
  // `null` until the wallet answers, and back to `null` if it stops answering,
  // so the screens say nothing rather than quoting a stale address.
  const [relayEndpoint, setRelayEndpoint] = useState<RelayEndpoint | null>(null);
  const statusRequestRef = useRef<Promise<WalletStatus> | null>(null);
  const assetTrendWalletRef = useRef<string | null>(null);

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

  const refreshStatus = useCallback((): Promise<WalletStatus> => {
    if (statusRequestRef.current) return statusRequestRef.current;
    const request = (async () => {
      let s = await api.status();
      if (s.has_wallet && s.watch_only && s.locked) {
        await api.openWatchOnly();
        s = await api.status();
      }
      setStatus(s);
      const trendWallet = s.has_wallet && !s.locked ? (s.address ?? null) : null;
      if (assetTrendWalletRef.current !== trendWallet) {
        assetTrendWalletRef.current = trendWallet;
        setAssetTrends(emptyAssetTrends());
      }
      if (!s.has_wallet) {
        setBalance(null);
        setAssets(null);
        setFastPayDetail(null);
        setChannelInfo(null);
        setHubHealth(undefined);
        setTxHistory([]);
        setBillsCount(0);
        setScreen("welcome");
      } else if (s.locked) {
        setBalance(null);
        setAssets(null);
        setFastPayDetail(null);
        setChannelInfo(null);
        setHubHealth(undefined);
        setTxHistory([]);
        setBillsCount(0);
        setScreen("unlock");
      }
      return s;
    })().finally(() => {
      if (statusRequestRef.current === request) statusRequestRef.current = null;
    });
    statusRequestRef.current = request;
    return request;
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
      setAssetTrends((current) => appendAssetSnapshot(current, summary));
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

  /**
   * `refreshFastPay` belongs here, not only on the Fast Pay tab.
   *
   * The sidebar chip and the nav badge are rendered on every screen and they now
   * read the measured Fast Pay state rather than `status.fast_pay_state`, which
   * can only ever say "checking". Without this the measured state was fetched
   * exactly once, when somebody opened the Fast Pay tab, so the chip stayed
   * "Fast Pay check" for a wallet that was ready until they went and looked.
   * It runs in the same `Promise.all` as the rest, so it costs no extra wall
   * clock, and it fails closed to `null` on its own.
   */
  const refreshUnlockedData = useCallback(async () => {
    await Promise.all([
      refreshBalance(),
      refreshSettings(),
      refreshBills(),
      refreshHistory(),
      refreshFastPay(),
    ]);
  }, [refreshBalance, refreshSettings, refreshBills, refreshHistory, refreshFastPay]);

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

  /** Read-only. Starts no relay and moves no socket. */
  const refreshRelayEndpoint = useCallback(async () => {
    try {
      setRelayEndpoint(await api.relayEndpoint());
    } catch {
      setRelayEndpoint(null);
    }
  }, []);

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

  // Every setting that decides whether a relay is hosted here, and where it
  // listens. The socket only moves on a save, so this follows the settings
  // rather than polling on a timer.
  useEffect(() => {
    refreshRelayEndpoint().catch(() => undefined);
  }, [
    dustWhisper.enabled,
    dustWhisper.auto_start_relay,
    dustWhisper.relay_bind,
    relayUrlsKey,
    refreshRelayEndpoint,
  ]);

  // Load wallet data when unlocking or switching wallets. NOT on every tab click.
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
    let inFlight = false;
    const timer = window.setInterval(() => {
      if (inFlight || document.visibilityState === "hidden") return;
      inFlight = true;
      refreshStatus()
        .catch(() => undefined)
        .finally(() => {
          inFlight = false;
        });
    }, 5000);
    return () => window.clearInterval(timer);
  }, [status?.locked, refreshStatus]);

  useEffect(() => {
    if (screen !== "home" || !status || status.locked) return;
    let inFlight = false;
    const timer = window.setInterval(() => {
      if (inFlight || document.visibilityState === "hidden") return;
      inFlight = true;
      refreshBalance()
        .catch(() => undefined)
        .finally(() => {
          inFlight = false;
        });
    }, 15_000);
    return () => window.clearInterval(timer);
  }, [screen, status?.locked, status?.address, refreshBalance]);

  useEffect(() => {
    if (screen !== "history" || !status || status.locked) return;
    const id = window.setTimeout(() => {
      refreshHistory().catch(() => undefined);
    }, 0);
    return () => window.clearTimeout(id);
  }, [screen, status?.locked, refreshHistory]);

  /**
   * Keep the Fast Pay reading fresh while somebody is looking at it.
   *
   * This used to fire once, on entering the tab, and never again. `fastPayDetail`
   * is the ONLY measured Fast Pay state in the app - `status.fast_pay_state` and
   * `status.fast_pay_message` both come from `fast_pay_status_sync`, which
   * contacts nothing and can only answer "checking" or "no_provider" - so a
   * single fetch meant the ON/OFF pill, the headline, the Hub's own refusal
   * message and the "next step" block all quoted the instant the tab opened.
   * Somebody starting their Hub, or fixing it, or granting consent in another
   * window, watched a screen that had stopped listening. Running the preflight
   * or the hub health check did not refresh it either; only "Use this hub" did.
   *
   * Ten seconds rather than the five the status poll uses: this one asks the Hub
   * over the network and queries the channel, so it is the more expensive call,
   * and it skips while a fetch is in flight and while the window is hidden.
   */
  useEffect(() => {
    if (screen !== "fastpay" || !status || status.locked) return;
    const id = window.setTimeout(() => {
      void Promise.all([refreshFastPay(), refreshChannel(), refreshBills()]);
    }, 0);
    let inFlight = false;
    const poll = window.setInterval(() => {
      if (inFlight || document.visibilityState === "hidden") return;
      inFlight = true;
      refreshFastPay()
        .catch(() => undefined)
        .finally(() => {
          inFlight = false;
        });
    }, 10000);
    return () => {
      window.clearTimeout(id);
      window.clearInterval(poll);
    };
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
        onInfo("Watch-only wallet added. You can monitor balance. signing requires a hardware device.");
      } catch (e) {
        onError(String(e));
      } finally {
        setBusy(false);
      }
    },
    [clearMessages, refreshStatus, onInfo, onError],
  );

  const handleSetHardwareMode = useCallback(
    async (
      mode: "software" | "webauthn_gate" | "airgap_only" | "watch_only",
      currentPassphrase: string,
    ) => {
      setBusy(true);
      clearMessages();
      try {
        if (mode === "airgap_only") {
          // Irreversible, so it needs a platform ceremony bound to this exact
          // activation, not just the passphrase.
          const prepared = await api.prepareColdVaultActivation();
          await authorizePreparedOperation(prepared, nativeBioAvailable);
          await api.executePreparedColdVaultActivation(prepared.id, currentPassphrase);
          await refreshStatus();
          onInfo(
            "Cold Vault activated. Only exact, freshly authorized Type 2 air-gap signing is allowed.",
          );
          return;
        }
        await api.setHardwareMode(mode, currentPassphrase);
        await refreshStatus();
        onInfo(`Signing policy: ${mode}`);
      } catch (e) {
        onError(formatInvokeError(e));
      } finally {
        setBusy(false);
      }
    },
    [clearMessages, nativeBioAvailable, refreshStatus, onInfo, onError],
  );

  const handleImport = useCallback(
    async (importSeed: string, importPassphrase: string, expectedAddress: string) => {
      setBusy(true);
      clearMessages();
      try {
        await api.import(importSeed.trim(), importPassphrase, expectedAddress);
        await refreshStatus();
        onInfo("Wallet imported. Unlock with your new passphrase.");
      } catch (e) {
        onError(formatInvokeError(e));
      } finally {
        setBusy(false);
      }
    },
    [clearMessages, refreshStatus, onInfo, onError],
  );

  const handleImportBackup = useCallback(
    async (
      json: string,
      passphrase: string,
      deleteSource?: string | null,
      allowLegacy = false,
    ) => {
      setBusy(true);
      clearMessages();
      try {
        await api.importBackup(json.trim(), passphrase, deleteSource, allowLegacy);
        await refreshStatus();
        onInfo(
          "Wallet restored from the authenticated backup. If source cleanup was unavailable, remove the original file from Downloads manually.",
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
    clearMessages();
    await api.lock();
    setBalance(null);
    setHubHealth(undefined);
    setWebauthnReady(webAuthnAvailable());
    await refreshStatus();
  }, [clearMessages, refreshStatus]);

  /**
   * Turn Fast Pay on, and RETURN the refusal instead of only broadcasting it.
   *
   * This is the "Enable Fast Pay" button. It deliberately does not call
   * `wallet_enable_fast_pay`: that command configures a provider and then stops
   * at `needs_channel` on purpose, because opening a funded channel is
   * irreversible L1 work and the core only allows it through the exact prepared
   * ceremony below. So the whole path is prepare, review, authorise, execute.
   *
   * The return value is the change. Every refusal on this path already reached
   * `onError`, which shows a toast for four seconds and writes a banner at the
   * top of the page. Somebody standing at the button, which sits well below the
   * fold, saw neither, and reported the button as dead. It still notifies, and
   * it now also hands the exact text back to the caller so the screen can keep
   * it beside the control. `null` means the open was submitted.
   */
  const handleEnableFastPay = useCallback(
    async (userDeposit: string): Promise<string | null> => {
      setBusy(true);
      clearMessages();
      try {
        const hubAddress = settings?.hub_right_address?.trim();
        if (!hubAddress) {
          throw new Error(
            'No provider address is saved, so there is no counterparty to open a channel with. Use "Check this hub" then "Use this hub" above.',
          );
        }
        const deposit = Number(userDeposit);
        if (!Number.isFinite(deposit) || deposit <= 0) {
          throw new Error(
            `The channel deposit must be a positive number of HAC. The field holds "${userDeposit}".`,
          );
        }
        const prepared = await api.prepareChannelOpen(hubAddress, userDeposit, "0");
        await authorizePreparedOperation(prepared, nativeBioAvailable);
        const tx = await api.executePreparedChannelOpen(prepared.id);
        await refreshStatus();
        await Promise.all([
          refreshBalance(),
          refreshChannel(),
          refreshBills(),
          refreshFastPay(),
        ]);
        onInfo("Channel open submitted (" + tx.slice(0, 12) + "…).");
        return null;
      } catch (e) {
        const message = formatInvokeError(e);
        onError(message);
        return message;
      } finally {
        setBusy(false);
      }
    },
    [
      clearMessages,
      nativeBioAvailable,
      onError,
      onInfo,
      refreshBalance,
      refreshBills,
      refreshChannel,
      refreshFastPay,
      refreshStatus,
      settings?.hub_right_address,
    ],
  );
  const handleApplyHub = useCallback(
    async (entry: HubDiscoveryEntry) => {
      /*
       * This opened with a bare `if (!settings || !entry.online) return;`, placed
       * before `setBusy`, so absolutely nothing moved on screen: no toast, no
       * spinner, no error. The declaration button that reaches it is gated only
       * on `busy || declaredIsActive`, not on settings, so the press really was
       * reachable in that state. `handleUseDeclared` in the panel was rewritten
       * so every branch speaks its reason, and this last branch sits one call
       * deeper and was missed.
       *
       * The panel now refuses both of these by name before it gets here, so this
       * is the backstop rather than the only guard. It still says something,
       * because a silent return is what caused the report in the first place.
       */
      if (!settings) {
        onError(
          "The wallet settings are not loaded yet, so there is nothing to save the provider into. Try again in a moment.",
        );
        return;
      }
      if (!entry.online) {
        onError(
          `${entry.name} is not answering, so it was not saved. Check it again first.`,
        );
        return;
      }
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
    async (
      nodeUrl: string,
      hubUrl: string,
      hubAddress: string,
      trustedMainnetFastPayPilot: boolean,
      currentPassphrase: string,
    ) => {
      if (!settings) return;
      // Giving consent to the bounded mainnet pilot chooses the settlement
      // model every later mainnet payment is judged under, so it goes through
      // its own authenticated command; wallet_update_settings refuses it.
      // Withdrawing consent is a tightening and rides along with the rest.
      const grantingConsent =
        trustedMainnetFastPayPilot && !settings.trusted_mainnet_fast_pay_pilot;
      if (grantingConsent && !currentPassphrase) {
        onError("Enter your wallet passphrase to turn on the bounded mainnet pilot.");
        return;
      }
      setBusy(true);
      clearMessages();
      try {
        const next: WalletSettings = {
          ...settings,
          node_url: nodeUrl.trim(),
          l2_hub_url: hubUrl.trim() || null,
          trusted_mainnet_fast_pay_pilot: grantingConsent
            ? settings.trusted_mainnet_fast_pay_pilot
            : trustedMainnetFastPayPilot,
          hub_right_address: hubAddress.trim() || settings.hub_right_address,
        };
        await api.updateSettings(next);
        if (grantingConsent) {
          await api.setMainnetFastPayConsent(true, currentPassphrase);
        }
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
          userDeposit,
          hubDeposit,
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
        const prepared = await api.prepareChannelOpen(
          hubAddress.trim(),
          userDeposit,
          hubDeposit,
        );
        await authorizePreparedOperation(prepared, nativeBioAvailable);
        const hash = await api.executePreparedChannelOpen(prepared.id);
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
    [clearMessages, nativeBioAvailable, refreshStatus, refreshChannel, refreshBills, onInfo, onError],
  );

  const handleCloseChannel = useCallback(
    async (setChannelPreview: (p: ChannelSetupPreview | null) => void) => {
      setBusy(true);
      clearMessages();
      try {
        const prepared = await api.prepareChannelClose();
        await authorizePreparedOperation(prepared, nativeBioAvailable);
        const hash = await api.executePreparedChannelClose(prepared.id);
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
    [clearMessages, nativeBioAvailable, refreshStatus, refreshChannel, onInfo, onError],
  );

  const handleRegisterWebAuthn = useCallback(async (currentPassphrase: string) => {
    if (!webauthnReady) {
      onError("WebAuthn not available in this environment.");
      return;
    }
    setBusy(true);
    clearMessages();
    try {
      const origin = webAuthnClientOrigin();
      // Swapping an existing authenticator must be approved by that authenticator,
      // so a stolen passphrase cannot hand the second factor to someone else.
      const replacing = (await api.status()).webauthn_enabled;
      if (replacing) {
        const approval = await api.webauthnReplacementBegin(origin);
        const assertion = await runWebAuthnAuth(approval);
        await api.webauthnReplacementFinish(assertion);
      }
      const options = await api.webauthnRegisterBegin(origin);
      const cred = await runWebAuthnRegister(options);
      await api.webauthnRegisterFinish(cred, currentPassphrase);
      await refreshStatus();
      onInfo(
        replacing
          ? "Authenticator replaced. The previous key approved the change and no longer works."
          : "YubiKey / Windows Hello registered.",
      );
    } catch (e) {
      onError(formatInvokeError(e));
    } finally {
      setBusy(false);
    }
  }, [webauthnReady, clearMessages, refreshStatus, onInfo, onError]);

  const handleSaveSettings = useCallback(
    async (nodeUrl: string, fallbackUrls: string[], autoFailover: boolean) => {
      if (!settings) return;
      setBusy(true);
      clearMessages();
      try {
        const next: WalletSettings = {
          ...settings,
          node_url: nodeUrl.trim(),
          node_fallback_urls: fallbackUrls,
          auto_node_failover: autoFailover,
        };
        await api.updateSettings(next);
        await refreshSettings();
        await refreshStatus();
        onInfo("Node settings saved.");
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
      if (newPassphrase.length < MIN_NEW_WALLET_PASSPHRASE_LENGTH) {
        onError(
          `New passphrase must be at least ${MIN_NEW_WALLET_PASSPHRASE_LENGTH} characters.`,
        );
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
        /*
         * This used to click a detached anchor, revoke the object URL in the
         * same synchronous task before the WebView had a turn to read it, and
         * then say "Authenticated full-wallet backup exported. Store it offline."
         * unconditionally. `a.click()` returns void, so no failure could reach
         * the catch: the success sentence was printed whether or not a byte was
         * written. For a wallet backup that is the most expensive lie the app
         * can tell.
         *
         * `handOffTextFile` revokes on a later task and reports what it actually
         * did. The JSON is still returned either way, so the caller keeps the
         * bytes even when no file was written.
         */
        const handoff = await handOffTextFile("hacash-full-backup-v1.json", json);
        if (handoff.ok) {
          onInfo(`${handoff.message} Store it offline.`);
        } else {
          onError(
            `${handoff.message} Your backup was NOT saved to a file. The contents are still on screen and can be copied.`,
          );
        }
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
        onInfo("Istanbul transaction safety pattern checks complete.");
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
          onError(
            "Add at least one relay URL to enable DUST Whisper. Somebody has to run a relay, and it can be you: docs/RUNNING-A-RELAY.md.",
          );
          return null;
        }
        await api.updateDustWhisperSettings(next);
        onInfo("DUST Whisper settings saved.");
        return next;
      } catch (e) {
        onError(String(e));
        return null;
      } finally {
        // RE-READ WHETHER THE SAVE THREW OR NOT.
        //
        // `wallet_update_dust_whisper_settings_desktop` persists the settings
        // and THEN binds the socket, so a save that fails on a port already in
        // use has already changed what is stored. These three refreshes used to
        // sit on the success path only, so on that failure the "Your own relay"
        // box kept showing the state from before the save while the stored
        // settings had moved: the screen was wrong precisely when the person
        // needed it to be right. `relayReach` already has the sentence for a
        // wallet that is set to host and is not listening; it was never fetched.
        await refreshStatus().catch(() => undefined);
        await refreshRelayHealth().catch(() => undefined);
        await refreshRelayEndpoint().catch(() => undefined);
        setBusy(false);
      }
    },
    [
      clearMessages,
      refreshStatus,
      refreshRelayHealth,
      refreshRelayEndpoint,
      onInfo,
      onError,
    ],
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
          ? `Address copied. clipboard clears in ${privacy.clipboard_clear_secs}s.`
          : "Address copied.",
      );
    } catch (e) {
      onError(String(e));
    }
  }, [status?.address, privacy.clipboard_clear_secs, clearMessages, onInfo, onError]);

  const handleSetProfile = useCallback(
    async (profile: string, currentPassphrase: string) => {
      setBusy(true);
      clearMessages();
      try {
        await api.setSecurityProfile(profile, currentPassphrase);
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

  const handleSetSecondFactorThreshold = useCallback(
    async (amountMei: number | null, currentPassphrase: string) => {
      setBusy(true);
      clearMessages();
      try {
        await api.setSecondFactorThreshold(amountMei, currentPassphrase);
        // Report what the core enforces, not what was asked for. A value above the
        // security profile's ceiling is stored and then ignored, so echoing the request
        // would state a threshold that is not in force.
        const next = await refreshStatus();
        const enforced = next.require_second_factor_above_mei;
        onInfo(
          enforced <= 1
            ? "Confirmation now required for every payment."
            : `Confirmation now required for sends above ${enforced - 1} HAC.`,
        );
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
    assetTrends,
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
    relayEndpoint,
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
    refreshRelayEndpoint,
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
    handleSaveSettings,
    handleChangePassphrase,
    handleExportBackup,
    handleSavePrivacy,
    handleSaveWhisper,
    handleClearHistory,
    handleCopyAddress,
    handleSetProfile,
    handleSetSecondFactorThreshold,
    handleSetHardwareMode,
    handleValidateHip23,
    setLastTxHash,
  };
}

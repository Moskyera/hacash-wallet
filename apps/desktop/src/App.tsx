import { useCallback, useEffect, useState } from "react";
import { getCurrentWindow } from "@tauri-apps/api/window";
import {
  api,
  ChannelInfo,
  ChannelSetupPreview,
  Hip23PatternCheck,
  HubHealth,
  PrivacySettings,
  SendPreview,
  TxRecord,
  WalletSettings,
  WalletStatus,
} from "./api";
import { runWebAuthnAuth, runWebAuthnRegister, webAuthnAvailable } from "./webauthn";
import AirgapScreen from "./AirgapScreen";
import QuantumToggle from "./components/QuantumToggle";
import SendQuantumTx from "./components/SendQuantumTx";
import AddressBadge from "./components/AddressBadge";
import { QuantumAccountSummary } from "./api";
import "./quantum.css";
import {
  copyWithPrivacyClear,
  DEFAULT_PRIVACY,
  maskAddress,
  maskBalance,
  maskHash,
} from "./privacy";

type Screen =
  | "welcome"
  | "unlock"
  | "home"
  | "send"
  | "receive"
  | "l2"
  | "history"
  | "advanced"
  | "settings"
  | "security"
  | "privacy"
  | "airgap"
  | "quantum";

type WelcomeTab = "create" | "import" | "watch";

const NAV_ITEMS: { id: Screen; label: string }[] = [
  { id: "home", label: "Home" },
  { id: "send", label: "Send" },
  { id: "quantum", label: "Quantum" },
  { id: "receive", label: "Receive" },
  { id: "l2", label: "L2" },
  { id: "history", label: "History" },
  { id: "advanced", label: "Advanced" },
  { id: "settings", label: "Settings" },
  { id: "security", label: "Security" },
  { id: "privacy", label: "Privacy" },
  { id: "airgap", label: "Air-gap QR" },
];

const ISTANBUL_HEIGHT = 765_432;

function formatCountdown(secs: number | null | undefined): string {
  if (secs == null) return "—";
  const m = Math.floor(secs / 60);
  const s = secs % 60;
  return m > 0 ? `${m}m ${s}s` : `${s}s`;
}

function isValidImportSeed(seed: string): boolean {
  const trimmed = seed.trim();
  if (!trimmed) return false;
  if (/^[0-9a-fA-F]{64}$/.test(trimmed)) return true;
  return trimmed.length >= 8;
}

export default function App() {
  const [screen, setScreen] = useState<Screen>("welcome");
  const [status, setStatus] = useState<WalletStatus | null>(null);
  const [settings, setSettings] = useState<WalletSettings | null>(null);
  const [passphrase, setPassphrase] = useState("");
  const [balance, setBalance] = useState<number | null>(null);
  const [error, setError] = useState("");
  const [info, setInfo] = useState("");
  const [busy, setBusy] = useState(false);

  const [welcomeTab, setWelcomeTab] = useState<WelcomeTab>("create");
  const [importSeed, setImportSeed] = useState("");
  const [importPassphrase, setImportPassphrase] = useState("");

  const [sendTo, setSendTo] = useState("");
  const [sendAmount, setSendAmount] = useState("");
  const [preview, setPreview] = useState<SendPreview | null>(null);
  const [lastTx, setLastTx] = useState("");

  const [nodeUrl, setNodeUrl] = useState("");
  const [hubUrl, setHubUrl] = useState("");
  const [hubAddress, setHubAddress] = useState("");
  const [userDeposit, setUserDeposit] = useState("10");
  const [hubDeposit, setHubDeposit] = useState("0");
  const [channelPreview, setChannelPreview] = useState<ChannelSetupPreview | null>(null);
  const [channelInfo, setChannelInfo] = useState<ChannelInfo | null>(null);
  const [hubHealth, setHubHealth] = useState<HubHealth | null | undefined>(undefined);
  const [billsCount, setBillsCount] = useState(0);

  const [txHistory, setTxHistory] = useState<TxRecord[]>([]);

  const [oldPassphrase, setOldPassphrase] = useState("");
  const [newPassphrase, setNewPassphrase] = useState("");
  const [confirmPassphrase, setConfirmPassphrase] = useState("");
  const [backupJson, setBackupJson] = useState("");
  const [exportPassphrase, setExportPassphrase] = useState("");

  const [hipTxType, setHipTxType] = useState("3");
  const [hipChainHeight, setHipChainHeight] = useState(String(ISTANBUL_HEIGHT));
  const [hipGasMax, setHipGasMax] = useState("100");
  const [hipHasAssetTex, setHipHasAssetTex] = useState(false);
  const [hipAstDepth, setHipAstDepth] = useState("0");
  const [hipGuardOnly, setHipGuardOnly] = useState(false);
  const [hipActionCount, setHipActionCount] = useState("1");
  const [includeP2, setIncludeP2] = useState(false);
  const [hipP2Start, setHipP2Start] = useState("0");
  const [hipP2End, setHipP2End] = useState("0");
  const [hipP2GuardBeforeDebit, setHipP2GuardBeforeDebit] = useState(true);
  const [includeP3, setIncludeP3] = useState(false);
  const [hipP3Floor, setHipP3Floor] = useState("1");
  const [hipP3DebitBeforeFloor, setHipP3DebitBeforeFloor] = useState(true);
  const [quantumAccount, setQuantumAccount] = useState<QuantumAccountSummary | null>(null);
  const [hipResults, setHipResults] = useState<Hip23PatternCheck[] | null>(null);

  const [webauthnReady, setWebauthnReady] = useState(false);
  const [nativeBioAvailable, setNativeBioAvailable] = useState(false);
  const [watchAddress, setWatchAddress] = useState("");
  const [privacyShield, setPrivacyShield] = useState(false);
  const [privacyDraft, setPrivacyDraft] = useState<PrivacySettings>(DEFAULT_PRIVACY);

  const privacy = status?.privacy ?? DEFAULT_PRIVACY;
  const hideBalances = privacy.hide_balances;
  const hideAddresses = privacy.hide_addresses;

  const clearMessages = () => {
    setError("");
    setInfo("");
  };

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
  }, []);

  const refreshSettings = useCallback(async () => {
    const s = await api.getSettings();
    setSettings(s);
    setNodeUrl(s.node_url);
    setHubUrl(s.l2_hub_url ?? "");
    setHubAddress(s.hub_right_address ?? "");
  }, []);

  const refreshBalance = useCallback(async () => {
    try {
      const b = await api.balance();
      setBalance(b);
    } catch {
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

  const refreshUnlockedData = useCallback(async () => {
    await Promise.all([
      refreshBalance(),
      refreshSettings(),
      refreshChannel(),
      refreshBills(),
      refreshHistory(),
    ]);
  }, [refreshBalance, refreshSettings, refreshChannel, refreshBills, refreshHistory]);

  useEffect(() => {
    setWebauthnReady(webAuthnAvailable());
    api.platformSecurityStatus().then((p) => setNativeBioAvailable(p.native_biometric_available)).catch(() => {});
    refreshStatus().catch((e) => setError(String(e)));
  }, [refreshStatus]);

  useEffect(() => {
    if (status?.privacy) setPrivacyDraft(status.privacy);
  }, [status?.privacy]);

  useEffect(() => {
    if (!privacy.screen_privacy) {
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
  }, [privacy.screen_privacy]);

  useEffect(() => {
    if (status && !status.locked) {
      refreshUnlockedData().catch(() => undefined);
      if (screen === "welcome" || screen === "unlock") setScreen("home");
    }
  }, [status?.locked, status?.address, refreshUnlockedData, screen]);

  useEffect(() => {
    if (!status || status.locked) return;
    const timer = window.setInterval(() => {
      refreshStatus().catch(() => undefined);
    }, 1000);
    return () => window.clearInterval(timer);
  }, [status?.locked, refreshStatus]);

  useEffect(() => {
    if (screen === "history" && status && !status.locked) {
      refreshHistory().catch(() => undefined);
    }
  }, [screen, status?.locked, refreshHistory]);

  const l2Active = !!(status?.l2_hub_url && status?.channel_id);

  async function handleCreate() {
    setBusy(true);
    clearMessages();
    try {
      await api.create(passphrase);
      setPassphrase("");
      await refreshStatus();
      setInfo("Wallet created. Unlock with your passphrase.");
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }

  async function handleWatchOnlyImport() {
    setBusy(true);
    clearMessages();
    try {
      await api.importWatchOnly(watchAddress.trim());
      setWatchAddress("");
      await refreshStatus();
      setInfo("Watch-only wallet added. You can monitor balance — signing requires a hardware device.");
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }

  async function handleSetHardwareMode(mode: "software" | "webauthn_gate" | "watch_only") {
    setBusy(true);
    clearMessages();
    try {
      await api.setHardwareMode(mode);
      await refreshStatus();
      setInfo(`Hardware signing mode: ${mode}`);
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }

  async function handleImport() {
    setBusy(true);
    clearMessages();
    try {
      await api.import(importSeed.trim(), importPassphrase);
      setImportSeed("");
      setImportPassphrase("");
      setPassphrase("");
      await refreshStatus();
      setInfo("Wallet imported. Unlock with your new passphrase.");
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }

  async function handleUnlock() {
    setBusy(true);
    clearMessages();
    try {
      await api.unlock(passphrase);
      setPassphrase("");
      await refreshStatus();
      await refreshUnlockedData();
      setScreen("home");
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }

  async function handleLock() {
    clearMessages();
    await api.lock();
    setBalance(null);
    setPreview(null);
    setHubHealth(undefined);
    setWebauthnReady(webAuthnAvailable());
    await refreshStatus();
  }

  async function handleSaveL2Settings() {
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
      setInfo("L2 settings saved.");
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }

  async function handleHubHealth() {
    setBusy(true);
    clearMessages();
    try {
      const health = await api.hubHealth();
      setHubHealth(health);
      if (!health) setInfo("No hub URL configured.");
      else if (health.ok) setInfo(`Hub healthy: ${health.name ?? "unknown"} (v${health.version})`);
      else setError("Hub health check failed.");
    } catch (e) {
      setError(String(e));
      setHubHealth(null);
    } finally {
      setBusy(false);
    }
  }

  async function handlePreviewChannel() {
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
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }

  async function handleOpenChannel() {
    setBusy(true);
    clearMessages();
    try {
      const hash = await api.openChannel(
        hubAddress.trim(),
        Number(userDeposit),
        Number(hubDeposit),
      );
      setInfo(`Channel open submitted: ${hash}`);
      setChannelPreview(null);
      await refreshStatus();
      await refreshChannel();
      await refreshBills();
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }

  async function handleCloseChannel() {
    setBusy(true);
    clearMessages();
    try {
      const hash = await api.closeChannel();
      setInfo(`Channel close submitted: ${hash}`);
      setChannelPreview(null);
      await refreshStatus();
      await refreshChannel();
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }

  async function handleRegisterWebAuthn() {
    if (!webauthnReady) {
      setError("WebAuthn not available in this environment.");
      return;
    }
    setBusy(true);
    clearMessages();
    try {
      const options = await api.webauthnRegisterBegin();
      const cred = await runWebAuthnRegister(options);
      await api.webauthnRegisterFinish(cred);
      await refreshStatus();
      setInfo("YubiKey / Windows Hello registered.");
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }

  async function handleWebAuthnSession() {
    if (!webauthnReady || !status?.webauthn_enabled) return;
    setBusy(true);
    clearMessages();
    try {
      const options = await api.webauthnAuthBegin();
      const assertion = await runWebAuthnAuth(options);
      await api.webauthnAuthFinish(assertion);
      await refreshStatus();
      setInfo("WebAuthn verified for this session.");
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }

  async function handlePreviewSend() {
    setBusy(true);
    clearMessages();
    setPreview(null);
    try {
      const p = await api.previewSend(sendTo.trim(), Number(sendAmount));
      setPreview(p);
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }

  async function handleConfirmSend() {
    setBusy(true);
    clearMessages();
    try {
      const amount = Number(sendAmount);
      const needs2fa =
        status?.security_profile === "paranoid" ||
        (status?.security_profile !== "paranoid" && amount >= 100);
      if (needs2fa && status?.webauthn_enabled) {
        const options = await api.webauthnAuthBegin();
        const assertion = await runWebAuthnAuth(options);
        await api.webauthnAuthFinish(assertion);
      } else if (needs2fa) {
        if (nativeBioAvailable) {
          await api.confirmBiometricNative();
        } else if (status?.webauthn_enabled) {
          const options = await api.webauthnAuthBegin();
          const assertion = await runWebAuthnAuth(options);
          await api.webauthnAuthFinish(assertion);
        } else {
          throw new Error("Enable Windows Hello or register WebAuthn for large sends");
        }
      }
      const result = await api.sendHac(sendTo.trim(), amount);
      setLastTx(result.tx_hash);
      setPreview(null);
      setSendTo("");
      setSendAmount("");
      await refreshBalance();
      await refreshHistory();
      setInfo(`Sent via ${result.rail}: ${result.summary}`);
      setScreen("home");
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }

  async function handleSaveSettings() {
    if (!settings) return;
    setBusy(true);
    clearMessages();
    try {
      const next: WalletSettings = { ...settings, node_url: nodeUrl.trim() };
      await api.updateSettings(next);
      await refreshSettings();
      await refreshStatus();
      setInfo("Node URL saved.");
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }

  async function handleChangePassphrase() {
    if (newPassphrase !== confirmPassphrase) {
      setError("New passphrase and confirmation do not match.");
      return;
    }
    if (newPassphrase.length < 8) {
      setError("New passphrase must be at least 8 characters.");
      return;
    }
    setBusy(true);
    clearMessages();
    try {
      await api.changePassphrase(oldPassphrase, newPassphrase);
      setOldPassphrase("");
      setNewPassphrase("");
      setConfirmPassphrase("");
      setInfo("Passphrase changed.");
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }

  async function handleExportBackup() {
    setBusy(true);
    clearMessages();
    try {
      const json = await api.exportBackup(exportPassphrase);
      setBackupJson(json);
      const blob = new Blob([json], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = "hacash-wallet-backup.json";
      a.click();
      URL.revokeObjectURL(url);
      setInfo("Backup exported and shown below.");
      setExportPassphrase("");
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }

  async function handleValidateHip23() {
    setBusy(true);
    clearMessages();
    setHipResults(null);
    try {
      const universal = {
        tx_type: Number(hipTxType),
        chain_height: Number(hipChainHeight),
        gas_max: Number(hipGasMax),
        has_asset_tex: hipHasAssetTex,
        ast_depth: Number(hipAstDepth),
        guard_only: hipGuardOnly,
        action_count: Number(hipActionCount),
      };
      const p2 = includeP2
        ? {
            start: Number(hipP2Start),
            end: Number(hipP2End),
            guard_before_debit: hipP2GuardBeforeDebit,
          }
        : null;
      const p3 = includeP3
        ? {
            floor_hacash_mei: Number(hipP3Floor),
            debit_before_floor: hipP3DebitBeforeFloor,
          }
        : null;
      const results = await api.validateHip23(universal, p2, p3);
      setHipResults(results);
      setInfo("HIP-23 pattern validation complete.");
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }

  async function handleSavePrivacy() {
    setBusy(true);
    clearMessages();
    try {
      await api.updatePrivacySettings(privacyDraft);
      await refreshStatus();
      setInfo("Privacy settings saved.");
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }

  async function handleClearHistory() {
    setBusy(true);
    clearMessages();
    try {
      await api.clearTxHistory();
      setTxHistory([]);
      setInfo("Local transaction history cleared.");
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }

  async function handleCopyAddress() {
    if (!status?.address) return;
    clearMessages();
    try {
      await copyWithPrivacyClear(status.address, privacy.clipboard_clear_secs);
      setInfo(
        privacy.clipboard_clear_secs > 0
          ? `Address copied — clipboard clears in ${privacy.clipboard_clear_secs}s.`
          : "Address copied.",
      );
    } catch (e) {
      setError(String(e));
    }
  }

  async function handleSetProfile(profile: string) {
    setBusy(true);
    clearMessages();
    try {
      await api.setSecurityProfile(profile);
      await refreshStatus();
      setInfo(`Security profile set to ${profile}.`);
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }

  function renderHip23Result(check: Hip23PatternCheck) {
    return (
      <div
        key={check.pattern}
        className={`preview-card ${check.check.ok ? "result-ok" : "result-fail"}`}
      >
        <h4>
          {check.pattern} — {check.check.ok ? "OK" : "Failed"}
        </h4>
        {check.check.errors.length > 0 && (
          <div className="warn-box">
            <strong>Errors</strong>
            <ul>
              {check.check.errors.map((e) => (
                <li key={e}>{e}</li>
              ))}
            </ul>
          </div>
        )}
        {check.check.warnings.length > 0 && (
          <div className="info-box">
            <strong>Warnings</strong>
            <ul>
              {check.check.warnings.map((w) => (
                <li key={w}>{w}</li>
              ))}
            </ul>
          </div>
        )}
      </div>
    );
  }

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
          <div className="brand-mark">H</div>
          <div>
            <div className="brand-title">Hacash Wallet</div>
            <div className="brand-sub">Secure · L1 + L2 Ready</div>
          </div>
        </div>
        {status && !status.locked && (
          <nav>
            {NAV_ITEMS.map((item) => (
              <button
                key={item.id}
                className={screen === item.id ? "active" : ""}
                onClick={() => {
                  clearMessages();
                  setScreen(item.id);
                }}
              >
                {item.label}
              </button>
            ))}
          </nav>
        )}
        <div className="sidebar-foot">
          {status?.node_url && <span className="muted">{status.node_url}</span>}
          {status && !status.locked && (
            <div className="status-chips">
              <span className={`chip ${l2Active ? "chip-accent" : ""}`}>
                L2 {l2Active ? "configured" : "off"}
              </span>
              {status.webauthn_enabled && <span className="chip chip-accent">WebAuthn</span>}
              {status.watch_only && <span className="chip">Watch-only</span>}
              {(privacy.hide_balances || privacy.hide_addresses) && (
                <span className="chip chip-accent">Privacy on</span>
              )}
              {status.hardware_signing_mode === "webauthn_gate" && (
                <span className="chip chip-accent">HW gate</span>
              )}
              {status.seconds_until_lock != null && (
                <span className="chip">Lock {formatCountdown(status.seconds_until_lock)}</span>
              )}
            </div>
          )}
        </div>
      </aside>

      <main className="content">
        {error && <div className="alert">{error}</div>}
        {info && <div className="info-box">{info}</div>}

        {screen === "welcome" && (
          <section className="panel hero">
            <h1>Your modern Hacash wallet</h1>
            <p>
              Encrypted keys on device. Human-readable signing. Fast Pay (L2) when hub is
              available.
            </p>
            <div className="tab-row">
              <button
                type="button"
                className={welcomeTab === "create" ? "tab active" : "tab"}
                onClick={() => setWelcomeTab("create")}
              >
                Create
              </button>
              <button
                type="button"
                className={welcomeTab === "import" ? "tab active" : "tab"}
                onClick={() => setWelcomeTab("import")}
              >
                Import
              </button>
              <button
                type="button"
                className={welcomeTab === "watch" ? "tab active" : "tab"}
                onClick={() => setWelcomeTab("watch")}
              >
                Watch-only
              </button>
            </div>

            {welcomeTab === "create" && (
              <>
                <label>Choose a strong passphrase</label>
                <input
                  type="password"
                  value={passphrase}
                  onChange={(e) => setPassphrase(e.target.value)}
                  placeholder="Passphrase (min 12 chars recommended)"
                />
                <button disabled={busy || passphrase.length < 8} onClick={handleCreate}>
                  Create wallet
                </button>
              </>
            )}

            {welcomeTab === "watch" && (
              <>
                <label>Hacash address to monitor</label>
                <input
                  value={watchAddress}
                  onChange={(e) => setWatchAddress(e.target.value)}
                  placeholder="1YourAddress..."
                />
                <p className="muted">
                  Sparrow-style watch-only — no private key on this device. Cannot send or sign.
                </p>
                <button disabled={busy || watchAddress.trim().length < 10} onClick={handleWatchOnlyImport}>
                  Add watch-only wallet
                </button>
              </>
            )}

            {welcomeTab === "import" && (
              <>
                <label>Seed (64-char hex or passphrase seed)</label>
                <textarea
                  className="textarea"
                  value={importSeed}
                  onChange={(e) => setImportSeed(e.target.value)}
                  placeholder="64-char hex seed or passphrase-derived seed"
                  rows={3}
                />
                <label>New passphrase for this device</label>
                <input
                  type="password"
                  value={importPassphrase}
                  onChange={(e) => setImportPassphrase(e.target.value)}
                  placeholder="Passphrase (min 8 chars)"
                />
                <button
                  disabled={
                    busy || !isValidImportSeed(importSeed) || importPassphrase.length < 8
                  }
                  onClick={handleImport}
                >
                  Import wallet
                </button>
              </>
            )}
          </section>
        )}

        {screen === "unlock" && (
          <section className="panel hero">
            <h1>Welcome back</h1>
            <p className="muted">{maskAddress(status?.address, hideAddresses)}</p>
            <input
              type="password"
              value={passphrase}
              onChange={(e) => setPassphrase(e.target.value)}
              placeholder="Passphrase"
            />
            <button disabled={busy || !passphrase} onClick={handleUnlock}>
              Unlock
            </button>
            {status?.webauthn_enabled && (
              <div className="info-box">
                WebAuthn is enabled. Wallet auto-locks after{" "}
                <strong>{status.auto_lock_secs}s</strong> of inactivity. After unlock, verify your
                security key to refresh the session timer.
              </div>
            )}
          </section>
        )}

        {screen === "home" && (
          <section className="panel">
            <div className="balance-card">
              <span className="label">Available balance</span>
              <div className="balance-value">
                {maskBalance(balance, hideBalances)} <small>HAC</small>
              </div>
              <div className="chips">
                <span className="chip">L1 On-chain</span>
                <span className={`chip ${l2Active ? "chip-accent" : ""}`}>
                  L2 / Hub {l2Active ? "ready" : "not configured"}
                </span>
                {status?.seconds_until_lock != null && (
                  <span className="chip chip-accent">
                    Auto-lock in {formatCountdown(status.seconds_until_lock)}
                  </span>
                )}
              </div>
            </div>
            <div className="actions-row">
              <button className="primary" onClick={() => setScreen("send")}>
                Send
              </button>
              <button onClick={() => setScreen("receive")}>Receive</button>
              {status?.webauthn_enabled && (
                <button disabled={busy} onClick={handleWebAuthnSession}>
                  Verify WebAuthn (session)
                </button>
              )}
              <button onClick={handleLock}>Lock</button>
            </div>
            {lastTx && (
              <div className="success-box">
                Last transaction: <code>{maskHash(lastTx, hideAddresses)}</code>
              </div>
            )}
          </section>
        )}

        {screen === "send" && (
          <section className="panel">
            <h2>Send HAC</h2>
            <label>To address</label>
            <input value={sendTo} onChange={(e) => setSendTo(e.target.value)} placeholder="1ABC..." />
            <label>Amount (mei)</label>
            <input
              value={sendAmount}
              onChange={(e) => setSendAmount(e.target.value)}
              placeholder="10"
              type="number"
              min="0"
              step="0.001"
            />
            <button disabled={busy || !sendTo || !sendAmount} onClick={handlePreviewSend}>
              Preview (HIP-23 checks)
            </button>
            {preview && (
              <div className="preview-card">
                <h3>Confirm payment</h3>
                <p>{preview.plan.summary}</p>
                <ul>
                  <li>
                    <strong>Rail:</strong> {preview.plan.rail}
                  </li>
                  <li>
                    <strong>Fee:</strong> {preview.plan.estimated_fee}
                  </li>
                  <li>
                    <strong>From:</strong> <code>{maskAddress(preview.from, hideAddresses)}</code>
                  </li>
                  <li>
                    <strong>To:</strong> <code>{maskAddress(preview.to, hideAddresses)}</code>
                  </li>
                </ul>
                {preview.hip23.errors.length > 0 && (
                  <div className="alert">
                    <strong>HIP-23 errors</strong>
                    <ul>
                      {preview.hip23.errors.map((e) => (
                        <li key={e}>{e}</li>
                      ))}
                    </ul>
                  </div>
                )}
                {preview.hip23.warnings.length > 0 && (
                  <div className="warn-box">
                    <strong>HIP-23 warnings</strong>
                    <ul>
                      {preview.hip23.warnings.map((w) => (
                        <li key={w}>{w}</li>
                      ))}
                    </ul>
                  </div>
                )}
                {status?.security_profile === "paranoid" && status.webauthn_enabled && (
                  <p className="muted">
                    Paranoid mode: WebAuthn (YubiKey / Windows Hello) required before signing.
                  </p>
                )}
                <button
                  className="primary"
                  disabled={busy || !preview.hip23.ok}
                  onClick={handleConfirmSend}
                >
                  Sign & send
                </button>
              </div>
            )}
          </section>
        )}

        {screen === "receive" && (
          <section className="panel">
            <h2>Receive HAC</h2>
            <p>Share your address. L2 inbound routes via hub when channel is open.</p>
            <div className="address-box">
              <code>{maskAddress(status?.address, hideAddresses)}</code>
            </div>
            {status?.address && !hideAddresses && (
              <button disabled={busy} onClick={handleCopyAddress}>
                Copy address
              </button>
            )}
          </section>
        )}

        {screen === "l2" && (
          <section className="panel">
            <h2>L2 Fast Pay</h2>
            <p className="muted">
              Configure node and hub URLs, verify hub health, and manage your payment channel.
            </p>

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
            <div className="actions-row">
              <button disabled={busy} onClick={handleSaveL2Settings}>
                Save settings
              </button>
              <button disabled={busy || !hubUrl.trim()} onClick={handleHubHealth}>
                Hub health check
              </button>
            </div>

            {hubHealth !== undefined && (
              <div className={hubHealth?.ok ? "success-box" : "alert"}>
                {hubHealth === null && "Hub unreachable or misconfigured."}
                {hubHealth && hubHealth.ok && (
                  <>
                    Hub OK — <strong>{hubHealth.name ?? "hub"}</strong> (protocol v
                    {hubHealth.version})
                  </>
                )}
                {hubHealth && !hubHealth.ok && "Hub returned unhealthy status."}
              </div>
            )}

            <hr className="divider" />

            <h3>Open payment channel (L1)</h3>
            <label>Hub / CSP address (right party)</label>
            <input
              value={hubAddress}
              onChange={(e) => setHubAddress(e.target.value)}
              placeholder="1Hub..."
            />
            <div className="two-col">
              <div>
                <label>Your deposit (mei)</label>
                <input
                  value={userDeposit}
                  onChange={(e) => setUserDeposit(e.target.value)}
                  type="number"
                  min="0"
                />
              </div>
              <div>
                <label>Hub deposit (mei)</label>
                <input
                  value={hubDeposit}
                  onChange={(e) => setHubDeposit(e.target.value)}
                  type="number"
                  min="0"
                />
              </div>
            </div>
            <div className="actions-row">
              <button disabled={busy || !hubAddress} onClick={handlePreviewChannel}>
                Preview channel
              </button>
              <button
                className="primary"
                disabled={busy || !channelPreview}
                onClick={handleOpenChannel}
              >
                Sign & open channel
              </button>
              <button disabled={busy || !status?.channel_id} onClick={handleCloseChannel}>
                Close channel
              </button>
            </div>

            {channelPreview && (
              <div className="preview-card">
                <p>
                  <strong>Channel ID:</strong> <code>{channelPreview.channel_id}</code>
                </p>
                <p>
                  Left: <code>{channelPreview.left_address}</code> — {channelPreview.left_deposit}
                </p>
                <p>
                  Right: <code>{channelPreview.right_address}</code> —{" "}
                  {channelPreview.right_deposit}
                </p>
              </div>
            )}

            {status?.channel_id && (
              <div className="success-box">
                Active channel: <code>{status.channel_id}</code>
                {channelInfo && (
                  <p className="muted">
                    Status {channelInfo.status} · Left {channelInfo.left.hacash} · Right{" "}
                    {channelInfo.right.hacash}
                  </p>
                )}
              </div>
            )}

            <p className="muted">
              {billsCount > 0
                ? `${billsCount} L2 settlement bill(s) backed up locally.`
                : "No L2 bills stored locally."}
            </p>
          </section>
        )}

        {screen === "history" && (
          <section className="panel panel-wide">
            <h2>Transaction history</h2>
            {txHistory.length === 0 ? (
              <p className="muted">No transactions recorded yet.</p>
            ) : (
              <div className="table-wrap">
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>Time</th>
                      <th>Rail</th>
                      <th>From</th>
                      <th>To</th>
                      <th>Amount</th>
                      <th>Tx hash</th>
                    </tr>
                  </thead>
                  <tbody>
                    {txHistory.map((tx) => (
                      <tr key={`${tx.tx_hash}-${tx.timestamp}`}>
                        <td>{tx.timestamp}</td>
                        <td>{tx.rail}</td>
                        <td>
                          <code>{maskAddress(tx.from, hideAddresses)}</code>
                        </td>
                        <td>
                          <code>{maskAddress(tx.to, hideAddresses)}</code>
                        </td>
                        <td>
                          {hideBalances ? "•••• HAC" : `${tx.amount_mei.toFixed(3)} HAC`}
                        </td>
                        <td>
                          <code>{maskHash(tx.tx_hash, hideAddresses)}</code>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </section>
        )}

        {screen === "advanced" && (
          <section className="panel">
            <h2>HIP-23 Type3 pattern validator</h2>
            <p className="muted">
              Validate universal, P2 (HeightScope), and P3 (BalanceFloor) checklist patterns
              before signing complex Type-3 transactions.
            </p>

            <div className="form-section">
              <h3>Universal</h3>
              <div className="two-col">
                <div>
                  <label>tx_type</label>
                  <input
                    type="number"
                    min="0"
                    value={hipTxType}
                    onChange={(e) => setHipTxType(e.target.value)}
                  />
                </div>
                <div>
                  <label>chain_height</label>
                  <input
                    type="number"
                    min="0"
                    value={hipChainHeight}
                    onChange={(e) => setHipChainHeight(e.target.value)}
                  />
                </div>
              </div>
              <div className="two-col">
                <div>
                  <label>gas_max</label>
                  <input
                    type="number"
                    min="0"
                    value={hipGasMax}
                    onChange={(e) => setHipGasMax(e.target.value)}
                  />
                </div>
                <div>
                  <label>ast_depth</label>
                  <input
                    type="number"
                    min="0"
                    value={hipAstDepth}
                    onChange={(e) => setHipAstDepth(e.target.value)}
                  />
                </div>
              </div>
              <div>
                <label>action_count</label>
                <input
                  type="number"
                  min="0"
                  value={hipActionCount}
                  onChange={(e) => setHipActionCount(e.target.value)}
                />
              </div>
              <label className="check-row">
                <input
                  type="checkbox"
                  checked={hipHasAssetTex}
                  onChange={(e) => setHipHasAssetTex(e.target.checked)}
                />
                has_asset_tex
              </label>
              <label className="check-row">
                <input
                  type="checkbox"
                  checked={hipGuardOnly}
                  onChange={(e) => setHipGuardOnly(e.target.checked)}
                />
                guard_only
              </label>
            </div>

            <div className="form-section">
              <label className="check-row">
                <input
                  type="checkbox"
                  checked={includeP2}
                  onChange={(e) => setIncludeP2(e.target.checked)}
                />
                Include P2 (HeightScope)
              </label>
              {includeP2 && (
                <>
                  <div className="two-col">
                    <div>
                      <label>start</label>
                      <input
                        type="number"
                        min="0"
                        value={hipP2Start}
                        onChange={(e) => setHipP2Start(e.target.value)}
                      />
                    </div>
                    <div>
                      <label>end (0 = open-ended)</label>
                      <input
                        type="number"
                        min="0"
                        value={hipP2End}
                        onChange={(e) => setHipP2End(e.target.value)}
                      />
                    </div>
                  </div>
                  <label className="check-row">
                    <input
                      type="checkbox"
                      checked={hipP2GuardBeforeDebit}
                      onChange={(e) => setHipP2GuardBeforeDebit(e.target.checked)}
                    />
                    guard_before_debit
                  </label>
                </>
              )}
            </div>

            <div className="form-section">
              <label className="check-row">
                <input
                  type="checkbox"
                  checked={includeP3}
                  onChange={(e) => setIncludeP3(e.target.checked)}
                />
                Include P3 (BalanceFloor)
              </label>
              {includeP3 && (
                <>
                  <label>floor_hacash_mei</label>
                  <input
                    type="number"
                    min="0"
                    step="0.001"
                    value={hipP3Floor}
                    onChange={(e) => setHipP3Floor(e.target.value)}
                  />
                  <label className="check-row">
                    <input
                      type="checkbox"
                      checked={hipP3DebitBeforeFloor}
                      onChange={(e) => setHipP3DebitBeforeFloor(e.target.checked)}
                    />
                    debit_before_floor
                  </label>
                </>
              )}
            </div>

            <button disabled={busy} onClick={handleValidateHip23}>
              Run validation
            </button>
            {hipResults?.map(renderHip23Result)}
          </section>
        )}

        {screen === "quantum" && (
          <section className="stack">
            <QuantumToggle onAccountChange={setQuantumAccount} />
            <SendQuantumTx
              account={quantumAccount}
              nodeUrl={settings?.node_url ?? status?.node_url}
              disabled={busy || !!status?.locked}
            />
          </section>
        )}

        {screen === "settings" && (
          <section className="panel">
            <h2>Settings</h2>

            <h3>Node</h3>
            <label>Node API URL</label>
            <input
              value={nodeUrl}
              onChange={(e) => setNodeUrl(e.target.value)}
              placeholder="https://node.example.com"
            />
            <button disabled={busy} onClick={handleSaveSettings}>
              Save node URL
            </button>

            <hr className="divider" />

            <h3>Change passphrase</h3>
            <label>Current passphrase</label>
            <input
              type="password"
              value={oldPassphrase}
              onChange={(e) => setOldPassphrase(e.target.value)}
            />
            <label>New passphrase</label>
            <input
              type="password"
              value={newPassphrase}
              onChange={(e) => setNewPassphrase(e.target.value)}
            />
            <label>Confirm new passphrase</label>
            <input
              type="password"
              value={confirmPassphrase}
              onChange={(e) => setConfirmPassphrase(e.target.value)}
            />
            <button
              disabled={
                busy || !oldPassphrase || !newPassphrase || newPassphrase !== confirmPassphrase
              }
              onClick={handleChangePassphrase}
            >
              Change passphrase
            </button>

            <hr className="divider" />

            <h3>Export backup</h3>
            <p className="muted">
              Export an encrypted JSON backup. You will need your passphrase to restore it.
            </p>
            <label>Passphrase to decrypt vault for export</label>
            <input
              type="password"
              value={exportPassphrase}
              onChange={(e) => setExportPassphrase(e.target.value)}
            />
            <button disabled={busy || !exportPassphrase} onClick={handleExportBackup}>
              Export backup
            </button>
            {backupJson && (
              <textarea
                className="textarea mono"
                readOnly
                value={backupJson}
                rows={8}
                aria-label="Exported backup JSON"
              />
            )}
          </section>
        )}

        {screen === "airgap" && status && !status.locked && (
          <AirgapScreen
            status={status}
            busy={busy}
            setBusy={setBusy}
            clearMessages={clearMessages}
            setError={setError}
            setInfo={setInfo}
            onBroadcast={async () => {
              await refreshBalance();
              await refreshHistory();
            }}
          />
        )}

        {screen === "privacy" && (
          <section className="panel">
            <h2>Privacy</h2>
            <p className="muted">
              Control what appears on screen and what is stored locally. Keys stay encrypted —
              these settings reduce shoulder-surfing and local metadata exposure.
            </p>

            <label className="check-row">
              <input
                type="checkbox"
                checked={privacyDraft.hide_balances}
                onChange={(e) =>
                  setPrivacyDraft((p) => ({ ...p, hide_balances: e.target.checked }))
                }
              />
              Hide balances
            </label>
            <label className="check-row">
              <input
                type="checkbox"
                checked={privacyDraft.hide_addresses}
                onChange={(e) =>
                  setPrivacyDraft((p) => ({ ...p, hide_addresses: e.target.checked }))
                }
              />
              Hide addresses &amp; tx hashes
            </label>
            <label className="check-row">
              <input
                type="checkbox"
                checked={privacyDraft.screen_privacy}
                onChange={(e) =>
                  setPrivacyDraft((p) => ({ ...p, screen_privacy: e.target.checked }))
                }
              />
              Screen privacy (blur when unfocused)
            </label>
            <label className="check-row">
              <input
                type="checkbox"
                checked={privacyDraft.store_tx_history}
                onChange={(e) =>
                  setPrivacyDraft((p) => ({ ...p, store_tx_history: e.target.checked }))
                }
              />
              Store transaction history locally
            </label>

            <label>Clipboard auto-clear (seconds, 0 = off)</label>
            <input
              type="number"
              min="0"
              max="300"
              value={privacyDraft.clipboard_clear_secs}
              onChange={(e) =>
                setPrivacyDraft((p) => ({
                  ...p,
                  clipboard_clear_secs: Math.max(0, Number(e.target.value)),
                }))
              }
            />

            <div className="actions-row">
              <button className="primary" disabled={busy} onClick={handleSavePrivacy}>
                Save privacy settings
              </button>
              <button disabled={busy} onClick={handleClearHistory}>
                Clear local history
              </button>
            </div>

            <div className="info-box">
              <strong>No cloud telemetry</strong> — node queries use your configured URL only.
              Air-gap and watch-only modes keep signing keys off the online device.
            </div>
          </section>
        )}

        {screen === "security" && (
          <section className="panel">
            <h2>Security</h2>
            <div className="security-grid">
              <div className="security-item done">
                <h4>Encrypted vault</h4>
                <p>Argon2id + AES-256-GCM. Keys never leave device unencrypted.</p>
              </div>
              <div className="security-item done">
                <h4>Local signing</h4>
                <p>Transactions signed in Rust core — private key never sent to node API.</p>
              </div>
              <div className="security-item done">
                <h4>HIP-23 pre-sign checks</h4>
                <p>Address format, balance, and large-transfer warnings before every send.</p>
              </div>
              <div
                className={`security-item ${status?.webauthn_enabled ? "done" : "soon"}`}
              >
                <h4>YubiKey / Windows Hello</h4>
                <p>
                  WebAuthn second factor for paranoid profile sends.
                  {status?.webauthn_enabled ? " Registered." : " Not registered yet."}
                </p>
              </div>
            </div>

            <div className="actions-row">
              <button disabled={busy || !webauthnReady} onClick={handleRegisterWebAuthn}>
                Register WebAuthn
              </button>
              <button
                disabled={busy || !status?.webauthn_enabled}
                onClick={handleWebAuthnSession}
              >
                Verify WebAuthn (session)
              </button>
            </div>

            <div className="actions-row">
              <button
                className={status?.security_profile === "balanced" ? "primary" : ""}
                disabled={busy}
                onClick={() => handleSetProfile("balanced")}
              >
                Balanced profile
              </button>
              <button
                className={status?.security_profile === "paranoid" ? "primary" : ""}
                disabled={busy}
                onClick={() => handleSetProfile("paranoid")}
              >
                Paranoid profile
              </button>
            </div>

            <h3>Hardware signing mode</h3>
            <p className="muted">
              {nativeBioAvailable
                ? "Windows Hello available for native biometric 2FA."
                : "Register WebAuthn (YubiKey / Hello) for hardware-gated signing."}
            </p>
            <div className="actions-row">
              <button
                className={status?.hardware_signing_mode === "software" ? "primary" : ""}
                disabled={busy || status?.watch_only}
                onClick={() => handleSetHardwareMode("software")}
              >
                Software key
              </button>
              <button
                className={status?.hardware_signing_mode === "webauthn_gate" ? "primary" : ""}
                disabled={busy || status?.watch_only}
                onClick={() => handleSetHardwareMode("webauthn_gate")}
              >
                WebAuthn gate (all signs)
              </button>
            </div>
            <p className="muted">
              Profile: <strong>{status?.security_profile ?? "balanced"}</strong>. Balanced auto-locks
              after {status?.auto_lock_secs ?? 180}s. Paranoid uses shorter timeouts and requires
              WebAuthn before high-value sends.
            </p>
          </section>
        )}
      </main>
    </div>
  );
}
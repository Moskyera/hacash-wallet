import { useEffect, useRef, useState } from "react";
import {
  api,
  BillSummary,
  DustWhisperSettings,
  HubHealth,
  PlatformSecurityStatus,
  PrivacySettings,
  TxRecord,
  WalletSettings,
  WalletStatus,
} from "../../api";
import AirgapScreen from "../../components/AirgapScreen";
import FastPayChannelScreen from "../FastPayChannelScreen";
import HacdLaunchpadIcon from "../../components/HacdLaunchpadIcon";
import LaunchpadScreen from "../../components/LaunchpadScreen";
import MessengerScreen from "../../components/MessengerScreen";
import QuantumScreen from "../../components/QuantumScreen";
import WhisperScreen from "../../components/WhisperScreen";
import { addContact, removeContact, type SavedContact } from "../../contacts";
import { copyWithPrivacyClear, maskAddress } from "../../privacy";
import { MIN_WALLET_PASS } from "../../quantumMeta";
import { BIOMETRIC_THRESHOLD_MEI } from "../../utils/appConstants";
import { formatInvokeError } from "../../formatInvokeError";
import HubDiscoveryPanel from "../../components/HubDiscoveryPanel";
import { fastPayMenuBadge } from "../../fastPayUi";
import { downloadJson } from "../../utils/downloadJson";
import {
  runWebAuthnAuth,
  runWebAuthnRegister,
  webAuthnAvailable,
  webAuthnClientOrigin,
} from "../../webauthn";

export type MorePage =
  | "menu"
  | "history"
  | "bills"
  | "fastpay"
  | "settings"
  | "security"
  | "privacy"
  | "contacts"
  | "quantum"
  | "airgap"
  | "launchpad"
  | "whisper"
  | "messages";

type Props = {
  page: MorePage;
  onBack: () => void;
  onNavigate: (page: MorePage) => void;
  history: TxRecord[];
  bills: BillSummary[];
  contacts: SavedContact[];
  setContacts: (c: SavedContact[]) => void;
  dustWhisper?: DustWhisperSettings;
  privacy: PrivacySettings;
  settings: WalletSettings | null;
  hubHealth: HubHealth | null;
  platformSec: PlatformSecurityStatus | null;
  status: WalletStatus | null;
  fastPay: import("../../api").FastPayStatus | null;
  watchOnly: boolean;
  statusAddress?: string | null;
  clipboardSecs: number;
  busy: boolean;
  settingsNodeUrl: string;
  setSettingsNodeUrl: (v: string) => void;
  settingsHubUrl: string;
  setSettingsHubUrl: (v: string) => void;
  walletNameDraft: string;
  setWalletNameDraft: (v: string) => void;
  backupPass: string;
  setBackupPass: (v: string) => void;
  oldPass: string;
  setOldPass: (v: string) => void;
  newPass: string;
  setNewPass: (v: string) => void;
  contactLabel: string;
  setContactLabel: (v: string) => void;
  contactAddress: string;
  setContactAddress: (v: string) => void;
  onClearHistory: () => void;
  onSaveSettings: () => void;
  onApplyHub: (entry: import("../../api").HubDiscoveryEntry) => Promise<void>;
  onSaveWalletName: () => void;
  onExportBackup: () => void;
  onChangePassphrase: () => void;
  onResetWallet: () => void;
  onLock: () => void;
  onPersistPrivacy: (patch: Partial<PrivacySettings>) => void;
  onSelectContact: (c: SavedContact) => void;
  onGoPayPeer: (peer: string) => void;
  onGoLegacySend: () => void;
  onToast: (msg: string, kind: "success" | "info" | "error") => void;
  onSelectBill: (bill: BillSummary) => void;
  onRefresh: () => Promise<void>;
  setBusy: (b: boolean) => void;
};

export default function MoreRouter(props: Props) {
  const [bioUnlockPass, setBioUnlockPass] = useState("");
  const [bioUnlockStatus, setBioUnlockStatus] = useState<{ enabled: boolean; configured: boolean } | null>(
    null,
  );
  const [privateKeyPass, setPrivateKeyPass] = useState("");
  const [privateKey, setPrivateKey] = useState<string | null>(null);
  const privateKeyTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  const {
    page,
    onBack,
    onNavigate,
    history,
    bills,
    contacts,
    setContacts,
    dustWhisper,
    privacy,
    settings,
    hubHealth,
    platformSec,
    status,
    fastPay,
    watchOnly,
    statusAddress,
    clipboardSecs,
    busy,
    settingsNodeUrl,
    setSettingsNodeUrl,
    settingsHubUrl,
    setSettingsHubUrl,
    walletNameDraft,
    setWalletNameDraft,
    backupPass,
    setBackupPass,
    oldPass,
    setOldPass,
    newPass,
    setNewPass,
    contactLabel,
    setContactLabel,
    contactAddress,
    setContactAddress,
    onClearHistory,
    onSaveSettings,
    onApplyHub,
    onSaveWalletName,
    onExportBackup,
    onChangePassphrase,
    onResetWallet,
    onLock,
    onPersistPrivacy,
    onSelectContact,
    onGoPayPeer,
    onGoLegacySend,
    onToast,
    onSelectBill,
    onRefresh,
    setBusy,
  } = props;

  useEffect(() => {
    if (page !== "security") return;
    void api
      .biometricUnlockStatus()
      .then(setBioUnlockStatus)
      .catch(() => setBioUnlockStatus(null));
  }, [page, settings?.biometric_unlock_enabled]);

  useEffect(() => {
    return () => {
      if (privateKeyTimer.current) clearTimeout(privateKeyTimer.current);
    };
  }, []);

  const [webauthnReady, setWebauthnReady] = useState(false);
  const [nodeTestMsg, setNodeTestMsg] = useState<string | null>(null);

  useEffect(() => {
    void webAuthnAvailable().then(setWebauthnReady);
  }, []);

  async function handleRegisterWebAuthn() {
    if (!webauthnReady) {
      onToast("WebAuthn is not available in this WebView.", "error");
      return;
    }
    setBusy(true);
    try {
      const options = await api.webauthnRegisterBegin(webAuthnClientOrigin());
      const cred = await runWebAuthnRegister(options);
      await api.webauthnRegisterFinish(cred);
      await onRefresh();
      onToast("WebAuthn passkey registered.", "success");
    } catch (e) {
      onToast(formatInvokeError(e), "error");
    } finally {
      setBusy(false);
    }
  }

  async function handleTestWebAuthn() {
    if (!webauthnReady || !settings?.webauthn_enabled) return;
    setBusy(true);
    try {
      const options = await api.webauthnAuthBegin(webAuthnClientOrigin());
      const assertion = await runWebAuthnAuth(options);
      await api.webauthnAuthFinish(assertion);
      onToast("WebAuthn verification OK.", "success");
    } catch (e) {
      onToast(formatInvokeError(e), "error");
    } finally {
      setBusy(false);
    }
  }

  if (page === "menu") {
    return (
      <div className="more-menu">
        <p className="section-title">Wallet</p>
        <button type="button" onClick={() => onNavigate("history")}>
          <span>Transaction history</span>
          <span>{history.length}</span>
        </button>
        <button type="button" onClick={() => onNavigate("bills")}>
          <span>Dispute bills</span>
          <span>{bills.length}</span>
        </button>
        <button type="button" onClick={() => onNavigate("fastpay")}>
          <span>Fast Pay</span>
          <span>{fastPayMenuBadge(fastPay?.state)}</span>
        </button>
        <button type="button" onClick={() => onNavigate("contacts")}>
          <span>Contacts</span>
          <span>{contacts.length}</span>
        </button>
        <button type="button" onClick={() => onNavigate("quantum")}>
          <span>Quantum (Type 4)</span>
          <span>◇</span>
        </button>
        <button type="button" onClick={() => onNavigate("airgap")}>
          <span>Air-gap (L1 QR)</span>
          <span>◎</span>
        </button>
        <button type="button" onClick={() => onNavigate("launchpad")}>
          <span>HACD Launchpad</span>
          <span className="menu-icon" aria-hidden>
            <HacdLaunchpadIcon />
          </span>
        </button>
        <button type="button" onClick={() => onNavigate("whisper")}>
          <span>DUST Whisper</span>
          <span>{dustWhisper?.enabled ? "on" : "off"}</span>
        </button>
        <p className="section-title">Preferences</p>
        <button type="button" onClick={() => onNavigate("settings")}>
          <span>Network settings</span>
          <span>→</span>
        </button>
        <button type="button" onClick={() => onNavigate("privacy")}>
          <span>Privacy</span>
          <span>→</span>
        </button>
        <button type="button" onClick={() => onNavigate("security")}>
          <span>Security & backup</span>
          <span>→</span>
        </button>
      </div>
    );
  }

  return (
    <>
      <button type="button" className="ghost small" onClick={onBack}>
        ← Back
      </button>
      {page === "history" && (
        <div className="card">
          <h2>Transactions</h2>
          {history.length === 0 ? (
            <p className="muted">No transactions yet.</p>
          ) : (
            history.map((row) => (
              <div key={row.tx_hash} className="list-item">
                <div>
                  <span className="badge badge-rail">{row.rail}</span> {row.amount_mei} HAC
                </div>
                <div className="muted">{row.summary}</div>
                <div className="muted">{row.timestamp}</div>
              </div>
            ))
          )}
          {history.length > 0 && (
            <button type="button" disabled={busy} onClick={() => void onClearHistory()}>
              Clear history
            </button>
          )}
        </div>
      )}
      {page === "bills" && (
        <div className="card">
          <h2>Dispute bills</h2>
          <p className="muted">Signed Fast Pay receipts for channel disputes.</p>
          <button
            className="primary"
            disabled={bills.length === 0}
            onClick={async () => {
              try {
                const json = await api.exportAllBillsJson();
                downloadJson(`hacash-bills-${Date.now()}.json`, json);
                onToast("All bills exported.", "success");
              } catch (e) {
                onToast(String(e), "error");
              }
            }}
          >
            Export all JSON
          </button>
          {bills.length === 0 ? (
            <p className="muted">No bills stored.</p>
          ) : (
            bills.map((bill) => (
              <div key={bill.payment_id} className="list-item" onClick={() => onSelectBill(bill)}>
                <div>
                  <code>{bill.payment_id.slice(0, 10)}…</code>{" "}
                  <span className={bill.dispute_ready ? "badge badge-ok" : "badge badge-warn"}>
                    {bill.dispute_ready ? "Ready" : "Incomplete"}
                  </span>
                </div>
                <div className="muted">{bill.timestamp_utc}</div>
              </div>
            ))
          )}
        </div>
      )}
      {page === "settings" && (
        <div className="card">
          <h2>Network</h2>
          {status?.node_url && (
            <p className="muted">
              Active node: <code>{status.node_url}</code>
            </p>
          )}
          <label className="label">Node URL</label>
          <input
            value={settingsNodeUrl}
            onChange={(e) => setSettingsNodeUrl(e.target.value)}
            placeholder="http://nodeapi.hacash.org"
            autoCapitalize="none"
            autoCorrect="off"
            spellCheck={false}
          />
          <p className="muted">Official Hacash node uses HTTP (not HTTPS). Tap Save after editing.</p>
          <label className="label">L2 Hub URL</label>
          <input
            value={settingsHubUrl}
            onChange={(e) => setSettingsHubUrl(e.target.value)}
            placeholder="https://hub.example (optional)"
          />
          {hubHealth && (
            <p className="muted">
              Hub: {hubHealth.ok ? "online" : "offline"}
              {hubHealth.hub_fee_mei != null && ` · fee ${hubHealth.hub_fee_mei} HAC`}
            </p>
          )}
          <HubDiscoveryPanel
            settings={settings}
            activeHubUrl={settingsHubUrl}
            busy={busy}
            setBusy={setBusy}
            onApplyHub={onApplyHub}
            onToast={onToast}
          />
          <div className="row-btns">
            <button className="primary" disabled={busy} onClick={() => void onSaveSettings()}>
              Save settings
            </button>
            <button
              type="button"
              disabled={busy}
              onClick={() => {
                setNodeTestMsg(null);
                setBusy(true);
                void api
                  .pingNode()
                  .then((r) => {
                    setNodeTestMsg(`Node OK (${String(r.reachable ?? "true")})`);
                    onToast("Node connection OK.", "success");
                  })
                  .catch((e) => {
                    const msg = formatInvokeError(e);
                    setNodeTestMsg(msg);
                    onToast(msg, "error");
                  })
                  .finally(() => setBusy(false));
              }}
            >
              Test node
            </button>
          </div>
          {nodeTestMsg && <p className="muted small">{nodeTestMsg}</p>}
          <p className="muted small">
            GrapheneOS: Settings → Apps → Hacash Wallet → Permissions → Network → Allow
          </p>
        </div>
      )}
      {page === "security" && (
        <>
          <div className="card">
            <h2>Wallet name</h2>
            <p className="muted">Shown on the unlock screen instead of your address.</p>
            <label className="label">Display name</label>
            <input
              value={walletNameDraft}
              onChange={(e) => setWalletNameDraft(e.target.value)}
              placeholder="My Wallet"
            />
            <button type="button" className="primary" onClick={onSaveWalletName}>
              Save name
            </button>
          </div>
          <div className="card">
            <h2>Backup</h2>
            <p className="muted">Export encrypted wallet backup (requires passphrase).</p>
            <label className="label">Passphrase</label>
            <input type="password" value={backupPass} onChange={(e) => setBackupPass(e.target.value)} />
            <button className="primary" disabled={busy || !backupPass} onClick={() => void onExportBackup()}>
              Download backup
            </button>
          </div>
          <div className="card">
            <h2>Private key</h2>
            <p className="muted small">
              Advanced: view your wallet private key. Anyone with this key controls your funds. Never share it.
            </p>
            <label className="label">Passphrase</label>
            <input
              type="password"
              value={privateKeyPass}
              onChange={(e) => setPrivateKeyPass(e.target.value)}
            />
            <button
              type="button"
              className="primary"
              disabled={busy || watchOnly || !privateKeyPass}
              onClick={() => {
                setBusy(true);
                void api
                  .exportPrivateKey(privateKeyPass)
                  .then((hex) => {
                    setPrivateKey(hex);
                    setPrivateKeyPass("");
                    onToast("Private key revealed. It will hide in 60s.", "info");
                    if (privateKeyTimer.current) clearTimeout(privateKeyTimer.current);
                    privateKeyTimer.current = setTimeout(() => setPrivateKey(null), 60_000);
                  })
                  .catch((err) => onToast(formatInvokeError(err), "error"))
                  .finally(() => setBusy(false));
              }}
            >
              Reveal private key
            </button>
            {privateKey ? (
              <>
                <p className="mono small" style={{ wordBreak: "break-all", marginTop: "0.75rem" }}>
                  {privateKey}
                </p>
                <button
                  type="button"
                  style={{ marginTop: "0.5rem" }}
                  onClick={() =>
                    void copyWithPrivacyClear(privateKey, clipboardSecs).then(() =>
                      onToast("Private key copied.", "success"),
                    )
                  }
                >
                  Copy
                </button>
                <button
                  type="button"
                  style={{ marginTop: "0.5rem", marginLeft: "0.5rem" }}
                  onClick={() => {
                    setPrivateKey(null);
                    if (privateKeyTimer.current) clearTimeout(privateKeyTimer.current);
                  }}
                >
                  Hide
                </button>
              </>
            ) : null}
          </div>
          <div className="card">
            <h2>Delete wallet</h2>
            <p className="muted">
              Removes this wallet from the phone so you can create or import a different one. Export a
              backup first if you need to recover funds later.
            </p>
            <button type="button" disabled={busy} onClick={onResetWallet}>
              Delete wallet from device
            </button>
          </div>
          <div className="card">
            <h2>Change passphrase</h2>
            <label className="label">Current</label>
            <input type="password" value={oldPass} onChange={(e) => setOldPass(e.target.value)} />
            <label className="label">New</label>
            <input type="password" value={newPass} onChange={(e) => setNewPass(e.target.value)} />
            <button
              className="primary"
              disabled={busy || !oldPass || !newPass || newPass.length < MIN_WALLET_PASS}
              onClick={() => void onChangePassphrase()}
            >
              Update passphrase
            </button>
            {newPass.length > 0 && newPass.length < MIN_WALLET_PASS && (
              <p className="warn-text">New passphrase must be at least {MIN_WALLET_PASS} characters.</p>
            )}
          </div>
          <div className="card">
            <h2>Security profile</h2>
            <p className="muted">Balanced is default. Paranoid requires WebAuthn or biometrics for large sends.</p>
            <div className="display-toggle">
              <button
                type="button"
                className={status?.security_profile !== "paranoid" ? "selected" : ""}
                disabled={busy || watchOnly}
                onClick={() =>
                  void api
                    .setSecurityProfile("balanced")
                    .then(() => onRefresh())
                    .then(() => onToast("Profile: balanced", "success"))
                }
              >
                Balanced
              </button>
              <button
                type="button"
                className={status?.security_profile === "paranoid" ? "selected" : ""}
                disabled={busy || watchOnly}
                onClick={() =>
                  void api
                    .setSecurityProfile("paranoid")
                    .then(() => onRefresh())
                    .then(() => onToast("Profile: paranoid", "success"))
                }
              >
                Paranoid
              </button>
            </div>
            <p className="muted small">Current: {status?.security_profile ?? "balanced"}</p>
          </div>
          <div className="card">
            <h2>Biometric unlock</h2>
            <p className="muted small">
              {platformSec?.native_biometric_available
                ? `Open the wallet with ${platformSec.biometric_kind ?? "biometric"} instead of typing your passphrase.`
                : "No biometric sensor on this device."}
            </p>
            {bioUnlockStatus?.enabled && bioUnlockStatus.configured ? (
              <p className="muted small">Biometric unlock is active.</p>
            ) : null}
            {!bioUnlockStatus?.configured && platformSec?.native_biometric_available ? (
              <>
                <label className="label">Passphrase (to enable)</label>
                <input
                  type="password"
                  value={bioUnlockPass}
                  onChange={(e) => setBioUnlockPass(e.target.value)}
                  placeholder="Enter wallet passphrase"
                />
                <button
                  type="button"
                  className="primary"
                  style={{ marginTop: "0.75rem", width: "100%" }}
                  disabled={busy || watchOnly || !bioUnlockPass}
                  onClick={() => {
                    setBusy(true);
                    void api
                      .enableBiometricUnlock(bioUnlockPass)
                      .then(() => onRefresh())
                      .then(() => api.biometricUnlockStatus())
                      .then((s) => {
                        setBioUnlockStatus(s);
                        setBioUnlockPass("");
                        onToast("Biometric unlock enabled.", "success");
                      })
                      .catch((err) => onToast(formatInvokeError(err), "error"))
                      .finally(() => setBusy(false));
                  }}
                >
                  Enable biometric unlock
                </button>
              </>
            ) : null}
            {bioUnlockStatus?.configured ? (
              <button
                type="button"
                style={{ marginTop: "0.75rem", width: "100%" }}
                disabled={busy || watchOnly}
                onClick={() => {
                  setBusy(true);
                  void api
                    .disableBiometricUnlock()
                    .then(() => onRefresh())
                    .then(() => api.biometricUnlockStatus())
                    .then((s) => {
                      setBioUnlockStatus(s);
                      onToast("Biometric unlock disabled.", "success");
                    })
                    .catch((err) => onToast(formatInvokeError(err), "error"))
                    .finally(() => setBusy(false));
                }}
              >
                Disable biometric unlock
              </button>
            ) : null}
          </div>
          <div className="card">
            <h2>Biometric confirm</h2>
            <p className="muted small">
              {platformSec?.native_biometric_available
                ? `Confirm sends ≥ ${BIOMETRIC_THRESHOLD_MEI} HAC with ${platformSec.biometric_kind ?? "biometric"}.`
                : "No biometric sensor detected. Use a passkey instead, or keep sends below the limit."}
            </p>
            <div className="toggle-row">
              <span>Use biometric for sends</span>
              <input
                type="checkbox"
                checked={settings?.biometric_send_enabled ?? true}
                disabled={busy || watchOnly || !platformSec?.native_biometric_available}
                onChange={(e) => {
                  if (!settings) return;
                  void api
                    .updateSettings({ ...settings, biometric_send_enabled: e.target.checked })
                    .then(() => onRefresh())
                    .then(() => onToast(e.target.checked ? "Biometric confirm on." : "Biometric confirm off.", "success"))
                    .catch((err) => onToast(formatInvokeError(err), "error"));
                }}
              />
            </div>
            <button
              type="button"
              className="primary"
              style={{ marginTop: "0.75rem", width: "100%" }}
              disabled={busy || watchOnly || !platformSec?.native_biometric_available}
              onClick={() => {
                setBusy(true);
                void api
                  .confirmBiometric()
                  .then(() => onToast("Biometric test OK.", "success"))
                  .catch((err) => onToast(formatInvokeError(err), "error"))
                  .finally(() => setBusy(false));
              }}
            >
              Test biometric
            </button>
          </div>
          <div className="card">
            <h2>Passkey</h2>
            <p className="muted small">
              {settings?.webauthn_enabled
                ? "Registered. Used for paranoid profile and large sends when enabled."
                : "Register once to confirm large sends with your device passkey."}
            </p>
            <p className="muted small">App origin: {webAuthnClientOrigin() || "unknown"}</p>
            <div className="row-btns">
              <button type="button" className="primary" disabled={busy || !webauthnReady} onClick={() => void handleRegisterWebAuthn()}>
                Register passkey
              </button>
              <button
                type="button"
                disabled={busy || !settings?.webauthn_enabled}
                onClick={() => void handleTestWebAuthn()}
              >
                Test passkey
              </button>
            </div>
            {!webauthnReady && (
              <p className="muted small">Passkey not available in this WebView. Update the app if this persists.</p>
            )}
          </div>
          <button type="button" onClick={() => void onLock()}>
            Lock wallet
          </button>
        </>
      )}
      {page === "privacy" && (
        <div className="card">
          <h2>Privacy</h2>
          <div className="toggle-row">
            <span>Hide balances</span>
            <input
              type="checkbox"
              checked={privacy.hide_balances}
              onChange={(e) => void onPersistPrivacy({ hide_balances: e.target.checked })}
            />
          </div>
          <div className="toggle-row">
            <span>Hide addresses</span>
            <input
              type="checkbox"
              checked={privacy.hide_addresses}
              onChange={(e) => void onPersistPrivacy({ hide_addresses: e.target.checked })}
            />
          </div>
          <div className="toggle-row">
            <span>Screen privacy shield</span>
            <input
              type="checkbox"
              checked={privacy.screen_privacy}
              onChange={(e) => void onPersistPrivacy({ screen_privacy: e.target.checked })}
            />
          </div>
          <div className="toggle-row">
            <span>Store tx history</span>
            <input
              type="checkbox"
              checked={privacy.store_tx_history}
              onChange={(e) => void onPersistPrivacy({ store_tx_history: e.target.checked })}
            />
          </div>
          <div className="toggle-row">
            <span>Pause auto-lock on HACD</span>
            <input
              type="checkbox"
              checked={privacy.pause_auto_lock_dapp ?? true}
              onChange={(e) =>
                void onPersistPrivacy({ pause_auto_lock_dapp: e.target.checked })
              }
            />
          </div>
          <label className="label">Clipboard clear (seconds)</label>
          <input
            type="number"
            min={0}
            max={300}
            value={privacy.clipboard_clear_secs}
            onChange={(e) =>
              void onPersistPrivacy({ clipboard_clear_secs: Number(e.target.value) || 0 })
            }
          />
        </div>
      )}
      {page === "fastpay" && (
        <FastPayChannelScreen
          fastPay={fastPay}
          settings={settings}
          hubUrl={settingsHubUrl}
          hubAddress={settings?.hub_right_address ?? ""}
          userAddress={statusAddress}
          hideAddresses={privacy.hide_addresses}
          watchOnly={watchOnly}
          busy={busy}
          setBusy={setBusy}
          onRefresh={onRefresh}
          onApplyHub={onApplyHub}
          onToast={onToast}
        />
      )}
      {page === "whisper" && <WhisperScreen initial={dustWhisper} onToast={onToast} />}
      {page === "messages" && (
        <MessengerScreen
          myAddress={statusAddress}
          hideAddresses={privacy.hide_addresses}
          whisperEnabled={dustWhisper?.enabled}
          contacts={contacts}
          onToast={onToast}
          onGoPay={onGoPayPeer}
        />
      )}
      {page === "quantum" && (
        <QuantumScreen
          legacyAddress={statusAddress}
          nodeUrl={settings?.node_url}
          clipboardClearSecs={clipboardSecs}
          platformSec={platformSec}
          securityProfile={settings?.security_profile}
          webauthnEnabled={settings?.webauthn_enabled}
          biometricSendEnabled={settings?.biometric_send_enabled ?? true}
          onToast={onToast}
          onGoLegacySend={onGoLegacySend}
        />
      )}
      {page === "airgap" && (
        <AirgapScreen
          watchOnly={watchOnly}
          busy={busy}
          setBusy={setBusy}
          onToast={onToast}
          onBroadcast={() => void onRefresh()}
        />
      )}
      {page === "launchpad" && (
        <LaunchpadScreen pauseAutoLockDapp={privacy.pause_auto_lock_dapp ?? true} />
      )}
      {page === "contacts" && (
        <div className="card">
          <h2>Contacts</h2>
          <label className="label">Name</label>
          <input value={contactLabel} onChange={(e) => setContactLabel(e.target.value)} placeholder="Alice" />
          <label className="label">Address</label>
          <input value={contactAddress} onChange={(e) => setContactAddress(e.target.value)} placeholder="1…" />
          <button
            className="primary"
            disabled={!contactLabel.trim() || !contactAddress.trim()}
            onClick={() => {
              setContacts(addContact(contactLabel, contactAddress));
              setContactLabel("");
              setContactAddress("");
              onToast("Contact saved.", "success");
            }}
          >
            Add contact
          </button>
          {contacts.length === 0 ? (
            <p className="muted">No saved contacts.</p>
          ) : (
            contacts.map((c) => (
              <div key={c.id} className="list-item">
                <div onClick={() => onSelectContact(c)}>
                  <strong>{c.label}</strong>
                  <div className="muted">{maskAddress(c.address, privacy.hide_addresses)}</div>
                </div>
                <button
                  type="button"
                  className="small ghost"
                  onClick={() => {
                    setContacts(removeContact(c.id));
                    onToast("Contact removed.", "info");
                  }}
                >
                  Remove
                </button>
              </div>
            ))
          )}
        </div>
      )}
    </>
  );
}
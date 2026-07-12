import { api } from "../../api";
import AirgapScreen from "../../components/AirgapScreen";
import HacdLaunchpadIcon from "../../components/HacdLaunchpadIcon";
import LaunchpadScreen from "../../components/LaunchpadScreen";
import MessengerScreen from "../../components/MessengerScreen";
import QuantumScreen from "../../components/QuantumScreen";
import WhisperScreen from "../../components/WhisperScreen";
import { downloadJson } from "../../utils/downloadJson";
import FastPayChannelScreen from "../FastPayChannelScreen";
import { fastPayMenuBadge } from "../../fastPayUi";
import ContactsScreen from "./ContactsScreen";
import PrivacyScreen from "./PrivacyScreen";
import SecurityScreen from "./SecurityScreen";
import SettingsScreen from "./SettingsScreen";
import type { MoreActions, MoreData, MorePage } from "./types";

export type { MorePage } from "./types";

type Props = {
  page: MorePage;
  data: MoreData;
  actions: MoreActions;
};

export default function MoreRouter({ page, data, actions }: Props) {
  const {
    history,
    bills,
    contacts,
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
  } = data;

  const {
    onBack,
    onNavigate,
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
    setContacts,
    walletNameDraft,
    setWalletNameDraft,
  } = actions;

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
            type="button"
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
        <SettingsScreen
          status={status}
          settings={settings}
          hubHealth={hubHealth}
          busy={busy}
          setBusy={setBusy}
          onSave={onSaveSettings}
          onApplyHub={onApplyHub}
          onToast={onToast}
        />
      )}
      {page === "security" && (
        <SecurityScreen
          status={status}
          settings={settings}
          platformSec={platformSec}
          watchOnly={watchOnly}
          busy={busy}
          clipboardSecs={clipboardSecs}
          walletNameDraft={walletNameDraft}
          setWalletNameDraft={setWalletNameDraft}
          onSaveWalletName={onSaveWalletName}
          onExportBackup={onExportBackup}
          onChangePassphrase={onChangePassphrase}
          onResetWallet={onResetWallet}
          onLock={onLock}
          onRefresh={onRefresh}
          onToast={onToast}
          setBusy={setBusy}
        />
      )}
      {page === "privacy" && <PrivacyScreen privacy={privacy} onPersistPrivacy={onPersistPrivacy} />}
      {page === "fastpay" && (
        <FastPayChannelScreen
          fastPay={fastPay}
          settings={settings}
          hubUrl={settings?.l2_hub_url ?? ""}
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
        <ContactsScreen
          contacts={contacts}
          setContacts={setContacts}
          hideAddresses={privacy.hide_addresses}
          onSelectContact={onSelectContact}
          onToast={onToast}
        />
      )}
    </>
  );
}
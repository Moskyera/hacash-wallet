import { api } from "../../api";
import TxStatusMark from "../../components/TxStatusMark";
import { formatHacMei } from "../../privacy";
import { openTxInExplorer } from "../../txHistory";
import { canOpenTxInExplorer } from "../../explorer";
import AirgapScreen from "../../components/AirgapScreen";
import HacdLaunchpadIcon from "../../components/HacdLaunchpadIcon";
import LaunchpadScreen from "../../components/LaunchpadScreen";
import MessengerScreen from "../../components/MessengerScreen";
import QuantumScreen from "../../components/QuantumScreen";
import WhisperScreen from "../../components/WhisperScreen";
import { downloadJson } from "../../utils/downloadJson";
import FastPayChannelScreen from "../FastPayChannelScreen";
import HacdTab from "../HacdTab";
import { fastPayMenuBadge } from "../../fastPayUi";
import { LanguageSwitcher, useLocale } from "../../locale";
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
  const { t } = useLocale();
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
        <p className="section-title">{t("more.wallet")}</p>
        <button type="button" onClick={() => onNavigate("history")}>
          <span>{t("more.transactions")}</span>
          <span>{history.length}</span>
        </button>
        <button type="button" onClick={() => onNavigate("bills")}>
          <span>{t("more.bills")}</span>
          <span>{bills.length}</span>
        </button>
        <button type="button" onClick={() => onNavigate("fastpay")}>
          <span>Fast Pay</span>
          <span>{fastPayMenuBadge(fastPay?.state)}</span>
        </button>
        <button type="button" onClick={() => onNavigate("contacts")}>
          <span>{t("more.contacts")}</span>
          <span>{contacts.length}</span>
        </button>
        <button type="button" onClick={() => onNavigate("hacd")}>
          <span>{t("more.hacd")}</span>
          <span>◆</span>
        </button>
        <button type="button" onClick={() => onNavigate("messages")}>
          <span>{t("nav.messages")}</span>
          <span>••</span>
        </button>
        <button type="button" onClick={() => onNavigate("quantum")}>
          <span>{t("more.quantum")}</span>
          <span>◇</span>
        </button>
        <button type="button" onClick={() => onNavigate("airgap")}>
          <span>{t("more.airgap")}</span>
          <span>◎</span>
        </button>
        <button type="button" onClick={() => onNavigate("launchpad")}>
          <span>{t("more.launchpad")}</span>
          <span className="menu-icon" aria-hidden>
            <HacdLaunchpadIcon />
          </span>
        </button>
        <button type="button" onClick={() => onNavigate("whisper")}>
          <span>DUST Whisper</span>
          <span>{dustWhisper?.enabled ? t("status.on") : t("status.off")}</span>
        </button>
        <p className="section-title">{t("more.preferences")}</p>
        <div className="card language-card">
          <h2 className="section-title" style={{ marginTop: 0 }}>
            {t("more.language")}
          </h2>
          <LanguageSwitcher />
        </div>
        <button type="button" onClick={() => onNavigate("settings")}>
          <span>{t("more.network")}</span>
          <span>→</span>
        </button>
        <button type="button" onClick={() => onNavigate("privacy")}>
          <span>{t("nav.privacy")}</span>
          <span>→</span>
        </button>
        <button type="button" onClick={() => onNavigate("security")}>
          <span>{t("nav.security")}</span>
          <span>→</span>
        </button>
      </div>
    );
  }

  return (
    <>
      <button type="button" className="ghost small" onClick={onBack}>
        ← {t("more.back")}
      </button>
      {page === "history" && (
        <div className="card">
          <h2>Transactions</h2>
          {history.length === 0 ? (
            <p className="muted">No transactions yet.</p>
          ) : (
            history.map((row) => {
              const showExplorer = canOpenTxInExplorer(row.rail, row.tx_hash);
              return (
                <div key={`${row.tx_hash}-${row.timestamp}`} className="list-item list-item-row">
                  <TxStatusMark status={row.status} />
                  <div className="list-item-body">
                    <div>
                      <span className="badge badge-rail">{row.rail}</span> {formatHacMei(row.amount_mei)} HAC
                    </div>
                    <div className="muted">{row.summary}</div>
                    <div className="muted">{row.timestamp}</div>
                  </div>
                  {showExplorer ? (
                    <button
                      type="button"
                      className="ghost small"
                      onClick={() => void openTxInExplorer(row, onToast)}
                    >
                      Explorer
                    </button>
                  ) : null}
                </div>
              );
            })
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
      {page === "hacd" && (
        <HacdTab
          locked={!status || status.locked}
          busy={busy}
          onToast={onToast}
          onGoPay={onGoLegacySend}
        />
      )}
      {page === "quantum" && (
        <QuantumScreen
          legacyAddress={statusAddress}
          nodeUrl={settings?.node_url}
          networkMode={settings?.network_mode ?? "mainnet"}
          clipboardClearSecs={clipboardSecs}
          platformSec={platformSec}
          securityProfile={settings?.security_profile}
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
        <LaunchpadScreen
          pauseAutoLockDapp={privacy.pause_auto_lock_dapp ?? true}
          watchOnly={watchOnly}
          onNotify={onToast}
        />
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
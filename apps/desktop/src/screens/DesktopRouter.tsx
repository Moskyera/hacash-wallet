import { useLocale } from "@hacash/wallet-ui";
import AirgapScreen from "../AirgapScreen";
import { AssetSummary, HubDiscoveryEntry, TxRecord, WalletSettings, WalletStatus } from "../api";
import type { AssetTrendHistory } from "../assetTrends";
import { HubFeePayer, L1FeeSpeed, SendPreview } from "../api";
import { DustWhisperSettings, PrivacySettings, RelayHealthStatus } from "../api";
import { ChannelInfo, HubHealth } from "../api";
import type { FastPayStatus } from "../fastPayUi";
import type { PaymentQrPayload } from "../paymentQr";
import AdvancedScreen from "./AdvancedScreen";
import FastPayScreen from "./FastPayScreen";
import HacdScreen from "./HacdScreen";
import HistoryScreen from "./HistoryScreen";
import HomeScreen from "./HomeScreen";
import PrivacyScreen from "./PrivacyScreen";
import QuantumScreen from "./QuantumScreen";
import ReceiveScreen from "./ReceiveScreen";
import SecurityInfoScreen from "./SecurityInfoScreen";
import SecurityScreen from "./SecurityScreen";
import SendScreen from "./SendScreen";
import SettingsScreen from "./SettingsScreen";
import UnlockScreen from "./UnlockScreen";
import WelcomeScreen from "./WelcomeScreen";
import type { Screen } from "./types";

export type DesktopData = {
  status: WalletStatus | null;
  settings: WalletSettings | null;
  assets: AssetSummary | null;
  assetTrends: AssetTrendHistory;
  fastPayDetail: FastPayStatus | null;
  channelInfo: ChannelInfo | null;
  hubHealth: HubHealth | null | undefined;
  billsCount: number;
  txHistory: TxRecord[];
  lastTx: string;
  webauthnReady: boolean;
  nativeBioAvailable: boolean;
  relayHealth: RelayHealthStatus[];
  privacy: PrivacySettings;
  dustWhisper: DustWhisperSettings;
  busy: boolean;
  fastPayReady: boolean;
  fastPayNeedsSetup: boolean;
  hideBalances: boolean;
  hideAddresses: boolean;
  sendActive: boolean;
  sendTo: string;
  sendAmount: string;
  sendHubFeePayer: HubFeePayer;
  sendForceL1: boolean;
  sendL1FeeSpeed: L1FeeSpeed;
  sendServiceFeeEnabled: boolean;
  serviceFeeRate: number;
  showSendOptions: boolean;
  sendQrScanOpen: boolean;
  preview: SendPreview | null;
};

export type DesktopActions = {
  setBusy: (b: boolean) => void;
  setScreen: (s: Screen) => void;
  clearMessages: () => void;
  onError: (msg: string) => void;
  onInfo: (msg: string) => void;
  onNotify: (msg: string, kind: "error" | "info" | "success") => void;
  onCreate: (passphrase: string) => void;
  onImport: (seed: string, passphrase: string, expectedAddress: string) => void;
  onImportBackup: (
    json: string,
    passphrase: string,
    deleteSource?: string | null,
    allowLegacy?: boolean,
  ) => void;
  onWatchOnly: (address: string) => void;
  onUnlock: (passphrase: string) => void;
  onLock: () => void;
  onOpenQrPay: () => void;
  onEnableFastPay: (userDeposit: string) => void;
  onApplyHub: (entry: HubDiscoveryEntry) => Promise<void>;
  onSaveL2Settings: (nodeUrl: string, hubUrl: string, hubAddress: string) => void;
  onHubHealth: () => void;
  onPreviewChannel: (
    hubAddress: string,
    userDeposit: string,
    hubDeposit: string,
    setChannelPreview: (p: import("../api").ChannelSetupPreview | null) => void,
  ) => void;
  onOpenChannel: (
    hubAddress: string,
    userDeposit: string,
    hubDeposit: string,
    setChannelPreview: (p: import("../api").ChannelSetupPreview | null) => void,
  ) => void;
  onCloseChannel: (setChannelPreview: (p: import("../api").ChannelSetupPreview | null) => void) => void;
  onRegisterWebAuthn: (currentPassphrase: string) => void;
  onSetProfile: (profile: string, currentPassphrase: string) => void;
  onSetSecondFactorThreshold: (amountMei: number | null, currentPassphrase: string) => void;
  onSetHardwareMode: (
    mode: "software" | "webauthn_gate" | "airgap_only" | "watch_only",
    currentPassphrase: string,
  ) => void;
  onSaveSettings: (nodeUrl: string, fallbackUrls: string[], autoFailover: boolean) => void;
  onChangePassphrase: (old: string, newPass: string, confirm: string) => Promise<boolean>;
  onExportBackup: (passphrase: string) => Promise<string | null>;
  onValidateHip23: Parameters<typeof AdvancedScreen>[0]["onValidate"];
  onSavePrivacy: (draft: PrivacySettings) => void;
  onSaveWhisper: (draft: DustWhisperSettings, relayText: string) => Promise<DustWhisperSettings | null>;
  onClearHistory: () => void;
  onCopyAddress: () => void;
  refreshUnlockedData: () => Promise<void>;
  setSendTo: (v: string) => void;
  setSendAmount: (v: string) => void;
  setSendForceL1: (v: boolean) => void;
  setSendL1FeeSpeed: (v: L1FeeSpeed) => void;
  setSendServiceFeeEnabled: (v: boolean) => void;
  setShowSendOptions: (v: boolean | ((prev: boolean) => boolean)) => void;
  setSendQrScanOpen: (v: boolean | ((prev: boolean) => boolean)) => void;
  clearPreview: () => void;
  persistSendPreferences: (
    hubFeePayer: HubFeePayer,
    forceL1: boolean,
    l1FeeSpeed?: L1FeeSpeed,
    serviceFeeEnabled?: boolean,
  ) => Promise<void>;
  onPaymentQr: (payload: PaymentQrPayload) => void;
  onPreviewSend: (speedOverride?: L1FeeSpeed) => void;
  onConfirmSend: () => void;
};

type Props = {
  screen: Screen;
  data: DesktopData;
  actions: DesktopActions;
};

export default function DesktopRouter({ screen, data, actions }: Props) {
  const { t } = useLocale();
  const {
    status,
    settings,
    assets,
    assetTrends,
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
    busy,
    fastPayReady,
    fastPayNeedsSetup,
    hideBalances,
    hideAddresses,
    sendActive,
    sendTo,
    sendAmount,
    sendHubFeePayer,
    sendForceL1,
    sendL1FeeSpeed,
    sendServiceFeeEnabled,
    serviceFeeRate,
    showSendOptions,
    sendQrScanOpen,
    preview,
  } = data;

  const {
    setBusy,
    setScreen,
    clearMessages,
    onError,
    onInfo,
    onNotify,
    onCreate,
    onImport,
    onImportBackup,
    onWatchOnly,
    onUnlock,
    onLock,
    onOpenQrPay,
    onEnableFastPay,
    onApplyHub,
    onSaveL2Settings,
    onHubHealth,
    onPreviewChannel,
    onOpenChannel,
    onCloseChannel,
    onRegisterWebAuthn,
    onSetProfile,
    onSetSecondFactorThreshold,
    onSetHardwareMode,
    onSaveSettings,
    onChangePassphrase,
    onExportBackup,
    onValidateHip23,
    onSavePrivacy,
    onSaveWhisper,
    onClearHistory,
    onCopyAddress,
    refreshUnlockedData,
    setSendTo,
    setSendAmount,
    setSendForceL1,
    setSendL1FeeSpeed,
    setSendServiceFeeEnabled,
    setShowSendOptions,
    setSendQrScanOpen,
    clearPreview,
    persistSendPreferences,
    onPaymentQr,
    onPreviewSend,
    onConfirmSend,
  } = actions;

  const coldBlockedScreen =
    status?.hardware_signing_mode === "airgap_only" &&
    (["send", "fastpay", "hacd", "quantum", "settings", "advanced"] as Screen[]).includes(
      screen,
    );
  if (coldBlockedScreen) {
    return (
      <section className="panel panel-wide">
        <h2>{t("security.coldVaultTitle")}</h2>
        <p className="warn-box">{t("airgap.coldVaultCoordinatorBlocked")}</p>
        <button
          type="button"
          className="primary"
          onClick={() => setScreen("airgap")}
        >
          {t("more.airgap")}
        </button>
      </section>
    );
  }

  switch (screen) {
    case "welcome":
      return (
        <WelcomeScreen
          busy={busy}
          onCreate={onCreate}
          onImport={onImport}
          onImportBackup={onImportBackup}
          onWatchOnly={onWatchOnly}
        />
      );
    case "unlock":
      return (
        <UnlockScreen
          status={status}
          hideAddresses={hideAddresses}
          busy={busy}
          onUnlock={onUnlock}
        />
      );
    case "home":
      return (
        <HomeScreen
          status={status}
          assets={assets}
          assetTrends={assetTrends}
          history={txHistory}
          hideBalances={hideBalances}
          hideAddresses={hideAddresses}
          fastPayReady={fastPayReady}
          lastTx={lastTx}
          privacy={privacy}
          onNavigate={setScreen}
          onNotify={onNotify}
          clearMessages={clearMessages}
        />
      );
    case "fastpay":
      return (
        <FastPayScreen
          status={status}
          settings={settings}
          fastPayDetail={fastPayDetail}
          channelInfo={channelInfo}
          hubHealth={hubHealth}
          billsCount={billsCount}
          fastPayReady={fastPayReady}
          fastPayNeedsSetup={fastPayNeedsSetup}
          hideAddresses={hideAddresses}
          busy={busy}
          setBusy={setBusy}
          onNavigate={setScreen}
          onEnableFastPay={onEnableFastPay}
          onApplyHub={onApplyHub}
          onSaveL2Settings={onSaveL2Settings}
          onHubHealth={onHubHealth}
          onPreviewChannel={onPreviewChannel}
          onOpenChannel={onOpenChannel}
          onCloseChannel={onCloseChannel}
          onRefresh={refreshUnlockedData}
          onNotify={onNotify}
          clearMessages={clearMessages}
        />
      );
    case "send":
      return (
        <SendScreen
          active={sendActive}
          status={status}
          assets={assets}
          hideBalances={hideBalances}
          hideAddresses={hideAddresses}
          fastPayReady={fastPayReady}
          nativeBioAvailable={nativeBioAvailable}
          busy={busy}
          setBusy={setBusy}
          sendTo={sendTo}
          setSendTo={setSendTo}
          sendAmount={sendAmount}
          setSendAmount={setSendAmount}
          sendHubFeePayer={sendHubFeePayer}
          sendForceL1={sendForceL1}
          setSendForceL1={setSendForceL1}
          sendL1FeeSpeed={sendL1FeeSpeed}
          setSendL1FeeSpeed={setSendL1FeeSpeed}
          sendServiceFeeEnabled={sendServiceFeeEnabled}
          setSendServiceFeeEnabled={setSendServiceFeeEnabled}
          serviceFeeRate={serviceFeeRate}
          showSendOptions={showSendOptions}
          setShowSendOptions={setShowSendOptions}
          sendQrScanOpen={sendQrScanOpen}
          setSendQrScanOpen={setSendQrScanOpen}
          preview={preview}
          clearPreview={clearPreview}
          persistSendPreferences={persistSendPreferences}
          onPaymentQr={onPaymentQr}
          onPreviewSend={onPreviewSend}
          onConfirmSend={onConfirmSend}
          onNavigate={setScreen}
          onNotify={onNotify}
          onSent={refreshUnlockedData}
        />
      );
    case "receive":
      return (
        <ReceiveScreen
          address={status?.address}
          ownedHacdNames={assets?.hacd_names ?? undefined}
          hideAddresses={hideAddresses}
          clipboardSecs={privacy.clipboard_clear_secs}
          busy={busy}
          onCopyAddress={onCopyAddress}
          onNotify={onNotify}
        />
      );
    case "hacd":
      return (
        <HacdScreen
          locked={!!status?.locked}
          busy={busy}
          onNotify={onNotify}
          onGoSend={() => setScreen("send")}
        />
      );
    case "history":
      return (
        <HistoryScreen
          txHistory={txHistory}
          hideAddresses={hideAddresses}
          hideBalances={hideBalances}
          onNotify={onNotify}
        />
      );
    case "advanced":
      return (
        <AdvancedScreen
          busy={busy}
          currentAddress={status?.address}
          networkMode={settings?.network_mode ?? status?.network_mode ?? "mainnet"}
          onValidate={onValidateHip23}
        />
      );
    case "quantum":
      return (
        <QuantumScreen
          status={status}
          settings={settings}
          busy={busy}
          nativeBioAvailable={nativeBioAvailable}
          onNavigate={setScreen}
          onSetSendTo={setSendTo}
        />
      );
    case "settings":
      return (
        <SettingsScreen
          settings={settings}
          busy={busy}
          onSave={onSaveSettings}
          onInfo={onInfo}
          onError={onError}
        />
      );
    case "security":
      return (
        <section className="panel">
          <h2>Security</h2>
          <SecurityInfoScreen
            status={status}
            webauthnReady={webauthnReady}
            nativeBioAvailable={nativeBioAvailable}
            busy={busy}
            onRegisterWebAuthn={onRegisterWebAuthn}
            onSetProfile={onSetProfile}
            onSetSecondFactorThreshold={onSetSecondFactorThreshold}
            onSetHardwareMode={onSetHardwareMode}
          />
          <SecurityScreen
            busy={busy}
            onChangePassphrase={onChangePassphrase}
            onExportBackup={onExportBackup}
          />
        </section>
      );
    case "privacy":
      return (
        <PrivacyScreen
          status={status}
          dustWhisper={dustWhisper}
          relayHealth={relayHealth}
          busy={busy}
          onSavePrivacy={onSavePrivacy}
          onSaveWhisper={onSaveWhisper}
          onClearHistory={onClearHistory}
        />
      );
    case "airgap":
      return status && !status.locked ? (
        <AirgapScreen
          status={status}
          busy={busy}
          setBusy={setBusy}
          clearMessages={clearMessages}
          setError={onError}
          setInfo={onInfo}
          onBroadcast={refreshUnlockedData}
          onLock={onLock}
          nativeBioAvailable={nativeBioAvailable}
        />
      ) : null;
    default:
      return null;
  }
}

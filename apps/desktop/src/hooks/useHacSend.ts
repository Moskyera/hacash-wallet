import { useCallback, useEffect, useState } from "react";
import { api, HubFeePayer, type L1FeeSpeed, SendOptions, SendPreview, WalletSettings } from "../api";
import { formatInvokeError } from "../formatInvokeError";
import { authorizePreparedOperation } from "../preparedAuthorization";
import { DEFAULT_SERVICE_FEE_RATE, sendSuccessMessage } from "../fastPayUi";
import type { PaymentQrPayload } from "../paymentQr";
import type { Screen } from "../screens/types";
import type { WalletStatus } from "../api";

type Notify = (msg: string, kind: "error" | "info") => void;

export function useHacSend(opts: {
  settings: WalletSettings | null;
  status: WalletStatus | null;
  nativeBioAvailable: boolean;
  setScreen: (s: Screen) => void;
  refreshBalance: () => Promise<void>;
  refreshHistory: () => Promise<void>;
  refreshSettings: () => Promise<WalletSettings>;
  setLastTxHash: (hash: string) => void;
  clearMessages: () => void;
  onError: (msg: string) => void;
  onInfo: (msg: string) => void;
  setBusy: (b: boolean) => void;
  busy: boolean;
}) {
  const {
    settings,
    status,
    nativeBioAvailable,
    setScreen,
    refreshBalance,
    refreshHistory,
    refreshSettings,
    setLastTxHash,
    clearMessages,
    onError,
    onInfo,
    setBusy,
    busy,
  } = opts;

  const [sendTo, setSendTo] = useState("");
  const [sendAmount, setSendAmount] = useState("");
  const [sendHubFeePayer, setSendHubFeePayer] = useState<HubFeePayer>("sender");
  const [sendForceL1, setSendForceL1] = useState(false);
  const [sendL1FeeSpeed, setSendL1FeeSpeed] = useState<L1FeeSpeed>("normal");
  const [sendServiceFeeEnabled, setSendServiceFeeEnabled] = useState(true);
  const [showSendOptions, setShowSendOptions] = useState(false);
  const [sendQrScanOpen, setSendQrScanOpen] = useState(false);
  const [preview, setPreview] = useState<SendPreview | null>(null);

  useEffect(() => {
    if (!settings) return;
    setSendHubFeePayer(settings.send?.hub_fee_payer ?? "sender");
    setSendForceL1(!(settings.send?.prefer_fast_pay ?? true));
    setSendL1FeeSpeed(settings.send?.l1_fee_speed ?? "normal");
    setSendServiceFeeEnabled(true);
  }, [
    settings?.send?.hub_fee_payer,
    settings?.send?.prefer_fast_pay,
    settings?.send?.l1_fee_speed,
    settings?.send?.service_fee_enabled,
    settings,
  ]);

  const serviceFeeRate = settings?.send?.service_fee_rate ?? DEFAULT_SERVICE_FEE_RATE;

  const currentSendOptions = useCallback(
    (): SendOptions => ({
      hub_fee_payer: sendHubFeePayer,
      force_l1: sendForceL1,
      l1_fee_speed: sendL1FeeSpeed,
      service_fee_enabled: true,
      service_fee_rate: DEFAULT_SERVICE_FEE_RATE,
    }),
    [sendHubFeePayer, sendForceL1, sendL1FeeSpeed, sendServiceFeeEnabled, serviceFeeRate],
  );

  const persistSendPreferences = useCallback(
    async (
      hubFeePayer: HubFeePayer,
      forceL1: boolean,
      l1FeeSpeed: L1FeeSpeed = sendL1FeeSpeed,
      serviceFeeEnabled: boolean = sendServiceFeeEnabled,
    ) => {
      if (!settings) return;
      const next = {
        ...settings,
        send: {
          hub_fee_payer: hubFeePayer,
          prefer_fast_pay: !forceL1,
          l1_fee_speed: l1FeeSpeed,
          service_fee_enabled: true,
          service_fee_rate: DEFAULT_SERVICE_FEE_RATE,
        },
      };
      await api.updateSettings(next);
      await refreshSettings();
    },
    [sendL1FeeSpeed, sendServiceFeeEnabled, serviceFeeRate, settings, refreshSettings],
  );

  const openQrPay = useCallback(() => {
    clearMessages();
    setPreview(null);
    setSendQrScanOpen(true);
    setScreen("send");
  }, [clearMessages, setScreen]);

  const handlePaymentQr = useCallback(
    async (payload: PaymentQrPayload) => {
      clearMessages();
      setSendQrScanOpen(false);
      setSendTo(payload.address);
      const amount = payload.amount_mei;
      if (amount != null && amount > 0) {
        setSendAmount(String(amount));
        setBusy(true);
        try {
          const p = await api.previewSend(payload.address, amount, currentSendOptions());
          setPreview(p);
          onInfo(
            payload.label
              ? `QR payment (${payload.label}). review and confirm.`
              : "QR payment loaded. review and confirm.",
          );
        } catch (e) {
          onError(formatInvokeError(e));
        } finally {
          setBusy(false);
        }
      } else {
        setSendAmount("");
        setPreview(null);
        onInfo("Address scanned. enter amount and tap Continue.");
      }
      setScreen("send");
    },
    [clearMessages, currentSendOptions, setScreen, setBusy, onInfo, onError],
  );

  const handlePreviewSend = useCallback(
    async (speedOverride?: L1FeeSpeed) => {
      setBusy(true);
      clearMessages();
      setPreview(null);
      if (speedOverride) setSendL1FeeSpeed(speedOverride);
      try {
        const p = await api.previewSend(sendTo.trim(), Number(sendAmount), {
          ...currentSendOptions(),
          l1_fee_speed: speedOverride ?? sendL1FeeSpeed,
        });
        setPreview(p);
      } catch (e) {
        onError(formatInvokeError(e));
      } finally {
        setBusy(false);
      }
    },
    [sendTo, sendAmount, currentSendOptions, sendL1FeeSpeed, clearMessages, setBusy, onError],
  );

  const handleConfirmSend = useCallback(async () => {
    setBusy(true);
    clearMessages();
    void refreshHistory();
    try {
      const amount = Number(sendAmount);
      // Mirror of authorization_requirement() in wallet-core. A hardware gate and a
      // Cold Vault need a factor for every amount, and the core rounds the policed
      // amount up, so 99.5 needs one too. Being more permissive here just turns a
      // usable "Select Force L1" hint into a raw policy error at the moment of paying.
      const needsAuthorization =
        status?.hardware_signing_mode === "webauthn_gate" ||
        status?.hardware_signing_mode === "airgap_only" ||
        status?.security_profile === "paranoid" ||
        Math.ceil(amount) >= (status?.require_second_factor_above_mei ?? 100);
      let result;
      if (preview?.plan.rail === "L2Fast") {
        if (needsAuthorization) {
          throw new Error(
            "Protected Fast Pay is blocked until its exact settlement bill can be prepared before authorization. Select Force L1.",
          );
        }
        result = await api.sendHac(sendTo.trim(), amount, currentSendOptions());
      } else {
        const prepared = await api.prepareSendHac(sendTo.trim(), amount, currentSendOptions());
        await authorizePreparedOperation(prepared, nativeBioAvailable);
        result = await api.executePreparedHac(prepared.id);
      }
      setLastTxHash(result.tx_hash);
      setPreview(null);
      setSendTo("");
      setSendAmount("");
      await refreshBalance();
      await refreshHistory();
      onInfo(result.pending ? result.summary : sendSuccessMessage(result.rail, result.summary));
      setScreen("home");
    } catch (e) {
      onError(formatInvokeError(e));
    } finally {
      setBusy(false);
    }
  }, [
    sendTo,
    sendAmount,
    status,
    nativeBioAvailable,
    currentSendOptions,
    clearMessages,
    setBusy,
    setLastTxHash,
    refreshBalance,
    refreshHistory,
    onInfo,
    onError,
    setScreen,
  ]);

  const clearPreview = useCallback(() => setPreview(null), []);

  return {
    sendTo,
    setSendTo,
    sendAmount,
    setSendAmount,
    sendHubFeePayer,
    setSendHubFeePayer,
    sendForceL1,
    setSendForceL1,
    sendL1FeeSpeed,
    setSendL1FeeSpeed,
    sendServiceFeeEnabled,
    setSendServiceFeeEnabled,
    serviceFeeRate,
    showSendOptions,
    setShowSendOptions,
    sendQrScanOpen,
    setSendQrScanOpen,
    preview,
    setPreview,
    clearPreview,
    currentSendOptions,
    persistSendPreferences,
    openQrPay,
    handlePaymentQr,
    handlePreviewSend,
    handleConfirmSend,
    busy,
  };
}

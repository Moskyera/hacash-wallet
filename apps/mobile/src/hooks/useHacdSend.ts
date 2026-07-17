import { useCallback, useEffect, useState } from "react";
import { api, type HacdSendPreview, type PlatformSecurityStatus, type WalletSettings } from "../api";
import { maybeSecondFactorGate } from "../utils/secondFactorGate";
import { formatInvokeError } from "../formatInvokeError";
import { hapticSuccess } from "../utils/haptic";
import { isValidHacdName, normalizeHacdName } from "../utils/paymentAssets";

export function useHacdSend(opts: {
  active: boolean;
  settings: WalletSettings | null;
  platformSec: PlatformSecurityStatus | null;
  setBusy: (b: boolean) => void;
  refresh: () => Promise<void>;
  showToast: (msg: string, kind: "success" | "info" | "error") => void;
}) {
  const { active, settings, platformSec, setBusy, refresh, showToast } = opts;

  const [owned, setOwned] = useState<string[]>([]);
  const [selected, setSelected] = useState<string[]>([]);
  const [batchMode, setBatchMode] = useState(false);
  const [recipient, setRecipient] = useState("");
  const [recipientScanOpen, setRecipientScanOpen] = useState(false);
  const [preview, setPreview] = useState<HacdSendPreview | null>(null);

  useEffect(() => {
    if (!active) return;
    let cancelled = false;
    void api
      .listOwnedDiamonds()
      .then((list) => {
        if (!cancelled) setOwned(list);
      })
      .catch(() => {
        if (!cancelled) setOwned([]);
      });
    return () => {
      cancelled = true;
    };
  }, [active]);

  useEffect(() => {
    if (!active) {
      setRecipientScanOpen(false);
      setPreview(null);
    }
  }, [active]);

  const resetPreview = useCallback(() => setPreview(null), []);

  const toggleDiamond = useCallback(
    (name: string) => {
      const norm = normalizeHacdName(name);
      if (!isValidHacdName(norm)) return;
      if (!batchMode) {
        setSelected([norm]);
        return;
      }
      setSelected((prev) =>
        prev.includes(norm) ? prev.filter((d) => d !== norm) : [...prev, norm].sort(),
      );
    },
    [batchMode],
  );

  const setSingleDiamond = useCallback((name: string) => {
    setSelected([normalizeHacdName(name)]);
  }, []);

  const handlePreview = useCallback(async () => {
    const names = selected.filter((n) => isValidHacdName(n));
    const to = recipient.trim();
    if (names.length === 0) {
      showToast("Select at least one HACD.", "error");
      return;
    }
    if (!to) {
      showToast("Enter recipient Hacash address.", "error");
      return;
    }
    setBusy(true);
    setPreview(null);
    try {
      const p = await api.previewSendHacd(to, names);
      setPreview(p);
    } catch (e) {
      showToast(formatInvokeError(e), "error");
    } finally {
      setBusy(false);
    }
  }, [recipient, selected, setBusy, showToast]);

  const handleConfirm = useCallback(async () => {
    if (!preview) return;
    try {
      await maybeSecondFactorGate({
        amountMei: Number.POSITIVE_INFINITY,
        securityProfile: settings?.security_profile,
        biometricSendEnabled: settings?.biometric_send_enabled ?? true,
        nativeBiometricAvailable: platformSec?.native_biometric_available,
      });
    } catch (e) {
      showToast(formatInvokeError(e), "error");
      return;
    }
    setBusy(true);
    try {
      void refresh();
      const result = await api.sendHacd(preview.to, preview.diamond_names);
      setPreview(null);
      setSelected([]);
      setRecipient("");
      setRecipientScanOpen(false);
      const count = preview.diamond_count;
      showToast(
        count === 1
          ? `HACD sent on chain (${result.rail})`
          : `${count} HACD sent on chain (${result.rail})`,
        "success",
      );
      hapticSuccess();
      const list = await api.listOwnedDiamonds();
      setOwned(list);
      await refresh();
    } catch (e) {
      showToast(formatInvokeError(e), "error");
    } finally {
      setBusy(false);
    }
  }, [platformSec, preview, refresh, setBusy, settings, showToast]);

  const applyRecipientAddress = useCallback(
    (address: string) => {
      setRecipient(address);
      setRecipientScanOpen(false);
      resetPreview();
      showToast("Recipient address from QR.", "success");
    },
    [resetPreview, showToast],
  );

  return {
    owned,
    selected,
    batchMode,
    setBatchMode,
    toggleDiamond,
    setSingleDiamond,
    recipient,
    setRecipient,
    recipientScanOpen,
    setRecipientScanOpen,
    preview,
    resetPreview,
    handlePreview,
    handleConfirm,
    applyRecipientAddress,
  };
}

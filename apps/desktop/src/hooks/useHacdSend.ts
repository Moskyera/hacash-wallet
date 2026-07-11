import { useCallback, useEffect, useState } from "react";
import { api, type HacdSendPreview } from "../api";
import { formatInvokeError } from "../formatInvokeError";
import { isValidHacdName, normalizeHacdName } from "../utils/paymentAssets";

export function useHacdSend(opts: {
  active: boolean;
  nativeBioAvailable: boolean;
  setBusy: (b: boolean) => void;
  onNotify: (msg: string, kind: "success" | "info" | "error") => void;
  onSent: () => Promise<void>;
}) {
  const { active, nativeBioAvailable, setBusy, onNotify, onSent } = opts;

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
      onNotify("Select at least one HACD.", "error");
      return;
    }
    if (!to) {
      onNotify("Enter recipient Hacash address.", "error");
      return;
    }
    setBusy(true);
    setPreview(null);
    try {
      const p = await api.previewSendHacd(to, names);
      setPreview(p);
    } catch (e) {
      onNotify(formatInvokeError(e), "error");
    } finally {
      setBusy(false);
    }
  }, [recipient, selected, setBusy, onNotify]);

  const handleConfirm = useCallback(async () => {
    if (!preview) return;
    if (nativeBioAvailable) {
      try {
        await api.confirmBiometricNative();
      } catch (e) {
        onNotify(formatInvokeError(e), "error");
        return;
      }
    }
    setBusy(true);
    try {
      const result = await api.sendHacd(preview.to, preview.diamond_names);
      setPreview(null);
      setSelected([]);
      setRecipient("");
      setRecipientScanOpen(false);
      const count = preview.diamond_count;
      onNotify(
        count === 1
          ? `HACD sent on chain (${result.rail})`
          : `${count} HACD sent on chain (${result.rail})`,
        "success",
      );
      const list = await api.listOwnedDiamonds();
      setOwned(list);
      await onSent();
    } catch (e) {
      onNotify(formatInvokeError(e), "error");
    } finally {
      setBusy(false);
    }
  }, [nativeBioAvailable, preview, onSent, setBusy, onNotify]);

  const applyRecipientAddress = useCallback(
    (address: string) => {
      setRecipient(address);
      setRecipientScanOpen(false);
      resetPreview();
      onNotify("Recipient address from QR.", "success");
    },
    [resetPreview, onNotify],
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
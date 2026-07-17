import { useCallback, useEffect, useState } from "react";
import { api } from "../api";
import HacdDiamondVisual from "../components/HacdDiamondVisual";
import { formatInvokeError } from "../formatInvokeError";
import { useLocale } from "../locale";
import { isValidHacdName, normalizeHacdName } from "../utils/paymentAssets";

type Props = {
  locked: boolean;
  busy: boolean;
  ownedHint?: string[];
  onNotify: (msg: string, kind: "success" | "info" | "error") => void;
  onGoSend?: () => void;
};

/**
 * Dedicated HACD gallery: owned diamonds as full on-chain metadata cards
 * (Explorer-style card via HacdDiamondVisual — not a bare HIP-5 chip).
 */
export default function HacdScreen({ locked, busy, ownedHint, onNotify, onGoSend }: Props) {
  const { t } = useLocale();
  const [owned, setOwned] = useState<string[]>(ownedHint ?? []);
  const [lookup, setLookup] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const refresh = useCallback(async () => {
    if (locked) {
      setOwned([]);
      setError(t("hacd.unlockFirst"));
      return;
    }
    setLoading(true);
    setError("");
    try {
      const names = await api.listOwnedDiamonds();
      setOwned(names);
    } catch (e) {
      const msg = formatInvokeError(e);
      setError(msg);
      onNotify(msg, "error");
    } finally {
      setLoading(false);
    }
  }, [locked, onNotify, t]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const lookupName = normalizeHacdName(lookup);
  const showLookup = isValidHacdName(lookupName);
  const gallery = showLookup && !owned.includes(lookupName) ? [lookupName, ...owned] : owned;

  return (
    <section className="stack hacd-gallery-screen">
      <header className="panel-head row-between">
        <div>
          <h2>{t("hacd.title")}</h2>
          <p className="muted">{t("hacd.subtitle")}</p>
        </div>
        <div className="row-btns">
          <button type="button" className="btn-ghost" disabled={busy || loading || locked} onClick={() => void refresh()}>
            {loading ? t("hacd.refreshing") : t("hacd.refresh")}
          </button>
          {onGoSend && (
            <button type="button" className="primary" disabled={busy || locked} onClick={onGoSend}>
              {t("hacd.send")}
            </button>
          )}
        </div>
      </header>

      <div className="panel">
        <label className="field">
          {t("hacd.lookup")}
          <input
            value={lookup}
            onChange={(e) => setLookup(e.target.value.toUpperCase())}
            placeholder="e.g. AVZXZS"
            maxLength={6}
            autoComplete="off"
            spellCheck={false}
          />
        </label>
        <p className="muted small-note">{t("hacd.lookupHint")}</p>
      </div>

      {error && <p className="form-error">{error}</p>}

      {locked ? (
        <div className="panel info-box">
          <p>{t("hacd.unlockFirst")}</p>
        </div>
      ) : gallery.length === 0 && !loading ? (
        <div className="panel info-box">
          <p>{t("hacd.empty")}</p>
          <p className="muted small-note">{t("hacd.emptyHint")}</p>
        </div>
      ) : (
        <div className="hacd-gallery-grid" aria-live="polite">
          {gallery.map((name) => (
            <div key={name} className="hacd-gallery-item">
              {!owned.includes(name) && (
                <p className="muted small-note hacd-gallery-lookup-badge">{t("hacd.lookupBadge")}</p>
              )}
              <HacdDiamondVisual name={name} size="lg" />
            </div>
          ))}
        </div>
      )}
    </section>
  );
}

import { useCallback, useEffect, useRef, useState } from "react";
import { api } from "../api";
import HacdDiamondVisual from "../components/HacdDiamondVisual";
import { formatInvokeError } from "../formatInvokeError";
import { useLocale } from "../locale";
import { isValidHacdName, normalizeHacdName } from "../utils/paymentAssets";

type Props = {
  locked: boolean;
  busy: boolean;
  ownedHint?: string[];
  onToast: (msg: string, kind: "success" | "info" | "error") => void;
  onGoPay?: () => void;
};

/** Mobile HACD gallery: owned diamonds as full metadata cards (Explorer-style). */
export default function HacdTab({ locked, busy, ownedHint, onToast, onGoPay }: Props) {
  const { t } = useLocale();
  const [owned, setOwned] = useState<string[]>(ownedHint ?? []);
  const [lookup, setLookup] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const onToastRef = useRef(onToast);
  onToastRef.current = onToast;

  useEffect(() => {
    if (ownedHint && ownedHint.length > 0) {
      setOwned(ownedHint);
    }
  }, [ownedHint]);

  const refresh = useCallback(
    async (opts?: { notify?: boolean }) => {
      if (locked) {
        setOwned([]);
        setError(t("hacd.unlockFirst"));
        return;
      }
      setLoading(true);
      setError("");
      try {
        setOwned(await api.listOwnedDiamonds());
      } catch (e) {
        const msg = formatInvokeError(e);
        setError(msg);
        if (opts?.notify) onToastRef.current(msg, "error");
      } finally {
        setLoading(false);
      }
    },
    [locked, t],
  );

  useEffect(() => {
    void refresh({ notify: false });
    // eslint-disable-next-line react-hooks/exhaustive-deps -- only re-run on lock change
  }, [locked]);

  const lookupName = normalizeHacdName(lookup);
  const showLookup = isValidHacdName(lookupName);
  const gallery = showLookup && !owned.includes(lookupName) ? [lookupName, ...owned] : owned;

  return (
    <div className="stack hacd-gallery-screen">
      <header className="card">
        <h1>{t("hacd.title")}</h1>
        <p className="muted">{t("hacd.subtitle")}</p>
        <div className="row-btns">
          <button
            type="button"
            disabled={busy || loading || locked}
            onClick={() => void refresh({ notify: true })}
          >
            {loading ? t("hacd.refreshing") : t("hacd.refresh")}
          </button>
          {onGoPay && (
            <button type="button" className="primary" disabled={busy || locked} onClick={onGoPay}>
              {t("hacd.send")}
            </button>
          )}
        </div>
      </header>

      <div className="card">
        <label className="label">{t("hacd.lookup")}</label>
        <input
          value={lookup}
          onChange={(e) => setLookup(e.target.value.toUpperCase())}
          placeholder="e.g. AVZXZS"
          maxLength={6}
          autoComplete="off"
          spellCheck={false}
        />
        <p className="muted small">{t("hacd.lookupHint")}</p>
      </div>

      {error && <p className="form-error">{error}</p>}

      {locked ? (
        <div className="card">
          <p>{t("hacd.unlockFirst")}</p>
        </div>
      ) : gallery.length === 0 && !loading ? (
        <div className="card">
          <p>{t("hacd.empty")}</p>
          <p className="muted small">{t("hacd.emptyHint")}</p>
        </div>
      ) : (
        <div className="hacd-gallery-grid" aria-live="polite">
          {gallery.map((name) => (
            <div key={name} className="hacd-gallery-item">
              {!owned.includes(name) && (
                <p className="muted small hacd-gallery-lookup-badge">{t("hacd.lookupBadge")}</p>
              )}
              <HacdDiamondVisual name={name} size="lg" />
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

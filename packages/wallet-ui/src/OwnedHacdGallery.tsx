import { useCallback, useEffect, useRef, useState } from "react";

import {
  HacdDiamondVisual,
  type HacdMetadataCopy,
  type OpenExternal,
  type QueryHacdDiamond,
} from "./HacdDiamondVisual";
import { isValidHacdName } from "./paymentAssets";

export type OwnedHacdGalleryCopy = {
  title: string;
  subtitle: string;
  refresh: string;
  refreshing: string;
  loading: string;
  empty: string;
  emptyHint: string;
  unlockFirst: string;
  loadError: string;
  showMore: (remaining: number) => string;
};

export function translatedOwnedHacdGalleryCopy(
  t: (key: string, params?: Readonly<Record<string, string | number>>) => string,
): OwnedHacdGalleryCopy {
  return {
    title: t("hacd.title"),
    subtitle: t("hacd.subtitle"),
    refresh: t("hacd.refresh"),
    refreshing: t("hacd.refreshing"),
    loading: t("hacd.loading"),
    empty: t("hacd.empty"),
    emptyHint: t("hacd.emptyHint"),
    unlockFirst: t("hacd.unlockFirst"),
    loadError: t("hacd.loadError"),
    showMore: (remaining) => t("hacd.showMore", { count: remaining }),
  };
}

type GalleryState =
  | { status: "idle"; names: string[] }
  | { status: "loading"; names: string[] }
  | { status: "ready"; names: string[] }
  | { status: "failed"; names: string[] };

export const OWNED_HACD_BATCH_SIZE = 12;

export function ownedHacdVisibleBatch(names: string[], visibleCount: number) {
  const requested = Number.isFinite(visibleCount)
    ? Math.max(0, Math.floor(visibleCount))
    : 0;
  const count = Math.min(names.length, requested);
  return {
    names: names.slice(0, count),
    remaining: names.length - count,
  };
}

export function normalizeOwnedHacdNames(input: string[]): string[] {
  return Array.from(
    new Set(
      input
        .map((name) => name.trim().toUpperCase())
        .filter((name): name is string => isValidHacdName(name)),
    ),
  );
}

export function OwnedHacdGallery({
  locked,
  busy,
  copy,
  metadataCopy,
  listOwned,
  queryDiamond,
  openExternal,
  onError,
}: {
  locked: boolean;
  busy: boolean;
  copy: OwnedHacdGalleryCopy;
  metadataCopy?: Partial<HacdMetadataCopy>;
  listOwned: () => Promise<string[]>;
  queryDiamond: QueryHacdDiamond;
  openExternal: OpenExternal;
  onError?: (cause: unknown) => void;
}) {
  const [state, setState] = useState<GalleryState>({ status: "idle", names: [] });
  const [visibleCount, setVisibleCount] = useState(OWNED_HACD_BATCH_SIZE);
  const generation = useRef(0);
  const onErrorRef = useRef(onError);
  onErrorRef.current = onError;

  const refresh = useCallback(
    async (notify: boolean) => {
      setVisibleCount(OWNED_HACD_BATCH_SIZE);
      if (locked) {
        generation.current += 1;
        setState({ status: "idle", names: [] });
        return;
      }
      const current = ++generation.current;
      setState((previous) => ({ status: "loading", names: previous.names }));
      try {
        const names = normalizeOwnedHacdNames(await listOwned());
        if (current === generation.current) setState({ status: "ready", names });
      } catch (cause) {
        if (current !== generation.current) return;
        setState((previous) => ({ status: "failed", names: previous.names }));
        if (notify) onErrorRef.current?.(cause);
      }
    },
    [listOwned, locked],
  );

  useEffect(() => {
    void refresh(false);
    return () => {
      generation.current += 1;
    };
  }, [refresh]);

  const initialLoading = state.status === "loading" && state.names.length === 0;
  const visible = ownedHacdVisibleBatch(state.names, visibleCount);

  return (
    <section className="hacd-owned-gallery" aria-busy={state.status === "loading"}>
      <header className="hacd-owned-gallery-head">
        <div>
          <h1>{copy.title}</h1>
          <p>{copy.subtitle}</p>
        </div>
        <button
          type="button"
          disabled={busy || locked || state.status === "loading"}
          onClick={() => void refresh(true)}
        >
          {state.status === "loading" ? copy.refreshing : copy.refresh}
        </button>
      </header>

      {locked ? (
        <div className="hacd-owned-message">{copy.unlockFirst}</div>
      ) : state.status === "failed" && state.names.length === 0 ? (
        <div className="hacd-owned-message hacd-owned-message-error">{copy.loadError}</div>
      ) : initialLoading ? (
        <div className="hacd-owned-message">{copy.loading}</div>
      ) : state.names.length === 0 ? (
        <div className="hacd-owned-message">
          <strong>{copy.empty}</strong>
          <span>{copy.emptyHint}</span>
        </div>
      ) : (
        <>
          {state.status === "failed" ? (
            <div className="hacd-owned-message hacd-owned-message-error">{copy.loadError}</div>
          ) : null}
          <div className="hacd-gallery-grid" aria-live="polite">
            {visible.names.map((name) => (
              <div key={name} className="hacd-gallery-item">
                <HacdDiamondVisual
                  name={name}
                  queryDiamond={queryDiamond}
                  openExternal={openExternal}
                  copy={metadataCopy}
                />
              </div>
            ))}
          </div>
          {visible.remaining > 0 ? (
            <button
              type="button"
              className="hacd-show-more"
              onClick={() =>
                setVisibleCount((current) =>
                  Math.min(state.names.length, current + OWNED_HACD_BATCH_SIZE),
                )
              }
            >
              {copy.showMore(visible.remaining)}
            </button>
          ) : null}
        </>
      )}
    </section>
  );
}

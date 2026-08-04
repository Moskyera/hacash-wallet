import { useEffect, useState } from "react";
import "./nativeAssets.css";
import { useLocale } from "./i18n";
import {
  isCanonicalNativeAssetList,
  type NativeAssetBalance,
  type NativeAssetMetadata,
} from "./nativeAssets";

type Props = {
  assets: readonly NativeAssetBalance[];
  hidden?: boolean;
  className?: string;
  loadMetadata?: (serial: string) => Promise<NativeAssetMetadata>;
};

export type NativeAssetDisclosure =
  | { status: "hidden" }
  | {
    status: "visible";
    assets: readonly NativeAssetBalance[];
    valid: boolean;
  };

export function nativeAssetDisclosure(
  assets: readonly NativeAssetBalance[],
  hidden: boolean,
): NativeAssetDisclosure {
  if (hidden) return { status: "hidden" };
  return {
    status: "visible",
    assets,
    valid: isCanonicalNativeAssetList(assets),
  };
}

export function NativeAssetBalances({
  assets,
  hidden = false,
  className = "",
  loadMetadata,
}: Props) {
  const { t } = useLocale();
  const [metadata, setMetadata] = useState<Record<string, NativeAssetMetadata>>({});

  useEffect(() => {
    if (hidden || !loadMetadata || !isCanonicalNativeAssetList(assets)) {
      setMetadata({});
      return;
    }
    let cancelled = false;
    void Promise.all(
      assets.map(async (asset) => {
        try {
          const item = await loadMetadata(asset.serial);
          return item.serial === asset.serial ? item : null;
        } catch {
          return null;
        }
      }),
    ).then((items) => {
      if (cancelled) return;
      const next: Record<string, NativeAssetMetadata> = {};
      for (const item of items) {
        if (item) next[item.serial] = item;
      }
      setMetadata(next);
    });
    return () => {
      cancelled = true;
    };
  }, [assets, hidden, loadMetadata]);

  if (assets.length === 0) return null;

  const disclosure = nativeAssetDisclosure(assets, hidden);
  if (disclosure.status === "hidden") {
    return (
      <section className={`native-assets-readonly ${className}`.trim()}>
        <header>
          <strong>{t("nativeAssets.title")}</strong>
          <span>•••</span>
        </header>
        <p>{t("nativeAssets.hidden")}</p>
      </section>
    );
  }

  return (
    <section className={`native-assets-readonly ${className}`.trim()}>
      <header>
        <strong>{t("nativeAssets.title")}</strong>
        <span>{disclosure.valid ? disclosure.assets.length : t("common.notAvailable")}</span>
      </header>
      <p>{t("nativeAssets.help")}</p>
      {disclosure.valid ? (
        <ul>
          {disclosure.assets.map((asset) => {
            const item = metadata[asset.serial];
            return (
              <li key={asset.serial}>
                <span>
                  <strong>{item?.ticket ?? `Asset #${asset.serial}`}</strong>
                  {item ? <small>{item.name} · Asset #{asset.serial}</small> : null}
                </span>
                <strong>{asset.amount}</strong>
              </li>
            );
          })}
        </ul>
      ) : (
        <p className="native-assets-warning" role="alert">
          {t("nativeAssets.invalid")}
        </p>
      )}
      {Object.keys(metadata).length > 0 ? (
        <p className="muted small-note">Metadata is display-only. Asset serials are canonical.</p>
      ) : null}
    </section>
  );
}
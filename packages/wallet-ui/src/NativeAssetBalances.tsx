import "./nativeAssets.css";
import { useLocale } from "./i18n";
import {
  isCanonicalNativeAssetList,
  type NativeAssetBalance,
} from "./nativeAssets";

type Props = {
  assets: readonly NativeAssetBalance[];
  hidden?: boolean;
  className?: string;
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
}: Props) {
  const { t } = useLocale();
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
          {disclosure.assets.map((asset) => (
            <li key={asset.serial}>
              <span>
                {t("nativeAssets.asset", { serial: asset.serial })}
              </span>
              <strong>{asset.amount}</strong>
            </li>
          ))}
        </ul>
      ) : (
        <p className="native-assets-warning" role="alert">
          {t("nativeAssets.invalid")}
        </p>
      )}
    </section>
  );
}

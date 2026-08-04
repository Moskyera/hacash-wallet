import "./assetMark.css";

import btcOnHacashUrl from "./assets/btc-on-hacash.svg";
import hacUrl from "./assets/hac.svg";
import hacdUrl from "./assets/hacd.svg";

export type AssetMarkKind = "hac" | "hacd" | "btc" | "hip20";

type Props = {
  kind: AssetMarkKind;
  size?: "sm" | "md" | "lg";
  className?: string;
};

const ASSET_LABELS: Record<AssetMarkKind, string> = {
  hac: "HAC",
  hacd: "HACD",
  btc: "BTC on Hacash",
  hip20: "HIP-20",
};

const ASSET_URLS: Partial<Record<AssetMarkKind, string>> = {
  hac: hacUrl,
  hacd: hacdUrl,
  btc: btcOnHacashUrl,
};

export function AssetMark({ kind, size = "md", className = "" }: Props) {
  const classes = `asset-mark asset-mark-${size} asset-mark-${kind} ${className}`.trim();
  if (kind === "hip20") {
    return (
      <span className={classes} role="img" aria-label={ASSET_LABELS[kind]}>
        <span>20</span>
      </span>
    );
  }

  return (
    <img
      src={ASSET_URLS[kind]}
      alt={ASSET_LABELS[kind]}
      className={classes}
      draggable={false}
    />
  );
}
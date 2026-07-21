export type NativeAssetBalance = {
  serial: string;
  amount: string;
};

export type AssetSummary = {
  hac_mei: number;
  hacd_count: number;
  hacd_names: string[];
  btc_wallet_satoshi: number;
  btc_channel_satoshi: number;
  native_assets: NativeAssetBalance[];
};

const U64_MAX_DECIMAL = "18446744073709551615";
const NATIVE_ASSET_LIMIT = 20;

function isCanonicalPositiveU64(value: string): boolean {
  if (!/^[1-9][0-9]*$/.test(value)) return false;
  if (value.length !== U64_MAX_DECIMAL.length) return value.length < U64_MAX_DECIMAL.length;
  return value <= U64_MAX_DECIMAL;
}

function compareCanonicalDecimals(left: string, right: string): number {
  if (left.length !== right.length) return left.length - right.length;
  return left < right ? -1 : left > right ? 1 : 0;
}

export function isCanonicalNativeAssetList(
  assets: readonly NativeAssetBalance[],
): boolean {
  if (assets.length > NATIVE_ASSET_LIMIT) return false;
  let previousSerial: string | null = null;
  for (const asset of assets) {
    if (!isCanonicalPositiveU64(asset.serial) || !isCanonicalPositiveU64(asset.amount)) {
      return false;
    }
    if (
      previousSerial !== null
      && compareCanonicalDecimals(previousSerial, asset.serial) >= 0
    ) {
      return false;
    }
    previousSerial = asset.serial;
  }
  return true;
}

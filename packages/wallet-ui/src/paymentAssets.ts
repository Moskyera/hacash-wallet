export * from "./nativeAssets";
export * from "./NativeAssetBalances";

export type PaymentAsset = "HAC" | "HACD" | "BTC";

export const PAYMENT_ASSETS: { id: PaymentAsset; label: string; symbol: string }[] = [
  { id: "HAC", label: "Hacash", symbol: "HAC" },
  { id: "HACD", label: "Diamond", symbol: "HACD" },
  { id: "BTC", label: "On Hacash", symbol: "BTC" },
];

const HACD_ALPHABET_RE = /[^WTYUIAHXVMEKBSZN]/g;

export function normalizeHacdName(raw: string): string {
  return raw.trim().toUpperCase().replace(HACD_ALPHABET_RE, "").slice(0, 6);
}

export function isValidHacdName(name: string): boolean {
  return /^[WTYUIAHXVMEKBSZN]{4,6}$/.test(name.trim().toUpperCase());
}

const KEY = "hacash_wallet_hacd_name";

export function loadWalletHacdName(): string {
  try {
    return localStorage.getItem(KEY) ?? "";
  } catch {
    return "";
  }
}

export function saveWalletHacdName(name: string): void {
  localStorage.setItem(KEY, name.trim().toUpperCase());
}
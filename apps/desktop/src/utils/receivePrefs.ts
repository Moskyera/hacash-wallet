const HACD_KEY = "hacash_wallet_hacd_name";

export function loadWalletHacdName(): string {
  try {
    return localStorage.getItem(HACD_KEY) ?? "";
  } catch {
    return "";
  }
}

export function saveWalletHacdName(name: string): void {
  localStorage.setItem(HACD_KEY, name.trim().toUpperCase());
}
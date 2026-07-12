const HACD_KEY = "hacash_wallet_hacd_name";
const BTC_KEY = "hacash_wallet_btc_receive";

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

export function loadBtcReceiveAddress(): string {
  try {
    return localStorage.getItem(BTC_KEY) ?? "";
  } catch {
    return "";
  }
}

export function saveBtcReceiveAddress(addr: string): void {
  localStorage.setItem(BTC_KEY, addr.trim());
}
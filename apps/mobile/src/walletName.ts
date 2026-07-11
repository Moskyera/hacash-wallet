const STORAGE_KEY = "hacash_wallet_name_v1";

function readMap(): Record<string, string> {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return {};
    const parsed = JSON.parse(raw) as Record<string, string>;
    return parsed && typeof parsed === "object" ? parsed : {};
  } catch {
    return {};
  }
}

export function loadWalletName(address: string | null | undefined): string {
  if (!address) return "";
  return readMap()[address]?.trim() ?? "";
}

export function saveWalletName(address: string, name: string): void {
  const map = readMap();
  const trimmed = name.trim();
  if (trimmed) {
    map[address] = trimmed;
  } else {
    delete map[address];
  }
  localStorage.setItem(STORAGE_KEY, JSON.stringify(map));
}

export function clearAllWalletNames(): void {
  localStorage.removeItem(STORAGE_KEY);
}

export function walletDisplayName(
  address: string | null | undefined,
  customName?: string,
): string {
  const name = (customName ?? loadWalletName(address)).trim();
  if (name) return name;
  return "My Wallet";
}
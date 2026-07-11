export type PaymentAsset = "HAC" | "HACD" | "BTC";

export const PAYMENT_ASSETS: { id: PaymentAsset; label: string; symbol: string }[] = [
  { id: "HAC", label: "Hacash", symbol: "HAC" },
  { id: "HACD", label: "Diamond", symbol: "HACD" },
  { id: "BTC", label: "Bitcoin", symbol: "BTC" },
];

export type HacdArchetype = "Momentum" | "Contrarian" | "Arbitrageur" | "Sentinel" | "Unknown";

const ARCHETYPE_MAP: Record<string, HacdArchetype> = {
  W: "Momentum",
  T: "Momentum",
  Y: "Momentum",
  U: "Momentum",
  I: "Contrarian",
  A: "Contrarian",
  H: "Contrarian",
  X: "Contrarian",
  V: "Arbitrageur",
  M: "Arbitrageur",
  E: "Arbitrageur",
  K: "Arbitrageur",
  B: "Sentinel",
  S: "Sentinel",
  Z: "Sentinel",
  N: "Sentinel",
};

const ARCHETYPE_COLORS: Record<HacdArchetype, string> = {
  Momentum: "#f5a623",
  Contrarian: "#7c5cff",
  Arbitrageur: "#3dd6c6",
  Sentinel: "#ff6b6b",
  Unknown: "#888888",
};

export function normalizeHacdName(raw: string): string {
  return raw.trim().toUpperCase().replace(/[^A-Z]/g, "").slice(0, 6);
}

export function hacdArchetype(name: string): HacdArchetype {
  const letter = normalizeHacdName(name).charAt(0);
  return ARCHETYPE_MAP[letter] ?? "Unknown";
}

export function hacdColor(name: string): string {
  return ARCHETYPE_COLORS[hacdArchetype(name)];
}

export function isValidHacdName(name: string): boolean {
  const n = normalizeHacdName(name);
  return n.length >= 4 && n.length <= 6;
}

export function isValidBtcAddress(addr: string): boolean {
  const a = addr.trim();
  return /^(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,62}$/.test(a);
}
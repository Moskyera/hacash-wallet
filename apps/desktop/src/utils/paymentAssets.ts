export type PaymentAsset = "HAC" | "HACD" | "BTC";

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

export function normalizeHacdName(raw: string): string {
  return raw.trim().toUpperCase().replace(/[^A-Z]/g, "").slice(0, 6);
}

export function hacdArchetype(name: string): HacdArchetype {
  const letter = normalizeHacdName(name).charAt(0);
  return ARCHETYPE_MAP[letter] ?? "Unknown";
}

export function isValidHacdName(name: string): boolean {
  const n = normalizeHacdName(name);
  return n.length >= 4 && n.length <= 6;
}
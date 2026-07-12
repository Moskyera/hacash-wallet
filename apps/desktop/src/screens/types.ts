export type Screen =
  | "welcome"
  | "unlock"
  | "home"
  | "send"
  | "fastpay"
  | "receive"
  | "history"
  | "advanced"
  | "settings"
  | "security"
  | "privacy"
  | "airgap"
  | "quantum";

export type WelcomeTab = "create" | "import" | "watch";

export const NAV_ITEMS: { id: Screen; label: string }[] = [
  { id: "home", label: "Home" },
  { id: "send", label: "Send" },
  { id: "fastpay", label: "Fast Pay" },
  { id: "quantum", label: "Quantum" },
  { id: "receive", label: "Receive" },
  { id: "history", label: "History" },
  { id: "advanced", label: "Advanced" },
  { id: "settings", label: "Settings" },
  { id: "security", label: "Security" },
  { id: "privacy", label: "Privacy" },
  { id: "airgap", label: "Air-gap QR" },
];

export const ISTANBUL_HEIGHT = 765_432;

export function formatCountdown(secs: number | null | undefined): string {
  if (secs == null) return "n/a";
  const m = Math.floor(secs / 60);
  const s = secs % 60;
  return m > 0 ? `${m}m ${s}s` : `${s}s`;
}

export function isValidImportSeed(seed: string): boolean {
  const trimmed = seed.trim();
  if (!trimmed) return false;
  if (/^[0-9a-fA-F]{64}$/.test(trimmed)) return true;
  return trimmed.length >= 8;
}
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

export type WelcomeTab = "create" | "import" | "backup" | "watch";

export type NavItem = {
  id: Screen;
  label: string;
  mark: string;
};

export const NAV_GROUPS: { label: string; items: NavItem[] }[] = [
  {
    label: "Wallet",
    items: [
      { id: "home", label: "Home", mark: "⌂" },
      { id: "send", label: "Send assets", mark: "↑" },
      { id: "receive", label: "Receive", mark: "↓" },
      { id: "history", label: "History", mark: "≡" },
      { id: "fastpay", label: "Fast Pay", mark: "⚡" },
    ],
  },
  {
    label: "Tools",
    items: [
      { id: "quantum", label: "Quantum", mark: "◇" },
      { id: "airgap", label: "Air-gap QR", mark: "▣" },
    ],
  },
  {
    label: "Control",
    items: [
      { id: "security", label: "Security", mark: "⛨" },
      { id: "privacy", label: "Privacy", mark: "◐" },
      { id: "settings", label: "Settings", mark: "⚙" },
      { id: "advanced", label: "Advanced", mark: "⋯" },
    ],
  },
];

export const ISTANBUL_HEIGHT = 765_432;

export function formatCountdown(secs: number | null | undefined): string {
  if (secs == null) return "n/a";
  const minutes = Math.floor(secs / 60);
  const seconds = secs % 60;
  return minutes > 0 ? `${minutes}m ${seconds}s` : `${seconds}s`;
}

export function isValidImportSeed(seed: string): boolean {
  const trimmed = seed.trim();
  if (!trimmed) return false;
  if (/^[0-9a-fA-F]{64}$/.test(trimmed)) return true;
  return trimmed.length >= 8;
}
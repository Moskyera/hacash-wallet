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
  mark: string;
};

export const NAV_GROUPS: { id: "wallet" | "tools" | "control"; items: NavItem[] }[] = [
  {
    id: "wallet",
    items: [
      { id: "home", mark: "⌂" },
      { id: "send", mark: "↑" },
      { id: "receive", mark: "↓" },
      { id: "history", mark: "≡" },
      { id: "fastpay", mark: "⚡" },
    ],
  },
  {
    id: "tools",
    items: [
      { id: "quantum", mark: "◇" },
      { id: "airgap", mark: "▣" },
    ],
  },
  {
    id: "control",
    items: [
      { id: "security", mark: "⛨" },
      { id: "privacy", mark: "◐" },
      { id: "settings", mark: "⚙" },
      { id: "advanced", mark: "⋯" },
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
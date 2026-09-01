export type Screen =
  | "welcome"
  | "unlock"
  | "home"
  | "workspace"
  | "send"
  | "fastpay"
  | "receive"
  | "history"
  | "advanced"
  | "settings"
  | "security"
  | "privacy"
  | "airgap"
  | "hacd"
  | "messages"
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
      { id: "workspace", mark: "◫" },
      { id: "send", mark: "↑" },
      { id: "receive", mark: "↓" },
      { id: "hacd", mark: "◆" },
      { id: "history", mark: "≡" },
      { id: "fastpay", mark: "⚡" },
    ],
  },
  {
    id: "tools",
    items: [
      { id: "messages", mark: "✉" },
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

/// A real Hacash secret key. It is the only thing importable: this wallet has no
/// path that derives a key from text.
export function isSecretHexSeed(seed: string): boolean {
  return /^[0-9a-fA-F]{64}$/.test(compactSeed(seed));
}

/** Hex digit count with all whitespace ignored, so a key pasted across lines counts. */
export function compactSeed(seed: string): string {
  return seed.replace(/\s+/g, "");
}

/**
 * An all-hex input that is not exactly 64 characters is a mistyped or truncated
 * private key. Reporting the character count tells the user what to fix, which a
 * generic "invalid key" message does not.
 */
export function looksLikeMistypedKey(seed: string): boolean {
  const compact = compactSeed(seed);
  return compact.length >= 32 && /^[0-9a-fA-F]+$/.test(compact) && compact.length !== 64;
}

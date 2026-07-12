export type FastPayState = "ready" | "needs_channel" | "hub_unreachable" | "no_provider";

export function parseFastPayState(raw?: string | null): FastPayState {
  if (raw === "ready" || raw === "needs_channel" || raw === "hub_unreachable") {
    return raw;
  }
  return "no_provider";
}

/** One line for Home banner and Fast Pay screen. */
export function fastPayStatusLine(state?: string | null, depositMei = 10): string {
  switch (parseFastPayState(state)) {
    case "ready":
      return "Sends settle in seconds with a low fee.";
    case "needs_channel":
      return `Deposit ${depositMei} HAC once to turn on. Blockchain pays still work.`;
    case "hub_unreachable":
      return "Payment network offline. Sends use the blockchain for now.";
    default:
      return "Not set up yet. Sends use the blockchain.";
  }
}

/** Short title above the status line. */
export function fastPayStatusTitle(state?: string | null): string {
  switch (parseFastPayState(state)) {
    case "ready":
      return "Fast Pay is on";
    case "needs_channel":
      return "Setup needed";
    case "hub_unreachable":
      return "Network offline";
    default:
      return "Fast Pay is off";
  }
}

/** More menu badge (on / off / setup). */
export function fastPayMenuBadge(state?: string | null): string {
  switch (parseFastPayState(state)) {
    case "ready":
      return "on";
    case "needs_channel":
      return "setup";
    case "hub_unreachable":
      return "offline";
    default:
      return "off";
  }
}

export function fastPayHowItWorks(): string {
  return "Deposit HAC once. After that, sends to other users settle in seconds instead of waiting for a block.";
}
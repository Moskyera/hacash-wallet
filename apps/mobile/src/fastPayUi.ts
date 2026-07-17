import type { L1FeeSpeed } from "./api";

export const L1_FEE_SPEEDS: L1FeeSpeed[] = ["slow", "normal", "fast", "ultra"];

export function l1FeeSpeedLabel(speed: L1FeeSpeed): string {
  switch (speed) {
    case "slow":
      return "Slow";
    case "fast":
      return "Fast";
    case "ultra":
      return "Ultra";
    default:
      return "Normal";
  }
}

export function l1FeeSpeedDetail(speed: L1FeeSpeed): string {
  switch (speed) {
    case "slow":
      return "Network minimum fee.";
    case "fast":
      return "5× network average. higher mempool priority.";
    case "ultra":
      return "15× network average. highest priority.";
    default:
      return "1.2× network average. balanced.";
  }
}

export const DEFAULT_SERVICE_FEE_RATE = 0.003;

export function formatServiceFeeRate(rate: number | null | undefined): string {
  if (rate == null) return "0.3%";
  return `${(rate * 100).toFixed(1).replace(/\.0$/, "")}%`;
}

export type FastPayState =
  | "ready"
  | "needs_channel"
  | "hub_unreachable"
  | "checking"
  | "provider_incompatible"
  | "no_provider";

export function parseFastPayState(raw?: string | null): FastPayState {
  if (
    raw === "ready" ||
    raw === "needs_channel" ||
    raw === "hub_unreachable" ||
    raw === "checking" ||
    raw === "provider_incompatible"
  ) {
    return raw;
  }
  return "no_provider";
}

/** One line for Home banner and Fast Pay screen. */
export function fastPayStatusLine(state?: string | null, depositMei = 10): string {
  switch (parseFastPayState(state)) {
    case "ready":
      return "Sends settle in seconds with no Fast Pay fee.";
    case "needs_channel":
      return `Deposit ${depositMei} HAC once to turn on. Blockchain pays still work.`;
    case "hub_unreachable":
      return "Payment network offline. Sends use the blockchain for now.";
    case "checking":
      return "Checking settlement, routing and fee capabilities. Sends stay on-chain.";
    case "provider_incompatible":
      return "Provider cannot create safe, fee-free routed settlements. Sends stay on-chain.";
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
    case "checking":
      return "Checking provider";
    case "provider_incompatible":
      return "Provider unavailable";
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
    case "checking":
      return "checking";
    case "provider_incompatible":
      return "unsupported";
    default:
      return "off";
  }
}

export function fastPayHowItWorks(): string {
  return "Deposit HAC once. After that, sends to other users settle in seconds instead of waiting for a block.";
}

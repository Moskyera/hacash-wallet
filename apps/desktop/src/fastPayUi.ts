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
      return "5× network average — higher mempool priority.";
    case "ultra":
      return "15× network average — highest priority.";
    default:
      return "1.2× network average — balanced.";
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
  | "no_provider";

export type FastPayStatus = {
  state: FastPayState;
  message: string;
  provider_name: string | null;
  hub_url: string | null;
  can_enable: boolean;
  default_deposit_mei: number;
};

export function fastPayChipLabel(state: FastPayState): string {
  switch (state) {
    case "ready":
      return "Fast Pay ON";
    case "needs_channel":
      return "Fast Pay setup";
    case "hub_unreachable":
      return "Fast Pay offline";
    default:
      return "Fast Pay OFF";
  }
}

export function fastPayStatusTitle(state: FastPayState): string {
  switch (state) {
    case "ready":
      return "Fast Pay is ON";
    case "needs_channel":
      return "Fast Pay needs setup";
    case "hub_unreachable":
      return "Fast Pay provider offline";
    default:
      return "Fast Pay is OFF";
  }
}

export function fastPayStatusHeadline(state: FastPayState): string {
  switch (state) {
    case "ready":
      return "Your sends from the Send tab will use instant Fast Pay (low fee, seconds).";
    case "needs_channel":
      return "A provider was found. Complete one-time setup to turn Fast Pay ON.";
    case "hub_unreachable":
      return "Your provider is not reachable. Sends use standard on-chain until it is back.";
    default:
      return "No Fast Pay provider online. Sends from the Send tab use standard on-chain.";
  }
}

export function fastPayNavHint(state: FastPayState): string {
  return state === "ready" ? "ON" : "OFF";
}

export function railBadgeClass(rail: "L2Fast" | "L1OnChain"): string {
  return rail === "L2Fast" ? "rail-badge rail-instant" : "rail-badge rail-standard";
}

export function sendSuccessMessage(rail: string, summary: string): string {
  if (rail === "L2Fast") {
    return `Sent instantly via Fast Pay. ${summary}`;
  }
  return `Sent on-chain. ${summary}`;
}
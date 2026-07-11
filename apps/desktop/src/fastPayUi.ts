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
      return "Fast Pay — setup";
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
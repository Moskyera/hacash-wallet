import type { AgentConnectorStatus, MobileCompanionStatus } from "./api";

export function connectorStatusForWallet(
  status: AgentConnectorStatus,
  walletId: string,
): AgentConnectorStatus | null {
  return status.walletId !== null && status.walletId !== walletId ? null : status;
}

export function companionStatusBelongsToWallet(
  status: MobileCompanionStatus | null,
  walletId: string,
): boolean {
  return Boolean(status?.enabled && status.walletId === walletId);
}

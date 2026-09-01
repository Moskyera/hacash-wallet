import type { PaymentOperation } from "./api";

export type BroadcastReconciliationView = {
  heading: string;
  summary: string;
  transactionId: string;
  explanation: string;
  action: string;
};

export function broadcastReconciliationView(
  operation: PaymentOperation | null,
  formatUnits: (units: string) => string,
): BroadcastReconciliationView | null {
  if (operation?.status !== "reconciliation_required" || !operation.tx_hash) {
    return null;
  }
  return {
    heading: "Confirm the network outcome",
    summary: `${formatUnits(operation.amount_units)} to ${operation.recipient}`,
    transactionId: operation.tx_hash,
    explanation:
      "The phone recorded that the broadcast outcome was uncertain. HPAY will check this exact transaction id on the verified node. It will not send or rebroadcast anything.",
    action: "Check verified node",
  };
}

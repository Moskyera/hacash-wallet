import { describe, expect, it } from "vitest";

import type { PaymentOperation } from "./api";
import { broadcastReconciliationView } from "./broadcastReconciliation";

const operation: PaymentOperation = {
  operation_id: "op-reconcile",
  agent_wallet_id: "wallet-agent",
  agent_id: "agent-one",
  idempotency_key: "request-one",
  request_commitment: "a".repeat(64),
  asset: "HAC",
  amount_units: "125000000",
  recipient: "1Recipient",
  reason: "compute",
  status: "reconciliation_required",
  approval_mode: "desktop_manual",
  network_fee_units: "1000",
  wallet_fee_units: "0",
  total_debit_units: "125001000",
  reserved_units: "125001000",
  transaction_commitment: "b".repeat(64),
  tx_hash: "c".repeat(64),
  created_at: 10,
  expires_at: 20,
  final_result: "reconciliation_required",
};

describe("broadcastReconciliationView", () => {
  it("offers an exact-hash node check without claiming the money moved", () => {
    const view = broadcastReconciliationView(operation, (units) => `${units} units`);
    expect(view?.transactionId).toBe(operation.tx_hash);
    expect(view?.explanation).toContain("will not send or rebroadcast anything");
    expect(view?.explanation.toLowerCase()).not.toContain("money has left");
  });

  it("fails closed for every state that is not waiting for reconciliation", () => {
    expect(
      broadcastReconciliationView({ ...operation, status: "broadcast_uncertain" }, String),
    ).toBeNull();
    expect(broadcastReconciliationView({ ...operation, tx_hash: null }, String)).toBeNull();
    expect(broadcastReconciliationView(null, String)).toBeNull();
  });
});

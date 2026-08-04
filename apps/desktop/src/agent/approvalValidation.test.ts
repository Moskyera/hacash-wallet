import { describe, expect, it } from "vitest";
import type { ApprovalCommitment } from "./api";
import { approvalIsExactAndFeeFree } from "./AgentAdminPages";

function approval(
  override: Partial<ApprovalCommitment> = {},
): ApprovalCommitment {
  return {
    approval_version: "2",
    approval_id: "approval_1",
    operation_id: "operation_1",
    agent_wallet_id: "agent_wallet_1",
    agent_id: "agent_1",
    desktop_device_id: "desktop_1",
    amount_units: "1000000",
    recipient: "1Recipient",
    fee_units: "1000",
    wallet_fee_units: "0",
    total_debit_units: "1001000",
    transaction_commitment: "ab".repeat(32),
    policy_epoch: "1",
    challenge_nonce: "cd".repeat(16),
    issued_at: "100",
    expires_at: "200",
    ...override,
  };
}

describe("desktop exact Agent Wallet approval review", () => {
  it("accepts the canonical fee-free decimal-string commitment", () => {
    expect(approvalIsExactAndFeeFree(approval())).toBe(true);
  });

  it.each([
    ["amount_units", "+1000000"],
    ["fee_units", " 1000"],
    ["wallet_fee_units", "0x0"],
    ["total_debit_units", "01"],
    ["approval_version", "02"],
    ["policy_epoch", "0"],
    ["issued_at", "1e2"],
    ["expires_at", "0xC8"],
  ] satisfies Array<[keyof ApprovalCommitment, string]>)(
    "fails closed for non-canonical %s",
    (field, value) => {
      expect(
        approvalIsExactAndFeeFree(approval({ [field]: value })),
      ).toBe(false);
    },
  );
});

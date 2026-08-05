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

const BINDING = {
  network_id: "local_pilot_v1",
  chain_id: 7,
  genesis_identifier: "ab".repeat(32),
  node_profile_id: "hpay-local-pilot-chain-v1",
  transaction_format_version: 2,
};

/** What a Testnet Pilot build actually issues: version 3 plus its binding. */
function pilotApproval(
  override: Partial<ApprovalCommitment> = {},
): ApprovalCommitment {
  return approval({
    approval_version: "3",
    network_binding: BINDING,
    ...override,
  });
}

describe("desktop exact Agent Wallet approval review", () => {
  it("accepts the canonical fee-free decimal-string commitment", () => {
    expect(approvalIsExactAndFeeFree(approval())).toBe(true);
  });

  /**
   * THE VERSION THE OWNER WILL ACTUALLY BE HANDED.
   *
   * `create_payment_intent` issues approval_version 3 under
   * `agent-wallet-testnet-pilot`, which is the only build where the Agent
   * Wallet screens are reachable. This predicate admitted "2" alone, so with
   * the Approve control restored every real pilot approval would have been
   * reported to the owner as malformed and the button would never have
   * enabled.
   */
  it("accepts the pilot commitment and its network binding", () => {
    expect(approvalIsExactAndFeeFree(pilotApproval())).toBe(true);
  });

  /**
   * The version and the binding are bound to each other, exactly as Rust binds
   * them: `ApprovalCommitment::validate` admits (2, none) and (3, binding) and
   * nothing else. Accepting a v3 without its binding would be accepting a
   * commitment the desktop cannot re-verify against the node it is talking to.
   */
  it.each([
    ["a pilot version with no binding", pilotApproval({ network_binding: null })],
    [
      "a pilot version with an undefined binding",
      pilotApproval({ network_binding: undefined }),
    ],
    ["a non-pilot version carrying a binding", approval({ network_binding: BINDING })],
    ["an unknown version", pilotApproval({ approval_version: "4" })],
    [
      "a binding with an empty network id",
      pilotApproval({ network_binding: { ...BINDING, network_id: "" } }),
    ],
    [
      "a binding with an empty genesis identifier",
      pilotApproval({ network_binding: { ...BINDING, genesis_identifier: "" } }),
    ],
    [
      "a binding with a non-integer chain id",
      pilotApproval({
        network_binding: { ...BINDING, chain_id: 7.5 },
      }),
    ],
  ] satisfies Array<[string, ApprovalCommitment]>)(
    "fails closed for %s",
    (_label, commitment) => {
      expect(approvalIsExactAndFeeFree(commitment)).toBe(false);
    },
  );

  it("still applies every exactness rule to a pilot commitment", () => {
    for (const [field, value] of [
      ["amount_units", "0"],
      ["fee_units", "999"],
      ["wallet_fee_units", "1"],
      ["total_debit_units", "1"],
    ] satisfies Array<[keyof ApprovalCommitment, string]>) {
      expect(approvalIsExactAndFeeFree(pilotApproval({ [field]: value }))).toBe(
        false,
      );
    }
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

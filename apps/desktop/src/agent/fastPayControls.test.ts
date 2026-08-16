import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

const panel = readFileSync(
  new URL("./AgentFastPayOperationsPanel.tsx", import.meta.url),
  "utf8",
);
const api = readFileSync(new URL("./api.ts", import.meta.url), "utf8");

describe("Agent Fast Pay owner controls", () => {
  it("keeps execution explicit and never offers an L1 fallback", () => {
    expect(panel).toContain("Execute approved Fast Pay");
    expect(panel).toContain("cannot fall back to L1");
    expect(panel).not.toContain("wallet_send_hac");
  });

  it("fails closed when any fee changes the exact debit", () => {
    expect(panel).toContain('operation.network_fee_units === "0"');
    expect(panel).toContain('operation.wallet_fee_units === "0"');
    expect(panel).toContain("operation.total_debit_units === operation.amount_units");
    expect(panel).toContain("Invalid fee contract");
  });

  it("separates read-only reconciliation from an exact signed retry", () => {
    expect(panel).toContain("Check exact Hub status");
    expect(panel).toContain("Prepare exact retry");
    expect(panel).toContain("Confirm exact retry");
    expect(panel).toContain("No new signature or identifier is created");
    expect(panel).toContain('operation.status === "exact_retry_ready"');
    expect(panel).not.toContain('operation.status === "recovery_required" && !confirmingRetry');
  });

  it("calls only the dedicated Agent Fast Pay commands", () => {
    expect(api).toContain('"agent_wallet_list_fast_pay_activity"');
    expect(api).toContain('"agent_wallet_execute_approved_fast_pay"');
    expect(api).toContain('"agent_wallet_reconcile_fast_pay"');
    expect(api).toContain('"agent_wallet_retry_fast_pay_exact"');
  });

  it("reloads authenticated state even when a network action fails", () => {
    expect(panel).toContain("} finally {");
    expect(panel).toContain("await load();");
    expect(panel).toContain("await onRefreshOverview();");
  });
});

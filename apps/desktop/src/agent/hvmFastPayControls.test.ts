import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

const panel = readFileSync(
  new URL("./AgentHvmOperationsPanel.tsx", import.meta.url),
  "utf8",
);
const api = readFileSync(new URL("./api.ts", import.meta.url), "utf8");
const desktopCommands = readFileSync(
  new URL("../../src-tauri/src/lib.rs", import.meta.url),
  "utf8",
);

describe("Agent HVM Fast Pay owner controls", () => {
  it("keeps mainnet owner actions locked", () => {
    expect(panel).toContain("HVM Fast Pay");
    expect(panel).toContain("Mainnet HVM owner actions are intentionally locked");
    expect(panel).toContain('networkMode === "mainnet"');
  });

  it("fails closed on any wallet or Hub fee", () => {
    expect(panel).toContain("operation.wallet_fee_zhu === 0");
    expect(panel).toContain("operation.hub_fee_zhu === 0");
    expect(panel).toContain("operation.total_debit_zhu === operation.amount_zhu");
    expect(panel).toContain("Invalid fee contract");
  });

  it("uses dedicated HVM commands and never generic send or signing", () => {
    expect(api).toContain('"agent_wallet_bind_hvm_channel"');
    expect(api).toContain('"agent_wallet_bind_hvm_registry"');
    expect(api).toContain('"agent_wallet_list_hvm_activity"');
    expect(api).toContain('"agent_wallet_execute_approved_hvm"');
    expect(api).toContain('"agent_wallet_reconcile_hvm"');
    expect(api).toContain('"agent_wallet_retry_hvm_exact"');
    expect(panel).not.toContain("wallet_send_hac");
    expect(panel).not.toContain("sign_arbitrary");
  });

  it("defaults new bindings to Registry V2 and keeps legacy explicit", () => {
    expect(panel).toContain('useState<HvmRail>("registry_v2")');
    expect(panel).toContain("if (isHvmRail(event.target.value))");
    expect(panel).toContain("agentWalletApi.bindHvmRegistry");
    expect(panel).toContain("agentWalletApi.bindHvmChannel");
    expect(panel).toContain("Registry V2 (recommended)");
    expect(panel).toContain("Legacy V1 (Local Pilot compatibility)");
  });

  it("does not expose first signing or exact resubmit while mainnet is locked", () => {
    expect(panel).toContain('networkMode === "testnet" && zeroFee && operation.status === "approved"');
    expect(panel).toContain('networkMode === "testnet" && operation.status === "exact_retry_ready"');
  });

  it("renders the authenticated Registry V2 binding separately", () => {
    expect(panel).toContain("registryBinding.recovery_bundle.binding.contract_address");
    expect(panel).toContain("registryBinding.recovery_bundle.binding.reuse_version");
    expect(panel).toContain("registryBinding.binding_commitment");
    expect(panel).toContain("channelBinding.recovery_bundle.binding.contract_address");
  });

  it("requires explicit confirmation before exact signed retry", () => {
    expect(panel).toContain("Prepare exact retry");
    expect(panel).toContain("Confirm exact retry");
    expect(panel).toContain("never creates a second signature");
    expect(panel).toContain('operation.status === "exact_retry_ready"');
  });

  it("reloads authenticated state after every network action", () => {
    expect(panel).toContain("} finally {");
    expect(panel).toContain("await load();");
    expect(panel).toContain("await onRefreshOverview();");
  });

  it("registers the owner commands only in the desktop shell", () => {
    expect(desktopCommands).toContain("agent_wallet_bind_hvm_channel");
    expect(desktopCommands).toContain("agent_wallet_execute_approved_hvm");
  });
});

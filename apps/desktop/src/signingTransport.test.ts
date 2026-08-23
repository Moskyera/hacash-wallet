import { describe, expect, it } from "vitest";
import { isLoopbackHost, mainnetSigningTransportIsEligible } from "@hacash/wallet-ui";

/**
 * This predicate exists only to SAY on screen what the core already enforces.
 * If it drifts from `validate_signing_node_url` in
 * crates/wallet-core/src/settings.rs it becomes a lie in one of two directions:
 * a screen that promises signing the core will refuse, or a screen that turns
 * away a configuration the core accepts. The second is the one that shipped:
 * the Agent create button required `startsWith("https://")` and so refused
 * http://127.0.0.1:8080, which is both what the operator doc prescribes and
 * what the core treats as safest.
 */
describe("mainnetSigningTransportIsEligible", () => {
  it("refuses the shipped default node on mainnet", () => {
    expect(mainnetSigningTransportIsEligible("http://nodeapi.hacash.org", "mainnet")).toBe(
      false,
    );
  });

  it("accepts HTTPS on mainnet", () => {
    expect(mainnetSigningTransportIsEligible("https://node.example.com", "mainnet")).toBe(
      true,
    );
  });

  it("accepts a node on this same machine over plain HTTP", () => {
    // Nothing leaves the machine, which is the whole reason the settings layer
    // treats this as safe. The safest configuration must not be the one turned
    // away.
    for (const url of [
      "http://127.0.0.1:8080",
      "http://localhost:8080",
      "http://127.5.6.7:8080",
      "http://[::1]:8080",
    ]) {
      expect(mainnetSigningTransportIsEligible(url, "mainnet")).toBe(true);
    }
  });

  it("refuses remote plaintext, including hosts that merely look local", () => {
    for (const url of [
      "http://hub.example.com",
      "http://127.0.0.1.evil.example.com",
      "http://192.168.1.10:8080",
      "http://10.0.0.4:8080",
    ]) {
      expect(mainnetSigningTransportIsEligible(url, "mainnet")).toBe(false);
    }
  });

  it("refuses a missing or unparseable node URL rather than defaulting open", () => {
    expect(mainnetSigningTransportIsEligible(null, "mainnet")).toBe(false);
    expect(mainnetSigningTransportIsEligible("", "mainnet")).toBe(false);
    expect(mainnetSigningTransportIsEligible("   ", "mainnet")).toBe(false);
    expect(mainnetSigningTransportIsEligible("not a url", "mainnet")).toBe(false);
    expect(mainnetSigningTransportIsEligible("ftp://node.example.com", "mainnet")).toBe(
      false,
    );
  });

  it("does not apply the transport rule off mainnet", () => {
    expect(mainnetSigningTransportIsEligible("http://nodeapi.hacash.org", "testnet")).toBe(
      true,
    );
  });

  it("treats the whole 127.0.0.0/8 block as loopback, like the core does", () => {
    expect(isLoopbackHost("127.0.0.1")).toBe(true);
    expect(isLoopbackHost("127.255.255.254")).toBe(true);
    expect(isLoopbackHost("128.0.0.1")).toBe(false);
    expect(isLoopbackHost("LOCALHOST")).toBe(true);
    expect(isLoopbackHost("999.0.0.1")).toBe(false);
  });
});

import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { depositHacToZhu, formatZhu } from "./AgentAdminPages";

/**
 * The registry screens count in the L1 chain's zhu, and this file is the only
 * thing that says so in a way that fails.
 *
 * Every money figure on the open, funding and exit panels goes through
 * `formatZhu`, and the deposit an owner types goes through `depositHacToZhu`.
 * Both previously used the Agent ledger's 1e-6 `HacUnits` scale against
 * amounts that arrive in the chain's 1e-8 zhu. Nothing failed, because
 * `depositHacToZhu` had no test at all and every test of the view functions
 * passed its own local copy of the formatter in as a parameter, so the copies
 * agreed with each other and none of them agreed with the chain.
 *
 * These tests therefore do two separate jobs. The first pins the conversion to
 * a number. The second reads the Rust that decides it, so the day somebody
 * changes the chain's unit the TypeScript fails here rather than silently
 * rendering a hundredfold error over an irreversible spend.
 */

const repoRoot = resolve(__dirname, "..", "..", "..", "..");
const readRepoFile = (relative: string) =>
  readFileSync(resolve(repoRoot, relative), "utf8");

describe("chain zhu is 1e-8 HAC, and the screen agrees with the chain", () => {
  it("renders one HAC from the chain's own anchor value", () => {
    // `parse_fin_balance_zhu("1:248") == 100_000_000` in l2-fast-pay-hub's
    // node.rs, and `1:248` is exactly one HAC.
    expect(formatZhu("100000000")).toBe("1 HAC");
  });

  it("renders the deposit the on-chain proof actually locked", () => {
    // exit_on_chain_tests.rs: `const DEPOSIT_ZHU: u64 = 5_000_000_000`, and the
    // owner's balance fell by roughly that plus fees. It is fifty HAC.
    expect(formatZhu("5000000000")).toBe("50 HAC");
  });

  it("renders the channel network fee ceiling as the hundredth of a HAC it is", () => {
    // l1_channel.rs: `MAX_CHANNEL_NETWORK_FEE_ZHU: u64 = 1_000_000`.
    expect(formatZhu("1000000")).toBe("0.01 HAC");
  });

  it("keeps eight decimal places, because a zhu is the smallest thing there is", () => {
    expect(formatZhu("1")).toBe("0.00000001 HAC");
    expect(formatZhu("123456789")).toBe("1.23456789 HAC");
    expect(formatZhu("0")).toBe("0 HAC");
  });

  it("refuses what it cannot render exactly instead of guessing", () => {
    expect(formatZhu("not a number")).toBe("Invalid amount");
    expect(formatZhu("1.5")).toBe("Invalid amount");
  });
});

describe("the deposit an owner types is the deposit the chain locks", () => {
  it("turns one typed HAC into the chain's own anchor value", () => {
    expect(depositHacToZhu("1")).toBe(100_000_000);
  });

  it("turns fifty typed HAC into the deposit the on-chain proof locked", () => {
    expect(depositHacToZhu("50")).toBe(5_000_000_000);
  });

  it("round-trips through the formatter, which is the property that broke", () => {
    // Typed HAC, and the HAC the screen shows back. They must be the same
    // string: an owner who types a deposit and is then shown a different
    // number is the whole defect, and it does not matter which of the two is
    // the one the chain agrees with.
    for (const hac of ["1", "50", "0.01", "0.00000001", "1234.5678"]) {
      const zhu = depositHacToZhu(hac);
      expect(zhu, `${hac} HAC should be a deposit`).not.toBeNull();
      expect(formatZhu(String(zhu)), `${hac} HAC should render back as itself`).toBe(
        `${hac} HAC`,
      );
    }
  });

  it("accepts all eight places, so a zhu-exact deposit can be typed", () => {
    expect(depositHacToZhu("0.00000001")).toBe(1);
    expect(depositHacToZhu("1.23456789")).toBe(123_456_789);
  });

  it("still refuses anything it cannot represent exactly", () => {
    expect(depositHacToZhu("0")).toBeNull();
    expect(depositHacToZhu("")).toBeNull();
    expect(depositHacToZhu("-1")).toBeNull();
    expect(depositHacToZhu("1.234567891")).toBeNull();
    expect(depositHacToZhu("1e8")).toBeNull();
    expect(depositHacToZhu("abc")).toBeNull();
  });
});

describe("the Rust that decides the unit still says what this file assumes", () => {
  it("agrees with wallet-core's ZHU_PER_HAC", () => {
    const source = readRepoFile(
      "crates/wallet-core/src/wallet/authorization_service.rs",
    );
    const match = source.match(/const ZHU_PER_HAC: u64 = ([0-9_]+);/);
    expect(match, "wallet-core no longer declares ZHU_PER_HAC").not.toBeNull();
    const zhuPerHac = Number(match![1].replace(/_/g, ""));
    expect(zhuPerHac).toBe(100_000_000);
    expect(depositHacToZhu("1")).toBe(zhuPerHac);
  });

  it("agrees with the fullnode balance parser's anchor", () => {
    const source = readRepoFile("crates/l2-fast-pay-hub/src/node.rs");
    expect(source).toContain(
      'assert_eq!(parse_fin_balance_zhu("1:248").unwrap(), 100_000_000);',
    );
  });

  it("agrees with the Hub readiness module's millimei", () => {
    const source = readRepoFile("crates/l2-fast-pay-hub/src/readiness.rs");
    const match = source.match(/pub const ZHU_PER_MILLIMEI: u64 = ([0-9_]+);/);
    expect(match, "readiness no longer declares ZHU_PER_MILLIMEI").not.toBeNull();
    const zhuPerMillimei = Number(match![1].replace(/_/g, ""));
    // A millimei is a thousandth of a HAC.
    expect(zhuPerMillimei * 1_000).toBe(depositHacToZhu("1"));
  });

  it("does not reuse the Agent ledger's 1e-6 unit for chain zhu", () => {
    const source = readRepoFile("crates/agent-wallet-core/src/amount.rs");
    const match = source.match(/pub const PER_HAC: u64 = ([0-9_]+);/);
    expect(match, "HacUnits no longer declares PER_HAC").not.toBeNull();
    const perHac = Number(match![1].replace(/_/g, ""));
    expect(perHac).toBe(1_000_000);
    // The two scales must differ, and this is the confusion that caused the
    // hundredfold error. If they ever become equal, delete this file's premise
    // deliberately rather than letting it pass by coincidence.
    expect(perHac).not.toBe(depositHacToZhu("1"));
  });
});

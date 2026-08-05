import { describe, expect, it } from "vitest";
import type { AgentPolicy } from "./api";
import { recipientStanding } from "./AgentAdminPages";

function policy(override: Partial<AgentPolicy> = {}): AgentPolicy {
  return {
    permissions: ["create_payment_intent"],
    max_per_payment_units: "1000000",
    max_daily_units: "10000000",
    max_pending_operations: 4,
    allowed_recipients: ["1Vetted"],
    blocked_recipients: [],
    allow_unlisted_recipient_with_approval: false,
    approval_mode: "desktop_manual",
    policy_epoch: 2,
    ...override,
  };
}

describe("recipientStanding", () => {
  it("names an address the owner already vetted", () => {
    expect(recipientStanding("1Vetted", policy())).toBe("allowlisted");
  });

  it("names an address that is not on the allowlist", () => {
    expect(recipientStanding("1NewDeveloper", policy())).toBe("not_on_allowlist");
  });

  it("still reports a new recipient when unlisted payments are permitted", () => {
    expect(
      recipientStanding(
        "1NewDeveloper",
        policy({ allow_unlisted_recipient_with_approval: true }),
      ),
    ).toBe("not_on_allowlist");
  });

  it("reports the same address as new again after it has been paid, because paying does not allowlist it", () => {
    const afterPayment = policy({ allow_unlisted_recipient_with_approval: true });
    expect(afterPayment.allowed_recipients).not.toContain("1NewDeveloper");
    expect(recipientStanding("1NewDeveloper", afterPayment)).toBe("not_on_allowlist");
  });

  it("never claims an address is vetted when the policy could not be read", () => {
    expect(recipientStanding("1Vetted", null)).toBe("unverified");
  });

  it("compares the whole address, so a prefix is not treated as vetted", () => {
    expect(recipientStanding("1Vetted2", policy())).toBe("not_on_allowlist");
    expect(recipientStanding("1Vette", policy())).toBe("not_on_allowlist");
  });
});

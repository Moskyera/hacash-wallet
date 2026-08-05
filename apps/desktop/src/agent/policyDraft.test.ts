import { describe, expect, it } from "vitest";
import type { AgentPolicy } from "./api";
import { policyToDraft, validateDraft } from "./AgentAdminPages";

function policy(override: Partial<AgentPolicy> = {}): AgentPolicy {
  return {
    permissions: ["create_payment_intent"],
    max_per_payment_units: "1000000",
    max_daily_units: "10000000",
    max_pending_operations: 4,
    allowed_recipients: ["1Vetted"],
    blocked_recipients: ["1Blocked"],
    allow_unlisted_recipient_with_approval: false,
    approval_mode: "desktop_manual",
    policy_epoch: 2,
    ...override,
  };
}

describe("policy draft round trip", () => {
  it("keeps the flag off for a policy that has it off", () => {
    const { policy: saved, error } = validateDraft(policyToDraft(policy()), 2);
    expect(error).toBe("");
    expect(saved?.allow_unlisted_recipient_with_approval).toBe(false);
  });

  // Without this, editing an unrelated field would send false back to the
  // backend and silently switch the owner's choice off.
  it("keeps the flag on through an edit of an unrelated field", () => {
    const draft = policyToDraft(
      policy({ allow_unlisted_recipient_with_approval: true }),
    );
    expect(draft.allowUnlistedWithApproval).toBe(true);
    const { policy: saved, error } = validateDraft(
      { ...draft, maxPending: "7" },
      2,
    );
    expect(error).toBe("");
    expect(saved?.allow_unlisted_recipient_with_approval).toBe(true);
    expect(saved?.max_pending_operations).toBe(7);
  });

  it("carries the owner's change of the flag in both directions", () => {
    const off = policyToDraft(policy());
    expect(
      validateDraft({ ...off, allowUnlistedWithApproval: true }, 2).policy
        ?.allow_unlisted_recipient_with_approval,
    ).toBe(true);
    const on = policyToDraft(
      policy({ allow_unlisted_recipient_with_approval: true }),
    );
    expect(
      validateDraft({ ...on, allowUnlistedWithApproval: false }, 2).policy
        ?.allow_unlisted_recipient_with_approval,
    ).toBe(false);
  });

  it("never turns the flag into an allowlist entry", () => {
    const { policy: saved } = validateDraft(
      { ...policyToDraft(policy()), allowUnlistedWithApproval: true },
      2,
    );
    expect(saved?.allowed_recipients).toEqual(["1Vetted"]);
    expect(saved?.blocked_recipients).toEqual(["1Blocked"]);
  });
});

/// THE NIGHT THIS PANEL COULD NOT EXPLAIN, AND THE EXIT IT DID NOT HAVE.
///
/// An owner opened their first mainnet Fast Pay channel. The wallet signed at
/// 10:11:48 and the Hub refused. The core mapped the refusal to `Err(_)` and
/// returned five generic words, so the panel had nothing to show. They pressed
/// the recovery button twice more and learned nothing three times. Five
/// minutes later the request envelope closed and the signed setup became
/// permanent furniture: confirm could not succeed, discard refuses anything a
/// signature exists for, and prepare refuses while any setup is stored.
///
/// Nothing here reads a source file. Each test renders the real panel and asks
/// what an owner can actually read and press, and the last two watch `invoke`
/// to see which command a button reaches and with what.

import { renderToStaticMarkup } from "react-dom/server";
import { beforeEach, describe, expect, it, vi } from "vitest";

const invoke = vi.fn();
vi.mock("@tauri-apps/api/core", () => ({
  invoke: (...args: unknown[]) => invoke(...args),
}));
vi.mock("@tauri-apps/plugin-shell", () => ({ open: vi.fn() }));

const { agentWalletApi } = await import("./api");
const { AgentFastPayChannelPanel, ChannelSetupReviewControl } = await import(
  "./AgentWalletApp"
);
const { channelSetupReviewIsBlocked, explainInvalidDepositAmount } = await import(
  "@hacash/wallet-ui"
);

type Overview = Parameters<typeof AgentFastPayChannelPanel>[0]["overview"];
type Setup = NonNullable<Overview["l2_channel_setup"]>;

const NOW_SECONDS = Math.floor(Date.now() / 1000);

/// The owner's own numbers, and their own clock offsets. The review was
/// prepared at 10:11:40 and expired 300 seconds later; the core treats the
/// signature as unusable 600 seconds after the review was prepared, which is
/// 300 seconds after it expired.
const setup = (overrides: Partial<Setup> = {}): Setup => ({
  wallet_id: "wallet_one",
  operation_id: "995e8831-8a43-46e1-8077-d341adf19810",
  review_commitment: "a".repeat(64),
  expires_at: NOW_SECONDS - 28_800,
  network_mode: "mainnet",
  hub_url: "http://127.0.0.1:8790",
  hub_address: "18bV2fjWhpQpmGRLifS8PDmzA6ATRJwVgq",
  channel_id: "488d41967b1263e469b152ec192aae35",
  channel_reuse_version: 1,
  deposit_units: "20000000",
  network_fee_units: "241",
  wallet_fee_units: "0",
  total_debit_units: "20000241",
  fee_estimate_degraded: null,
  last_hub_refusal: null,
  phase: "recovery_required",
  ...overrides,
});

const overview = (stored: Setup | null): Overview =>
  ({
    wallet_id: "wallet_one",
    address: "1BKZFnGqRbCTvpcT7J9nZa2ftL1ha6mYfg",
    l2_binding: null,
    l2_channel_setup: stored,
    l2_channel_close: null,
    l2_channel_close_voucher: null,
  }) as unknown as Overview;

const markupFor = (stored: Setup | null): string =>
  renderToStaticMarkup(
    <AgentFastPayChannelPanel
      overview={overview(stored)}
      busy={false}
      run={async (work) => {
        await work();
      }}
      onInfo={() => {}}
      onRefresh={async () => {}}
    />,
  );

/// The exact sentence the Hub produced on the owner's own machine.
const OWNER_REFUSAL =
  "admission: mainnet pilot aggregate Hub TVL cap exceeded: proposed 40000000 zhu, cap 20000000 zhu";

describe("the reason the Hub refused", () => {
  beforeEach(() => {
    invoke.mockReset();
    invoke.mockResolvedValue({});
  });

  it("is on the screen, in the Hub's own words", () => {
    const markup = markupFor(setup({ last_hub_refusal: OWNER_REFUSAL }));
    expect(markup).toContain("aggregate Hub TVL cap exceeded");
    expect(markup).toContain("proposed 40000000 zhu, cap 20000000 zhu");
  });

  it("survives the refresh that threw the returned error away", () => {
    // The owner refreshed. A toast is gone by then; this is read from the
    // stored setup on every render, so it is still there.
    const stored = setup({ last_hub_refusal: OWNER_REFUSAL });
    expect(markupFor(stored)).toEqual(markupFor(stored));
    expect(markupFor(stored)).toContain("The Fast Pay Hub refused this channel");
  });

  it("says plainly that no money moved", () => {
    const markup = markupFor(setup({ last_hub_refusal: OWNER_REFUSAL }));
    expect(markup).toContain("Nothing was sent to the chain and nothing was spent");
  });

  it("shows nothing at all when no Hub has answered", () => {
    const markup = markupFor(setup({ phase: "prepared", expires_at: NOW_SECONDS + 200 }));
    expect(markup).not.toContain("The Fast Pay Hub refused this channel");
  });
});

describe("the exit from a signed request nobody will accept", () => {
  beforeEach(() => {
    invoke.mockReset();
    invoke.mockResolvedValue({});
  });

  it("is offered for a signed setup whose signing window is long closed", () => {
    for (const phase of ["signed", "recovery_required"] as const) {
      const markup = markupFor(setup({ phase }));
      expect(markup, `phase ${phase}`).toContain("Abandon this signed setup");
    }
  });

  it("is not offered while the request could still be accepted", () => {
    // Signed eight seconds ago, the way the owner's was. The Hub may still
    // take it, and a wallet that forgets a live signature is a wallet that can
    // fund the same channel twice.
    const live = markupFor(setup({ phase: "signed", expires_at: NOW_SECONDS + 292 }));
    expect(live).not.toContain("Abandon this signed setup");
    // And not in the gap between the envelope closing and the transaction
    // ageing out, where the core would refuse anyway.
    const between = markupFor(setup({ phase: "signed", expires_at: NOW_SECONDS - 100 }));
    expect(between).not.toContain("Abandon this signed setup");
  });

  it("is never offered for a setup that reached a node", () => {
    for (const phase of ["submitted", "awaiting_confirmations", "confirmed"] as const) {
      const markup = markupFor(setup({ phase }));
      expect(markup, `phase ${phase}`).not.toContain("Abandon this signed setup");
    }
  });

  it("is never confused with the discard, which claims something different", () => {
    const dead = markupFor(setup({ phase: "signed" }));
    expect(dead).toContain("Abandon this signed setup");
    expect(dead).not.toContain("Discard this review");

    const unsigned = markupFor(setup({ phase: "prepared" }));
    expect(unsigned).toContain("Discard this review");
    expect(unsigned).not.toContain("Abandon this signed setup");
  });

  it("tells the owner what it is about to check, and that the deposit never left", () => {
    const markup = markupFor(setup({ phase: "signed" }));
    expect(markup).toContain("no Hub will accept it now");
    expect(markup).toContain("Your deposit was never sent");
    expect(markup).toContain("asks the chain before it agrees");
  });

  it("reaches the owner-only command with the exact reviewed operation", async () => {
    await agentWalletApi.abandonDeadFastPayChannelSetup(
      "wallet_one",
      "995e8831-8a43-46e1-8077-d341adf19810",
      "a".repeat(64),
    );
    expect(invoke).toHaveBeenCalledWith("agent_wallet_abandon_dead_fast_pay_channel_setup", {
      walletId: "wallet_one",
      operationId: "995e8831-8a43-46e1-8077-d341adf19810",
      reviewCommitment: "a".repeat(64),
    });
  });
});

describe("the deposit amount is refused before it is sent, not after", () => {
  beforeEach(() => {
    invoke.mockReset();
    invoke.mockResolvedValue({});
  });

  const HUB = "http://127.0.0.1:8790";

  it("names the comma, which the core reports as five generic words", () => {
    expect(explainInvalidDepositAmount("0,2")).toContain("full stop");
    expect(explainInvalidDepositAmount("0.2")).toBeNull();
  });

  it("passes the shapes the core parser takes", () => {
    for (const good of ["1", "0.2", "0.200", "12.345"]) {
      expect(explainInvalidDepositAmount(good), `${good} is accepted`).toBeNull();
    }
  });

  it("does not second-guess unit:exponent notation, which the parser accepts", () => {
    expect(explainInvalidDepositAmount("248:248")).toBeNull();
  });

  it("refuses every shape the core parser refuses, and says which rule", () => {
    for (const bad of ["0,2", ".2", "0.2000", "0.2 HAC", "1.2.3", "1.", "0", "0.000"]) {
      expect(explainInvalidDepositAmount(bad), `${bad} is refused`).not.toBeNull();
    }
  });

  // THE POINT OF ALL OF IT. Explaining the problem and then letting the press
  // through means the amount is sent anyway and the core answers with the five
  // words this check exists to replace.
  it("blocks the review button for exactly the amounts it complains about", () => {
    for (const bad of ["0,2", ".2", "0.2000", "0.2 HAC", "1.2.3", "1.", "0", "0.000", "   "]) {
      expect(channelSetupReviewIsBlocked(HUB, bad), `${bad} must block`).toBe(true);
      expect(explainInvalidDepositAmount(bad) === null, `${bad} must be explained`).toBe(false);
    }
  });

  it("lets a good amount through, so the gate is not simply always shut", () => {
    for (const good of ["1", "0.2", "0.200", "12.345"]) {
      expect(channelSetupReviewIsBlocked(HUB, good), `${good} must pass`).toBe(false);
    }
  });

  it("still refuses a missing Hub, which is the check that was already there", () => {
    expect(channelSetupReviewIsBlocked("", "0.2")).toBe(true);
    expect(channelSetupReviewIsBlocked("   ", "0.2")).toBe(true);
  });

  // Rendering the real control, with a real amount in it. The panel keeps
  // this in `useState` and static markup cannot type, which is exactly why the
  // complaint and the button live in one component that a test can hand an
  // amount to.
  const control = (deposit: string, hubUrl = HUB): string =>
    renderToStaticMarkup(
      <ChannelSetupReviewControl
        hubUrl={hubUrl}
        deposit={deposit}
        busy={false}
        onReview={() => {}}
      />,
    );

  it("disables the button on the screen for every amount it complains about", () => {
    for (const bad of ["0,2", ".2", "0.2000", "0.2 HAC", "1.2.3", "1.", "0", "0.000"]) {
      const markup = control(bad);
      expect(markup, `${bad} must be explained`).toContain("agent-warning");
      expect(markup, `${bad} must be refused`).toContain("disabled");
    }
  });

  it("enables it for an amount it does not complain about", () => {
    for (const good of ["1", "0.2", "0.200", "12.345"]) {
      const markup = control(good);
      expect(markup, `${good} must not be explained`).not.toContain("agent-warning");
      expect(markup, `${good} must be pressable`).not.toContain("disabled");
    }
  });

  it("never explains a problem it then allows, whatever is typed", () => {
    for (const typed of ["0,2", "0.2", ".2", "1", "0.2000", "12.345", "abc", "0"]) {
      const markup = control(typed);
      const explained = markup.includes("agent-warning");
      const refused = markup.includes("disabled");
      expect(explained && !refused, `${typed} explained but allowed`).toBe(false);
    }
  });

  it("starts with the empty panel showing the inputs and no complaint", () => {
    // The deposit defaults to "1", which is valid, so nothing is complained
    // about before anyone has typed.
    const markup = markupFor(null);
    expect(markup).toContain("Agent channel deposit (HAC)");
    expect(markup).toContain("Review channel setup");
    expect(markup).not.toContain("full stop for the decimal point");
  });
});

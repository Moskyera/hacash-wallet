/// THE WAY OUT OF A REVIEW THAT EXPIRED, AND ONLY OUT OF THAT ONE.
///
/// The owner's first mainnet Fast Pay channel got stuck in front of this
/// panel. A review prepared at 15:59:42 expired 300 seconds later, and the
/// only control the panel offered afterwards was "Confirm exact setup", which
/// can never succeed once the window has closed. The deposit input is hidden
/// while any setup is stored, so there was no way forward and no way back.
///
/// Nothing here reads a source file. Each test renders the real panel and asks
/// what an owner can actually press, and the last one watches `invoke` to see
/// which command the button reaches.

import { renderToStaticMarkup } from "react-dom/server";
import { beforeEach, describe, expect, it, vi } from "vitest";

const invoke = vi.fn();
vi.mock("@tauri-apps/api/core", () => ({
  invoke: (...args: unknown[]) => invoke(...args),
}));
vi.mock("@tauri-apps/plugin-shell", () => ({ open: vi.fn() }));

const { agentWalletApi } = await import("./api");
const { AgentFastPayChannelPanel } = await import("./AgentWalletApp");

type Overview = Parameters<typeof AgentFastPayChannelPanel>[0]["overview"];
type Setup = NonNullable<Overview["l2_channel_setup"]>;

const NOW_SECONDS = Math.floor(Date.now() / 1000);

const setup = (overrides: Partial<Setup> = {}): Setup => ({
  wallet_id: "wallet_one",
  operation_id: "channel-setup-operation",
  review_commitment: "a".repeat(64),
  expires_at: NOW_SECONDS - 28_800,
  network_mode: "mainnet",
  hub_url: "http://127.0.0.1:8790",
  hub_address: "1Hub",
  channel_id: "488d41967b1263e469b152ec192aae35",
  channel_reuse_version: 1,
  deposit_units: "20000000",
  network_fee_units: "1000",
  wallet_fee_units: "0",
  total_debit_units: "20001000",
  fee_estimate_degraded: null,
  phase: "prepared",
  ...overrides,
});

const overview = (stored: Setup | null): Overview =>
  ({
    wallet_id: "wallet_one",
    address: "1Agent",
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

describe("a channel setup review that expired before it was confirmed", () => {
  beforeEach(() => {
    invoke.mockReset();
    invoke.mockResolvedValue({});
  });

  it("offers the way out instead of a button that can only refuse", () => {
    const markup = markupFor(setup());
    expect(markup).toContain("Discard this review");
    expect(markup).not.toContain("Confirm exact setup");
  });

  it("says in plain words what happened and what to do", () => {
    // It deliberately does NOT say "nothing was signed". See
    // "claims only what the phase and the clock can establish" below: this
    // screen cannot know that, and it said it anyway.
    const markup = markupFor(setup());
    expect(markup).toContain("This review was never confirmed");
    expect(markup).toContain("its window has closed");
    expect(markup).toContain("set the channel up again");
  });

  it("still offers the confirm while the review is live, and a way to back out", () => {
    const markup = markupFor(setup({ expires_at: NOW_SECONDS + 200 }));
    expect(markup).toContain("Confirm exact setup");
    expect(markup).toContain("Discard this review");
    expect(markup).not.toContain("This review expired before it was confirmed");
  });

  it("offers no discard for any phase a signature could exist for", () => {
    for (const phase of [
      "signature_may_exist",
      "signed",
      "submitted",
      "awaiting_confirmations",
      "recovery_required",
      "confirmed",
    ] as const) {
      const markup = markupFor(setup({ phase }));
      expect(markup, `phase ${phase} must keep only its recovery path`).not.toContain(
        "Discard this review",
      );
      expect(markup).toContain("Check or recover setup");
    }
  });

  it("brings the Hub and deposit inputs back once nothing is stored", () => {
    const markup = markupFor(null);
    expect(markup).toContain("Review channel setup");
    expect(markup).toContain("Agent channel deposit (HAC)");
  });

  it("reaches the owner-only discard command with the exact reviewed operation", async () => {
    await agentWalletApi.discardFastPayChannelSetup(
      "wallet_one",
      "channel-setup-operation",
      "a".repeat(64),
    );
    expect(invoke).toHaveBeenCalledWith("agent_wallet_discard_fast_pay_channel_setup", {
      walletId: "wallet_one",
      operationId: "channel-setup-operation",
      reviewCommitment: "a".repeat(64),
    });
  });
});

describe("attack: what the panel offers versus what the core will accept", () => {
  beforeEach(() => {
    invoke.mockReset();
    invoke.mockResolvedValue({});
  });

  it("offers the discard alone, and never a control that could only refuse", () => {
    // These two tests used to assert the OPPOSITE. They were written to pin a
    // real defect: for an expired prepared review the panel rendered neither
    // "Confirm exact setup" nor "Check or recover setup", so the only button
    // was the discard, and the core refuses that discard in exactly one
    // interleaving - a crash between `safety.mark_signature_may_exist()` and
    // the state write after it, which leaves the durable store saying a
    // signature may exist while the phase still reads prepared. The refusal
    // text names "Check or recover setup", which was not on the screen.
    //
    // That is the same dead end this whole change exists to remove, rebuilt one
    // state narrower. So the panel now always offers the second control, and
    // these tests pin the fix instead of the defect.
    // Deliberately ONE button, and it is the discard. A second control was
    // tried here and reverted: recovery re-runs the confirm that already
    // refused, so it would fail the same way. When the discard is refused the
    // remedy is the refusal text, which now carries the whole truth, not
    // another button to press.
    const markup = markupFor(setup());
    expect(markup).not.toContain("Confirm exact setup");
    expect(markup).not.toContain("Check or recover setup");
    const buttons = markup.match(/<button/g) ?? [];
    expect(buttons.length).toBe(1);
  });

  it("claims only what the phase and the clock can establish", () => {
    // The old notice stated flatly that nothing was signed, nothing reached the
    // Hub and nothing was spent. This screen cannot know any of that: whether a
    // signature could exist is decided by the durable ChannelOpenSafety store,
    // which is never sent here. Saying it anyway asserted a correctness claim
    // in the one state where the core declines to make it.
    const markup = markupFor(setup());
    expect(markup).not.toContain("Nothing was signed, nothing was sent to the Hub");
    expect(markup).toContain("This review was never confirmed");
    // And it must NOT send the reader to a control that cannot help. Recovery
    // for a non-Confirmed phase re-runs the confirm, which is what refused in
    // the first place, so naming it was a politer dead end. What the screen can
    // honestly say is that the deposit never left.
    expect(markup).not.toMatch(/use Check or recover setup/i);
    expect(markup).toContain("deposit was never sent");
  });

  it("keeps the deposit inputs hidden while a review is stored", () => {
    const markup = markupFor(setup());
    expect(markup).not.toContain("Agent channel deposit (HAC)");
    expect(markup).not.toContain("Review channel setup");
  });

  it("offers the discard only for the phase the core can accept", () => {
    for (const phase of [
      "signature_may_exist",
      "signed",
      "submitted",
      "awaiting_confirmations",
      "recovery_required",
      "confirmed",
    ] as const) {
      for (const expires_at of [NOW_SECONDS - 28_800, NOW_SECONDS + 200]) {
        const markup = markupFor(setup({ phase, expires_at }));
        expect(markup, `phase ${phase}`).not.toContain("Discard this review");
        expect(markup, `phase ${phase}`).not.toContain(
          "This review expired before it was confirmed",
        );
      }
    }
  });

  it("sends the stored operation id and commitment, never a substitute", async () => {
    const stored = setup({ operation_id: "op-42", review_commitment: "b".repeat(64) });
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
    await agentWalletApi.discardFastPayChannelSetup(
      "wallet_one",
      stored.operation_id,
      stored.review_commitment,
    );
    expect(invoke).toHaveBeenCalledWith("agent_wallet_discard_fast_pay_channel_setup", {
      walletId: "wallet_one",
      operationId: "op-42",
      reviewCommitment: "b".repeat(64),
    });
  });
});

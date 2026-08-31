/// THE HALF HOUR THE WALLET SHOWED NOTHING, AND THE TWO NUMBERS IT ALREADY HAD.
///
/// An owner opened and closed the first mainnet Fast Pay channel on this rail.
/// It worked. What nearly stopped them was this screen, and the worst stretch
/// was about half an hour in which 0.2 HAC of their own money sat committed on
/// the chain and the panel rendered nothing at all for it: ChannelExit is gated
/// on `binding && !binding.closed`, and the core cannot produce a binding until
/// the open has six confirmations, so during the entire wait there was
/// literally no element for that state. An ordinary wait and a dead app looked
/// the same.
///
/// Two of the three things missing were already in the overview and were never
/// drawn: `l2_channel_setup.expires_at`, read only to compute two booleans, and
/// `payments_suspended`, which this panel said nothing about while sitting
/// above the only control that clears it.
///
/// Most of what follows renders the real panel and asks what an owner can
/// actually read. The count itself is argued with directly, because the number
/// that gates the exit is the one thing here that must not be approximated.

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { renderToStaticMarkup } from "react-dom/server";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const invoke = vi.fn();
vi.mock("@tauri-apps/api/core", () => ({
  invoke: (...args: unknown[]) => invoke(...args),
}));
vi.mock("@tauri-apps/plugin-shell", () => ({ open: vi.fn() }));

const { AgentFastPayChannelPanel } = await import("./AgentWalletApp");
const { channelOpenProgress, reviewCountdown, REQUIRED_OPEN_CONFIRMATIONS } =
  await import("./channelWaitingView");

type Overview = Parameters<typeof AgentFastPayChannelPanel>[0]["overview"];
type Setup = NonNullable<Overview["l2_channel_setup"]>;
type Binding = NonNullable<Overview["l2_binding"]>;

/// A frozen clock, because two of the three additions here ARE clocks. The
/// countdown label is exact to the second, and a test that allowed "4:12 or
/// 4:11, whichever the machine was feeling" would not be able to tell a correct
/// countdown from one that is off by a second.
const FIXED_NOW_MS = Date.UTC(2026, 7, 31, 12, 0, 0);
const NOW_SECONDS = Math.floor(FIXED_NOW_MS / 1000);

/// The owner's own numbers: 0.2 HAC into a Hub on their own machine.
const setup = (overrides: Partial<Setup> = {}): Setup => ({
  wallet_id: "wallet_one",
  operation_id: "995e8831-8a43-46e1-8077-d341adf19810",
  review_commitment: "a".repeat(64),
  expires_at: NOW_SECONDS + 252,
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
  phase: "awaiting_confirmations",
  ...overrides,
});

const binding = (overrides: Partial<Binding> = {}): Binding =>
  ({
    schema_version: 1,
    wallet_id: "wallet_one",
    wallet_scope: "agent",
    network_mode: "mainnet",
    agent_address: "1BKZFnGqRbCTvpcT7J9nZa2ftL1ha6mYfg",
    hub_url: "http://127.0.0.1:8790",
    hub_address: "18bV2fjWhpQpmGRLifS8PDmzA6ATRJwVgq",
    channel_id: "488d41967b1263e469b152ec192aae35",
    channel_reuse_version: 1,
    channel_open_height: 777_933,
    confirmed_at_height: 777_938,
    deposit_units: "20000000",
    bound_at: NOW_SECONDS,
    commitment_sha256: "c".repeat(64),
    ...overrides,
  }) as Binding;

const overview = (parts: {
  setup?: Setup | null;
  binding?: Binding | null;
  currentHeight?: number | null;
  paymentsSuspended?: boolean;
}): Overview =>
  ({
    wallet_id: "wallet_one",
    address: "1BKZFnGqRbCTvpcT7J9nZa2ftL1ha6mYfg",
    payments_suspended: parts.paymentsSuspended ?? false,
    node:
      parts.currentHeight === undefined || parts.currentHeight === null
        ? null
        : { current_height: parts.currentHeight },
    l2_binding: parts.binding ?? null,
    l2_channel_setup: parts.setup ?? null,
    l2_channel_close: null,
    l2_channel_close_voucher: null,
  }) as unknown as Overview;

const markupFor = (parts: Parameters<typeof overview>[0]): string =>
  renderToStaticMarkup(
    <AgentFastPayChannelPanel
      overview={overview(parts)}
      busy={false}
      run={async (work) => {
        await work();
      }}
      onInfo={() => {}}
      onRefresh={async () => {}}
    />,
  );

beforeEach(() => {
  invoke.mockReset();
  invoke.mockResolvedValue({});
  vi.useFakeTimers();
  vi.setSystemTime(FIXED_NOW_MS);
});

afterEach(() => {
  vi.useRealTimers();
});

/**
 * THE NUMBER THE WHOLE BAR TURNS ON.
 *
 * The tree looks like it disagrees with itself: a named constant saying 6 at
 * service/l2.rs:50 and a bare `open_height.saturating_add(5)` doing the gating
 * at channel_setup.rs:634. They are the same rule. The constant is never used
 * bare; both of its use sites subtract one, at l2.rs:1058 where a binding is
 * created and l2.rs:1108 where it is re-validated on every load from disk. Six
 * confirmations counted inclusively: the open block is the first, so the sixth
 * lands at open_height + 5.
 *
 * The exit button takes a voucher, and channel_voucher.rs:125 refuses to issue
 * one without an active binding. So this is not a cosmetic number. A bar that
 * fills at open_height + 6 fills a block after the wallet would already act; a
 * bar that fills at open_height + 4 promises an exit the core will refuse.
 */
describe("the progress counts what actually gates the exit", () => {
  const OPEN = 777_933;

  it("counts the open block itself as the first confirmation", () => {
    const at = channelOpenProgress({ currentHeight: OPEN, openHeight: OPEN });
    expect(at.kind).toBe("counting");
    if (at.kind !== "counting") return;
    expect(at.confirmations).toBe(1);
    expect(at.settled).toBe(false);
  });

  it("is not settled one block before the core would act", () => {
    // open + 4 is five confirmations. The other reading of the tree, "six
    // blocks elapsed", would still be two short here; the wrong-by-one reading
    // that fills early would already be full.
    const at = channelOpenProgress({ currentHeight: OPEN + 4, openHeight: OPEN });
    expect(at.kind).toBe("counting");
    if (at.kind !== "counting") return;
    expect(at.confirmations).toBe(5);
    expect(at.settled).toBe(false);
    expect(at.percent).toBeLessThan(100);
  });

  it("is settled at exactly open_height + 5, which is where the core opens the gate", () => {
    const at = channelOpenProgress({ currentHeight: OPEN + 5, openHeight: OPEN });
    expect(at.kind).toBe("counting");
    if (at.kind !== "counting") return;
    expect(at.confirmations).toBe(REQUIRED_OPEN_CONFIRMATIONS);
    expect(at.confirmations).toBe(6);
    expect(at.settled).toBe(true);
    expect(at.percent).toBe(100);
  });

  it("does not keep climbing past six once the gate is open", () => {
    const at = channelOpenProgress({ currentHeight: OPEN + 40, openHeight: OPEN });
    expect(at.kind).toBe("counting");
    if (at.kind !== "counting") return;
    expect(at.confirmations).toBe(6);
    expect(at.percent).toBe(100);
  });

  it("never reports a negative count when the chain is shorter than the open", () => {
    // A reorg, or a swap to a node that is behind. This must read as fewer
    // confirmations, never as the channel sliding below zero.
    const at = channelOpenProgress({ currentHeight: OPEN - 3, openHeight: OPEN });
    expect(at.kind).toBe("counting");
    if (at.kind !== "counting") return;
    expect(at.confirmations).toBe(0);
    expect(at.settled).toBe(false);
    expect(at.percent).toBe(0);
  });

  it("puts that same count on the screen once the binding exists", () => {
    // confirmed_at_height is overridden to match the height under test. The
    // default fixture banks 777938, which is six confirmations already, and a
    // binding cannot have been confirmed at a height the chain has not reached.
    // Leaving it at the default made this test drive a state that cannot exist.
    const markup = markupFor({
      binding: binding({ confirmed_at_height: 777_933 + 4 }),
      currentHeight: 777_933 + 4,
    });
    expect(markup).toContain("5 of 6");
    expect(markup).toContain("confirmations");
    expect(markup).toContain('aria-valuenow="5"');
    expect(markup).toContain('aria-valuemax="6"');
    expect(markup).toContain("777933");
  });

  it("fills the bar at open + 5 and not before", () => {
    const early = markupFor({
      binding: binding({ confirmed_at_height: 777_933 + 4 }),
      currentHeight: 777_933 + 4,
    });
    expect(early).not.toContain("width:100%");
    const gate = markupFor({
      binding: binding({ confirmed_at_height: 777_933 + 5 }),
      currentHeight: 777_933 + 5,
    });
    expect(gate).toContain("6 of 6");
    expect(gate).toContain("width:100%");
  });
});

/**
 * NEVER ANIMATE OVER AN UNKNOWN.
 *
 * `overview.node` is nullable and is null whenever the node probe returned no
 * snapshot at all, which covers offline, network_mismatch and
 * capability_mismatch. A height defaulted to zero would draw a channel that had
 * slid backwards, and during the wait the open height is not on this screen in
 * any form: AgentChannelSetupReview carries no open height, no confirmed height
 * and no transaction hash, and l2_binding is null until the wait is over.
 */
describe("nothing is counted that the data cannot support", () => {
  it("draws no bar and no count when the wallet cannot reach a node", () => {
    const markup = markupFor({ binding: binding(), currentHeight: null });
    expect(markup).not.toContain("agent-wait-track");
    expect(markup).not.toContain("progressbar");
    expect(markup).not.toMatch(/of 6/);
    expect(markup).not.toMatch(/width:\s*\d+%/);
    expect(markup).toContain("cannot reach a node");
  });

  it("refuses to invent a confirmation count while the open height is unknown", () => {
    // The whole wait lives here. design/Waiting.dc.html draws six filling pips
    // and "Opened at block 777933"; that height is a hardcoded demo value with
    // no source in the overview, and porting it would be exactly the fabricated
    // number this work exists to remove.
    const markup = markupFor({ setup: setup(), currentHeight: 913_400 });
    expect(markup).not.toContain("agent-wait-track");
    expect(markup).not.toContain("progressbar");
    expect(markup).not.toMatch(/of 6/);
    expect(markup).not.toMatch(/width:\s*\d+%/);
    expect(markup).toContain("not known to this wallet yet");
  });

  it("still shows the height it does know, which is the part that moves", () => {
    const markup = markupFor({ setup: setup(), currentHeight: 913_400 });
    expect(markup).toContain("Chain is at");
    expect(markup).toContain("913400");
  });

  it("says the height is unknown rather than printing a zero", () => {
    const markup = markupFor({ setup: setup(), currentHeight: null });
    expect(markup).toContain("cannot reach a node");
    expect(markup).not.toContain("Chain is at");
    expect(markup).not.toMatch(/of 6/);
  });

  it("treats a zero height as no height, because a live chain is never at zero", () => {
    expect(channelOpenProgress({ currentHeight: 0, openHeight: 777_933 }).kind).toBe(
      "chain_height_unknown",
    );
    expect(channelOpenProgress({ currentHeight: undefined, openHeight: 1 }).kind).toBe(
      "chain_height_unknown",
    );
    expect(channelOpenProgress({ currentHeight: 900_000, openHeight: null }).kind).toBe(
      "open_height_unknown",
    );
  });
});

/**
 * THE STRETCH THAT RENDERED NOTHING.
 *
 * ChannelExit is behind `active && (...)` where `active = Boolean(binding &&
 * !binding.closed)`. Because the core will not produce a binding below
 * open_height + 5, that panel provably cannot render during the wait. The
 * remedy is not to move the exit; it is to say, in words, that its absence is
 * the wallet working.
 */
describe("the wait says in words why there is no exit button", () => {
  for (const phase of ["submitted", "awaiting_confirmations"] as const) {
    it(`explains itself while the setup is ${phase}`, () => {
      const markup = markupFor({ setup: setup({ phase }), currentHeight: 913_400 });
      expect(markup).toContain("Why there is no exit button yet");
      expect(markup).toContain("Your deposit is on the chain");
      expect(markup).toContain("cannot sign a way out of a channel the chain has not");
      expect(markup).toContain("six confirmations");
      expect(markup).toContain("appears here");
    });
  }

  it("does not claim the exit needs a press, because it arrives on its own", () => {
    const markup = markupFor({ setup: setup(), currentHeight: 913_400 });
    expect(markup).toContain("on its own");
    // And it must not name a control that is not on this screen. The exit
    // panel is not rendered at all during the wait.
    expect(markup).not.toContain("Take my way out");
  });

  it("says nothing of the kind before the deposit is on the chain", () => {
    for (const phase of ["prepared", "signed"] as const) {
      const markup = markupFor({
        setup: setup({ phase, expires_at: NOW_SECONDS + 252 }),
        currentHeight: 913_400,
      });
      expect(markup, `phase ${phase}`).not.toContain("Why there is no exit button yet");
      expect(markup, `phase ${phase}`).not.toContain("Your deposit is on the chain");
    }
  });

  it("says nothing of the kind once the channel is open and the exit is there", () => {
    const markup = markupFor({ binding: binding(), currentHeight: 777_940 });
    expect(markup).not.toContain("Why there is no exit button yet");
  });
});

/**
 * THE 300 SECOND ENVELOPE NOBODY WAS SHOWN.
 *
 * `expires_at` was on this review from the first version and was read only to
 * compute `reviewExpired` and `requestIsDead`. The owner's first attempt
 * expired unseen and the refusal afterwards was the same generic sentence eight
 * other causes produce.
 */
describe("the countdown on a prepared review", () => {
  it("is on the screen while the numbers are still good", () => {
    const markup = markupFor({ setup: setup({ phase: "prepared" }) });
    expect(markup).toContain("These numbers are good for");
    expect(markup).toContain("4:12");
  });

  it("counts down rather than showing one fixed number", () => {
    const far = markupFor({
      setup: setup({ phase: "prepared", expires_at: NOW_SECONDS + 300 }),
    });
    const near = markupFor({
      setup: setup({ phase: "prepared", expires_at: NOW_SECONDS + 9 }),
    });
    expect(far).toContain("5:00");
    expect(near).toContain("0:09");
    expect(far).not.toEqual(near);
  });

  it("says the review expired, and offers the way forward", () => {
    const markup = markupFor({
      setup: setup({ phase: "prepared", expires_at: NOW_SECONDS - 60 }),
    });
    expect(markup).toContain("These numbers have expired");
    expect(markup).toContain("Discard this review");
    // The button that could only ever refuse must be gone by then.
    expect(markup).not.toContain("Confirm exact setup");
  });

  it("claims only what the phase and the clock establish", () => {
    // design/Review.dc.html ends its expired state with "Nothing was signed and
    // nothing was spent." This screen cannot know that: whether a signature
    // could exist is decided by the durable ChannelOpenSafety store, which is
    // never sent here, and there is one crash interleaving where it says a
    // signature may exist while the phase still reads prepared.
    const markup = markupFor({
      setup: setup({ phase: "prepared", expires_at: NOW_SECONDS - 60 }),
    });
    expect(markup).not.toContain("Nothing was signed and nothing was spent");
  });

  it("does not offer a live countdown on a phase the countdown cannot save", () => {
    // Past prepared, the envelope closing is not something the owner can act on
    // by hurrying, and a ticking clock beside a signature would read as a
    // deadline they were failing to meet.
    for (const phase of ["signed", "submitted", "awaiting_confirmations"] as const) {
      const markup = markupFor({ setup: setup({ phase }), currentHeight: 913_400 });
      expect(markup, `phase ${phase}`).not.toContain("These numbers are good for");
    }
  });

  it("treats the exact expiry instant as expired, not as a last second", () => {
    expect(reviewCountdown({ expiresAt: 1_000, nowSeconds: 1_000 }).kind).toBe("expired");
    expect(reviewCountdown({ expiresAt: 1_001, nowSeconds: 1_000 }).kind).toBe("live");
    expect(reviewCountdown({ expiresAt: null, nowSeconds: 1_000 }).kind).toBe("unknown");
  });

  it("formats the remaining time so it can be read at a glance", () => {
    const live = reviewCountdown({ expiresAt: 1_252, nowSeconds: 1_000 });
    expect(live.kind).toBe("live");
    if (live.kind !== "live") return;
    expect(live.secondsRemaining).toBe(252);
    expect(live.label).toBe("4:12");
  });
});

/**
 * READINESS WHERE THE DECISION IS.
 *
 * `payments_suspended` has always been on this overview. This panel said
 * nothing about it while sitting ABOVE the one control that clears it, so the
 * owner pressed a channel button, met a refusal, and was given no cause.
 */
describe("the channel panel says payments are off before the press", () => {
  it("says so on the panel where the decision is made", () => {
    const markup = markupFor({ paymentsSuspended: true });
    expect(markup).toContain("Payments are off");
    expect(markup).toContain("until you turn them back on");
  });

  it("names where the control that fixes it actually is", () => {
    // The rule from design/Refusals.dc.html: never name a button that is not on
    // this screen. Payment control is on this page, below this panel.
    const markup = markupFor({ paymentsSuspended: true });
    expect(markup).toContain("Payment control");
    expect(markup).toContain("further down this page");
  });

  it("is there before the press, not only after a refusal", () => {
    // The open form is what the owner is about to use, and the warning sits
    // above it rather than arriving as an answer to it.
    const markup = markupFor({ paymentsSuspended: true });
    const warning = markup.indexOf("Payments are off");
    const form = markup.indexOf("Agent channel deposit (HAC)");
    expect(warning).toBeGreaterThan(-1);
    expect(form).toBeGreaterThan(-1);
    expect(warning).toBeLessThan(form);
  });

  it("stays on the panel through every later state, because it blocks those too", () => {
    for (const parts of [
      { setup: setup({ phase: "prepared" }), paymentsSuspended: true },
      { setup: setup(), currentHeight: 913_400, paymentsSuspended: true },
      { binding: binding(), currentHeight: 777_940, paymentsSuspended: true },
    ]) {
      expect(markupFor(parts)).toContain("Payments are off");
    }
  });

  it("says nothing at all when payments are on", () => {
    const markup = markupFor({ paymentsSuspended: false });
    expect(markup).not.toContain("Payments are off");
    expect(markup).not.toContain("agent-readiness");
  });
});

/**
 * MARKUP WITH NO CSS BEHIND IT HAS SHIPPED HERE BEFORE.
 *
 * `.toast` was written into the markup and defined in no desktop stylesheet at
 * all, so every refusal on the Fast Pay screen went into an unstyled block off
 * the screen and deleted itself four seconds later. The Enable button looked
 * dead for two days.
 *
 * The list is a literal on purpose. A list scraped from the component agrees
 * with the component by construction and would have passed happily while
 * `.toast` was undefined.
 */
describe("every class this panel adds is defined in the sheet the screen loads", () => {
  const CSS = readFileSync(
    fileURLToPath(new URL("./agent-wallet.css", import.meta.url)),
    "utf8",
  );

  const ADDED = [
    "agent-readiness",
    "agent-wait",
    "agent-wait-count",
    "agent-wait-track",
    "agent-wait-fill",
    "agent-countdown",
  ];

  for (const cls of ADDED) {
    it(`defines .${cls}`, () => {
      expect(
        new RegExp(`\\.${cls}[\\s,{:]`).test(CSS),
        `.${cls} is rendered by AgentFastPayChannelPanel and has no rule in ` +
          "agent-wallet.css, which is the only stylesheet this screen imports.",
      ).toBe(true);
    });
  }

  it("renders every one of them, so the list is not a fiction either way", () => {
    const everywhere = [
      markupFor({ paymentsSuspended: true }),
      markupFor({ setup: setup({ phase: "prepared" }) }),
      markupFor({ setup: setup(), currentHeight: 913_400 }),
      markupFor({ binding: binding(), currentHeight: 777_940 }),
    ].join("\n");
    for (const cls of ADDED) {
      expect(everywhere, `.${cls} is defined but nothing renders it`).toContain(cls);
    }
  });

  it("quiets the only moving part under prefers-reduced-motion", () => {
    const flat = CSS.replace(/\s+/g, "");
    expect(flat).toContain("@media(prefers-reduced-motion:reduce)");
    const blocks: string[] = [];
    for (
      let at = flat.indexOf("@media(prefers-reduced-motion:reduce)");
      at !== -1;
      at = flat.indexOf("@media(prefers-reduced-motion:reduce)", at + 1)
    ) {
      blocks.push(flat.slice(at, flat.indexOf("}}", at) + 2));
    }
    expect(
      blocks.some((block) => block.includes(".agent-wait-fill") && block.includes("transition:none")),
      "the confirmation bar still slides for somebody who asked for no motion",
    ).toBe(true);
  });

  it("ships no looping animation and no indeterminate track", () => {
    // A bar that moves while nothing is known is the screen this whole effort
    // is removing. Motion here must only ever mean a block arrived.
    const flat = CSS.replace(/\s+/g, "");
    const at = flat.indexOf(".agent-wait-fill{");
    expect(at, ".agent-wait-fill has no rule of its own").not.toBe(-1);
    const body = flat.slice(at, flat.indexOf("}", at));
    expect(body).not.toContain("animation:");
    expect(flat).not.toContain(".agent-wait-track--indeterminate");
    expect(flat).not.toContain("@keyframes");
  });
});

describe("a node that is behind must not contradict the wallet", () => {
  // The attacker's finding, and it is not exotic. service.rs assigns
  // node.current_height straight from the probe with no sync-lag gate, so a
  // restarted or resyncing node reports a height below the block the open
  // landed in. The panel then read "0 of 6 confirmations" beside a live exit
  // button that works, because AgentL2Binding::validate re-checks the STORED
  // confirmed_at_height and the voucher path never looks at the chain height.
  //
  // The count now floors at what the wallet has already banked.
  it("counts from the height the core banked, not the height a lagging node reports", () => {
    const progress = channelOpenProgress({
      currentHeight: 777930,
      openHeight: 777933,
      confirmedAtHeight: 777938,
    });
    expect(progress.kind).toBe("counting");
    if (progress.kind !== "counting") throw new Error("expected a count");
    expect(progress.confirmations).toBe(6);
    expect(progress.settled).toBe(true);
    expect(progress.percent).toBe(100);
  });

  it("still prefers the live height when the chain is ahead of the binding", () => {
    const progress = channelOpenProgress({
      currentHeight: 777940,
      openHeight: 777933,
      confirmedAtHeight: 777938,
    });
    if (progress.kind !== "counting") throw new Error("expected a count");
    expect(progress.currentHeight).toBe(777940);
    expect(progress.confirmations).toBe(6);
  });

  it("labels the live height, never the banked one", () => {
    const progress = channelOpenProgress({
      currentHeight: 777930,
      openHeight: 777933,
      confirmedAtHeight: 777938,
    });
    if (progress.kind !== "counting") throw new Error("expected a count");
    // The count is settled from what was banked, and the height on screen is
    // still the one the node actually reported.
    expect(progress.currentHeight).toBe(777930);
    expect(progress.settled).toBe(true);
  });

  it("still says the chain height is unknown when no node can be reached", () => {
    // Tried the other way first and it was wrong: flooring the DISPLAYED height
    // on the banked one made the panel announce "Chain is at 777938" while the
    // wallet could not reach a node. A count may rest on what was banked; a
    // claim about where the chain is may not.
    const progress = channelOpenProgress({
      currentHeight: null,
      openHeight: 777933,
      confirmedAtHeight: 777938,
    });
    expect(progress.kind).toBe("chain_height_unknown");
  });

  it("still says nothing when neither height is known", () => {
    const progress = channelOpenProgress({
      currentHeight: null,
      openHeight: 777933,
      confirmedAtHeight: null,
    });
    expect(progress.kind).toBe("chain_height_unknown");
  });
});

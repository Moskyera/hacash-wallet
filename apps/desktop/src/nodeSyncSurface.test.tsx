// @vitest-environment jsdom
/**
 * WHAT A SYNC IS ALLOWED TO PUT ON A SCREEN WHILE IT IS STILL RUNNING.
 *
 * The owner asked for a loading state, and they were right that seven minutes
 * of silence loses people. But the failure this screen exists to prevent is
 * exactly the one a spinner would deepen: during a sync a real mainnet
 * catch-up and a node that has quietly started a private chain of its own look
 * identical, because both show a climbing height. A spinner turns the same way
 * for both.
 *
 * So these tests are not about a bar being pretty. They are about four things
 * that must hold no matter what the node says:
 *
 *   1. The chain answer is rendered BEFORE the percentage, in the DOM, so it
 *      is also what a screen reader reaches first.
 *   2. No percentage exists unless the node supplied both numbers it is made
 *      of. One reading is not enough, and a missing tip timestamp is not zero.
 *   3. A block one that does not match produces a warning and no progress
 *      element at all. Not a slower bar. No bar.
 *   4. The changing line is announced, and every fact survives without sight.
 */
import { describe, expect, it, vi } from "vitest";
import type { NodeSupervisorReport } from "./api";
import { mountComponent, settle } from "./domHarness";
import {
  estimateSyncTarget,
  nodeSyncView,
  recordSyncSample,
  syncVerdictFromAnchor,
  type SyncSample,
} from "@hacash/wallet-ui";

vi.mock("@tauri-apps/api/core", () => ({
  invoke: vi.fn(async () => undefined),
}));

const { default: NodeSupervisorPanel } = await import("./components/NodeSupervisorPanel");

const MAINNET_BLOCK_ONE =
  "001e231cb03f9938d54f04407797b8188f0375eb10f0bcb426dccae87dcadb56";
const SOMEBODY_ELSES_BLOCK_ONE =
  "beef231cb03f9938d54f04407797b8188f0375eb10f0bcb426dccae87dcadbff";

/** Mainnet blocks were spaced 300 seconds apart across the run these use. */
const BLOCK_SECONDS = 300;

const BASE: NodeSupervisorReport = {
  state: "catching_up",
  ours: true,
  headline: "Catching up",
  detail: "This node is still downloading.",
  binary: {
    path: null,
    source: null,
    version: null,
    database_type: null,
    searched: [],
    picked_path: null,
    picked_problem: null,
  },
  api_url: "http://127.0.0.1:8080",
  api_port: 8080,
  p2p_port: 3337,
  data_dir: "C:\\chain",
  config_path: "C:\\node\\hacash.config.ini",
  config: null,
  height: null,
  tip_age_seconds: null,
  max_tip_age_seconds: 3600,
  tip_timestamp_unix: null,
  observed_unix: null,
  fresh: false,
  anchor: "unknown",
  watching: "Nothing has been read from this node yet.",
  peer_role: null,
  peers_inbound: null,
  peers_outbound: null,
  reach: null,
  exit_code: null,
  last_error_lines: [],
  stopped_hard: false,
  can_start: false,
  can_stop: true,
  offers: [],
  api_port_holder: { holder: "not_checked" },
};

/**
 * A run of readings the way the panel really collects them: one per poll,
 * every three seconds, each one the node describing itself.
 *
 * `tipAge` falls as the node ingests, `tipTimestamp` climbs by one block
 * interval per block, and `observedUnix` is the node's own clock. Nothing in
 * here is a constant the wallet decided.
 */
function catchingUpRun(
  polls: number,
  start = { height: 700_000, tipAge: 22_950_000, observed: 1_800_000_000 },
): NodeSupervisorReport[] {
  const blocksPerPoll = 400;
  const secondsPerPoll = 3;
  const reports: NodeSupervisorReport[] = [];
  for (let index = 0; index < polls; index += 1) {
    const height = start.height + blocksPerPoll * index;
    const observed = start.observed + secondsPerPoll * index;
    const tipAge = start.tipAge - blocksPerPoll * BLOCK_SECONDS * index + secondsPerPoll * index;
    reports.push({
      ...BASE,
      height,
      tip_age_seconds: tipAge,
      tip_timestamp_unix: observed - tipAge,
      observed_unix: observed,
      anchor: "confirmed",
      watching: `Watching Hacash mainnet. This node's block one is ${MAINNET_BLOCK_ONE}, which is the one this wallet was built with, on chain 0.`,
    });
  }
  return reports;
}

/**
 * Drive the panel through a run of polls, exactly as the interval does, and
 * hand back the DOM at the end. The panel is what is measured, not a string
 * helper, because the defect this guards against is a screen that reassures.
 */
async function screenAfter(reports: NodeSupervisorReport[]): Promise<HTMLElement> {
  const core = await import("@tauri-apps/api/core");
  let next = 0;
  vi.mocked(core.invoke).mockImplementation(async () => {
    const report = reports[Math.min(next, reports.length - 1)];
    next += 1;
    return report as never;
  });
  const mounted = mountComponent(<NodeSupervisorPanel onInfo={() => {}} onError={() => {}} />);
  await settle();
  for (let index = 1; index < reports.length; index += 1) {
    vi.advanceTimersByTime(3000);
    await settle();
  }
  return mounted.container;
}

describe("the sync surface", () => {
  it("answers which chain BEFORE it shows any percentage", async () => {
    vi.useFakeTimers();
    try {
      const container = await screenAfter(catchingUpRun(6));
      const chain = container.querySelector('[data-testid="node-sync-chain"]');
      const distance = container.querySelector('[data-testid="node-sync-distance"]');
      expect(chain).toBeTruthy();
      expect(distance).toBeTruthy();
      // A percentage did get produced by this run, so the ordering claim is
      // about a real percentage rather than about an empty screen.
      expect(distance?.textContent).toMatch(/percent of the way there/);
      // Node.DOCUMENT_POSITION_FOLLOWING === 4: `distance` comes after `chain`.
      expect(chain!.compareDocumentPosition(distance!) & 4).toBe(4);
    } finally {
      vi.useRealTimers();
    }
  });

  it("shows no percentage and nothing that fills from a single reading", async () => {
    vi.useFakeTimers();
    try {
      const container = await screenAfter(catchingUpRun(1));
      const distance = container.querySelector('[data-testid="node-sync-distance"]');
      expect(distance?.textContent).toContain("At block 700,000");
      expect(distance?.textContent).toContain("not known yet");
      expect(distance?.textContent).not.toMatch(/\d+ percent/);
      // The one gate on anything that fills.
      expect(container.querySelector('[data-testid="node-sync-track"]')).toBeNull();
      expect(container.querySelector(".node-sync-fill")).toBeNull();
      // And it says so rather than inventing a time.
      expect(container.querySelector('[data-testid="node-sync-eta"]')?.textContent).toContain(
        "Working out how long",
      );
    } finally {
      vi.useRealTimers();
    }
  });

  it("shows no percentage when the node never said how old its newest block is", async () => {
    vi.useFakeTimers();
    try {
      // A node on the older capability contract: a height, and no freshness
      // block at all. A height with no denominator is not five percent of
      // anything, and the old code path would have been free to call it zero.
      const blind = catchingUpRun(6).map((report) => ({
        ...report,
        tip_age_seconds: null,
        tip_timestamp_unix: null,
        observed_unix: null,
      }));
      const container = await screenAfter(blind);
      const distance = container.querySelector('[data-testid="node-sync-distance"]');
      expect(distance?.textContent).not.toMatch(/\d+ percent/);
      expect(container.querySelector('[data-testid="node-sync-track"]')).toBeNull();
    } finally {
      vi.useRealTimers();
    }
  });

  it("turns a block one that does not match into a warning, not a spinner", async () => {
    vi.useFakeTimers();
    try {
      // The same climbing height as a healthy sync, on a chain that is not
      // ours. This is the case the owner would have watched a spinner over.
      const wrong = catchingUpRun(6).map((report) => ({
        ...report,
        anchor: "wrong" as const,
        watching: `This node's block one is ${SOMEBODY_ELSES_BLOCK_ONE}. Hacash mainnet's block one is ${MAINNET_BLOCK_ONE}. This is not Hacash mainnet and money sent on this chain reaches nobody.`,
      }));
      const container = await screenAfter(wrong);
      const sync = container.querySelector('[data-testid="node-sync"]');
      expect(sync?.getAttribute("data-chain")).toBe("mismatched");

      const chain = container.querySelector('[data-testid="node-sync-chain"]');
      expect(chain?.className).toContain("tone-bad");
      expect(chain?.textContent).toContain(SOMEBODY_ELSES_BLOCK_ONE);
      expect(chain?.textContent).toContain("reaches nobody");

      // NOTHING THAT FILLS. Not a slower bar: no bar.
      expect(container.querySelector('[data-testid="node-sync-track"]')).toBeNull();
      expect(container.querySelector(".node-sync-fill")).toBeNull();
      expect(container.querySelector('[role="progressbar"]')).toBeNull();

      // And no percentage, even though every number needed for one is present.
      expect(container.textContent).not.toMatch(/percent of the way there/);
      expect(
        container.querySelector('[data-testid="node-sync-distance"]')?.textContent,
      ).toContain("progress toward the wrong chain is not progress");

      // No estimate of a finish either, because finishing does not help.
      expect(container.querySelector('[data-testid="node-sync-eta"]')?.textContent).toContain(
        "would not put you on Hacash mainnet",
      );
    } finally {
      vi.useRealTimers();
    }
  });

  it("announces the changing line and keeps every fact in the text", async () => {
    vi.useFakeTimers();
    try {
      const container = await screenAfter(catchingUpRun(6));
      const live = container.querySelector('[data-testid="node-sync-live"]');
      expect(live?.getAttribute("aria-live")).toBe("polite");
      expect(
        container.querySelector('[data-testid="node-sync-chain"]')?.getAttribute("role"),
      ).toBe("status");

      const bar = container.querySelector('[data-testid="node-sync-track"]');
      expect(bar?.getAttribute("role")).toBe("progressbar");
      expect(bar?.getAttribute("aria-valuenow")).toMatch(/^\d+$/);
      expect(bar?.getAttribute("aria-valuemin")).toBe("0");
      expect(bar?.getAttribute("aria-valuemax")).toBe("100");

      // Strip every element and the three answers are still all there.
      const spoken = container.textContent ?? "";
      expect(spoken).toContain("Hacash mainnet");
      expect(spoken).toMatch(/Block [\d,]+ of about [\d,]+/);
      expect(spoken).toMatch(/percent of the way there/);
      expect(spoken).toMatch(/left, worked out from the last/);
    } finally {
      vi.useRealTimers();
    }
  });

  it("does not print the height twice while the sync block is on screen", async () => {
    vi.useFakeTimers();
    try {
      const container = await screenAfter(catchingUpRun(6));
      expect(container.querySelector('[data-testid="node-progress"]')).toBeNull();
      expect(container.querySelector('[data-testid="node-watching"]')).toBeNull();
    } finally {
      vi.useRealTimers();
    }
  });
});

describe("the numbers behind the percentage", () => {
  function sample(height: number, observed: number, tipAge: number): SyncSample {
    return {
      height,
      observedUnix: observed,
      tipAgeSeconds: tipAge,
      tipTimestampUnix: observed - tipAge,
    };
  }

  it("measures the block interval from the node rather than assuming one", () => {
    // A chain whose blocks are 60 seconds apart, not the 300 mainnet uses.
    // Nothing compiled in may be allowed to decide this.
    const first = sample(1_000, 1_800_000_000, 60_000);
    const last = sample(1_100, 1_800_000_010, 54_010);
    const estimate = estimateSyncTarget([first, last]);
    expect(estimate).not.toBeNull();
    expect(estimate!.blockSeconds).toBeCloseTo(60, 5);
    // 54,010 seconds behind at 60 seconds a block is about 900 blocks.
    expect(estimate!.blocksBehind).toBe(900);
    expect(estimate!.targetHeight).toBe(2_000);
    expect(estimate!.percent).toBe(55);
  });

  it("refuses to produce anything from one reading", () => {
    expect(estimateSyncTarget([sample(1_000, 1_800_000_000, 60_000)])).toBeNull();
  });

  it("refuses to produce anything from a window too short to have measured", () => {
    const first = sample(1_000, 1_800_000_000, 60_000);
    const near = sample(1_020, 1_800_000_002, 58_802);
    expect(estimateSyncTarget([first, near])).toBeNull();
  });

  it("says it is not gaining rather than inventing a finishing time", () => {
    // Ten blocks taken in over 600 seconds on a chain that adds one every 60:
    // the gap is not closing, and no number of minutes is honest here.
    const first = sample(1_000, 1_800_000_000, 60_000);
    const last = sample(1_010, 1_800_000_600, 60_000);
    const estimate = estimateSyncTarget([first, last]);
    expect(estimate).not.toBeNull();
    expect(estimate!.secondsLeft).toBeNull();

    const view = nodeSyncView(
      { verdict: "matched", chainSentence: "Checked.", height: 1_010 },
      [first, last],
    );
    expect(view.remaining.known).toBe(false);
    expect(view.remaining.text).toContain("Not gaining on the tip yet");
    // Still a real percentage: the distance is measured even when the time is not.
    expect(view.distance.percent).not.toBeNull();
  });

  it("starts the run again when the height goes backwards", () => {
    // A restart or a reorg is not slow progress, and averaging across it would
    // produce a negative rate and then a nonsense estimate.
    const history = [sample(1_000, 1_800_000_000, 60_000)];
    const after = recordSyncSample(history, sample(200, 1_800_000_030, 90_000));
    expect(after).toHaveLength(1);
    expect(after[0].height).toBe(200);
  });

  it("maps the supervisor's own anchor rather than deciding the chain twice", () => {
    expect(syncVerdictFromAnchor("confirmed")).toBe("matched");
    expect(syncVerdictFromAnchor("wrong")).toBe("mismatched");
    expect(syncVerdictFromAnchor("not_yet_available")).toBe("unestablished");
    expect(syncVerdictFromAnchor("unknown")).toBe("unknown");
  });

  it("never puts a bar under a chain that has not been established", () => {
    // The trap, in its purest form: a node alone on a private chain is a
    // hundred percent of the way to its own tip. Every number needed for a bar
    // is present and the bar would be true, meaningless and reassuring.
    const first = sample(1_000, 1_800_000_000, 60_000);
    const last = sample(1_100, 1_800_000_010, 54_010);
    expect(estimateSyncTarget([first, last])).not.toBeNull();

    const view = nodeSyncView(
      {
        verdict: "unestablished",
        chainSentence: "This node has no block one and has connected to 0 boot nodes.",
        height: 1_100,
      },
      [first, last],
    );
    expect(view.chain.tone).toBe("warn");
    expect(view.showsBar).toBe(false);
    expect(view.distance.percent).toBeNull();
    // The height is still said out loud. It is a fact; it is just not progress.
    expect(view.distance.text).toContain("At block 1,100");
    expect(view.distance.text).toContain("which chain that height is on");
    expect(view.remaining.known).toBe(false);
  });
});

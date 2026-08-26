// @vitest-environment jsdom
/**
 * THE SAME THREE LINES, ON THE PHONE.
 *
 * The phone reads a node rather than running one, and that changes nothing
 * about which question has to be answered first. A remote node can be behind,
 * and a remote node can be on a chain that is not Hacash mainnet, and both look
 * from here like a wallet that is merely slow.
 *
 * These are the same four claims the desktop suite makes, made against the
 * phone's own screen: chain before percentage, no percentage without both
 * numbers, a mismatch as a warning rather than a spinner, and the changing
 * line announced.
 */
import { readFileSync } from "node:fs";
import { join } from "node:path";
import type { NodeCapabilities } from "@hacash/wallet-ui";
import { describe, expect, it, vi } from "vitest";
import { mountComponent, settle } from "./domHarness";

vi.mock("@tauri-apps/api/core", () => ({
  invoke: vi.fn(async () => undefined),
}));

const { default: NodeSyncSection } = await import("./components/NodeSyncSection");

const MAINNET_BLOCK_ONE =
  "001e231cb03f9938d54f04407797b8188f0375eb10f0bcb426dccae87dcadb56";
const SOMEBODY_ELSES_BLOCK_ONE =
  "beef231cb03f9938d54f04407797b8188f0375eb10f0bcb426dccae87dcadbff";

const BLOCK_SECONDS = 300;

function capabilities(options: {
  height: number;
  observed: number;
  tipAge: number;
  blockOne?: string | null;
  blockOneAvailable?: boolean;
}): NodeCapabilities {
  return {
    ret: 0,
    api_version: 1,
    node: { name: "hacash-fullnode", version: "1.0.10", build_time: "" },
    chain: {
      id: 0,
      height: options.height,
      next_height: options.height + 1,
      mainnet: true,
    },
    network: {
      kind: "mainnet",
      node_profile_id: "hacash-mainnet",
      block_1_available: options.blockOneAvailable ?? true,
      block_1_hash: options.blockOne === undefined ? MAINNET_BLOCK_ONE : options.blockOne,
      instance_id: null,
      funding_confirmed: true,
      transaction_ready: true,
      current_height: options.height,
      transaction_format_version: 1,
    },
    sync: {
      tip_timestamp_unix: options.observed - options.tipAge,
      observed_unix: options.observed,
      tip_age_seconds: options.tipAge,
      max_tip_age_seconds: 3600,
      fresh: options.tipAge < 3600,
    },
    istanbul: { activation_height: 0, evaluation_height: options.height + 1, active: true },
    transactions: { registered: [1, 2, 3], enabled: [1, 2, 3] },
    actions: { registered: [1], enabled: [1] },
    features: {
      action_guard: true,
      tx_blob: true,
      ast: true,
      tex: true,
      native_assets: true,
      hip20_primitives: true,
      hip20: true,
      hvm: true,
      p2sh: true,
      account_abstraction: true,
      intent: true,
      contract_state_leasing: true,
      ir_decompilation: true,
      req_sign_list: true,
      type4_mainnet: true,
      exact_unsigned_simulation: true,
    },
    limits: {
      max_tx_size: 1024,
      max_tx_actions: 32,
      max_type3_signers: 8,
      gas_max_byte: 255,
      gas_max: 1_000_000,
      ast_depth: 32,
    },
    source: "reported",
  } as NodeCapabilities;
}

/** A run of readings, one per poll, the way the section really collects them. */
function run(polls: number, overrides: Partial<Parameters<typeof capabilities>[0]> = {}) {
  const blocksPerPoll = 400;
  const secondsPerPoll = 5;
  const answers: NodeCapabilities[] = [];
  for (let index = 0; index < polls; index += 1) {
    answers.push(
      capabilities({
        height: 700_000 + blocksPerPoll * index,
        observed: 1_800_000_000 + secondsPerPoll * index,
        tipAge: 22_950_000 - blocksPerPoll * BLOCK_SECONDS * index + secondsPerPoll * index,
        ...overrides,
      }),
    );
  }
  return answers;
}

async function screenAfter(answers: NodeCapabilities[]): Promise<HTMLElement> {
  const core = await import("@tauri-apps/api/core");
  let next = 0;
  vi.mocked(core.invoke).mockImplementation(async () => {
    const answer = answers[Math.min(next, answers.length - 1)];
    next += 1;
    return answer as never;
  });
  const mounted = mountComponent(<NodeSyncSection />);
  await settle();
  for (let index = 1; index < answers.length; index += 1) {
    vi.advanceTimersByTime(5000);
    await settle();
  }
  return mounted.container;
}

describe("the sync surface on the phone", () => {
  it("answers which chain BEFORE it shows any percentage", async () => {
    vi.useFakeTimers();
    try {
      const container = await screenAfter(run(4));
      const chain = container.querySelector('[data-testid="node-sync-chain"]');
      const distance = container.querySelector('[data-testid="node-sync-distance"]');
      expect(chain?.textContent).toContain(MAINNET_BLOCK_ONE);
      expect(distance?.textContent).toMatch(/percent of the way there/);
      expect(chain!.compareDocumentPosition(distance!) & 4).toBe(4);
    } finally {
      vi.useRealTimers();
    }
  });

  it("says what it is waiting on instead of spinning before the first answer", async () => {
    const core = await import("@tauri-apps/api/core");
    vi.mocked(core.invoke).mockImplementation(() => new Promise(() => {}));
    const mounted = mountComponent(<NodeSyncSection />);
    await settle();
    expect(mounted.container.textContent).toContain("Asking this node which chain it is on");
    expect(mounted.container.querySelector('[data-testid="node-sync-track"]')).toBeNull();
    mounted.unmount();
  });

  it("shows no percentage and nothing that fills from a single reading", async () => {
    vi.useFakeTimers();
    try {
      const container = await screenAfter(run(1));
      const distance = container.querySelector('[data-testid="node-sync-distance"]');
      expect(distance?.textContent).toContain("At block 700,000");
      expect(distance?.textContent).not.toMatch(/\d+ percent/);
      expect(container.querySelector('[data-testid="node-sync-track"]')).toBeNull();
      expect(container.querySelector('[data-testid="node-sync-eta"]')?.textContent).toContain(
        "Working out how long",
      );
    } finally {
      vi.useRealTimers();
    }
  });

  it("turns a block one that does not match into a warning, not a spinner", async () => {
    vi.useFakeTimers();
    try {
      const container = await screenAfter(run(4, { blockOne: SOMEBODY_ELSES_BLOCK_ONE }));
      expect(container.querySelector('[data-testid="node-sync"]')?.getAttribute("data-chain")).toBe(
        "mismatched",
      );
      const chain = container.querySelector('[data-testid="node-sync-chain"]');
      expect(chain?.className).toContain("tone-bad");
      expect(chain?.textContent).toContain("reaches nobody");
      expect(container.querySelector('[role="progressbar"]')).toBeNull();
      expect(container.querySelector(".node-sync-fill")).toBeNull();
      expect(container.textContent).not.toMatch(/percent of the way there/);
    } finally {
      vi.useRealTimers();
    }
  });

  it("draws no bar while the node has produced no block one to compare", async () => {
    vi.useFakeTimers();
    try {
      const container = await screenAfter(
        run(4, { blockOneAvailable: false, blockOne: null }),
      );
      expect(container.querySelector('[data-testid="node-sync"]')?.getAttribute("data-chain")).toBe(
        "unestablished",
      );
      // A node alone on a private chain is at the top of its own chain, and a
      // bar saying so would be true, meaningless and reassuring.
      expect(container.querySelector('[data-testid="node-sync-track"]')).toBeNull();
      expect(container.textContent).toContain("climbing height proves nothing");
    } finally {
      vi.useRealTimers();
    }
  });

  it("announces the changing line", async () => {
    vi.useFakeTimers();
    try {
      const container = await screenAfter(run(4));
      expect(
        container.querySelector('[data-testid="node-sync-live"]')?.getAttribute("aria-live"),
      ).toBe("polite");
      const bar = container.querySelector('[data-testid="node-sync-track"]');
      expect(bar?.getAttribute("role")).toBe("progressbar");
      expect(bar?.getAttribute("aria-valuenow")).toMatch(/^\d+$/);
    } finally {
      vi.useRealTimers();
    }
  });
});

/**
 * The two apps draw this from two files, because packages/wallet-ui is
 * hardlinked into each app's node_modules and a new file there would reach
 * neither app. Two files is how the shape drifts, so the drift is a test
 * failure rather than a thing somebody notices in a screenshot months later.
 */
describe("desktop and phone draw the same shape", () => {
  it("keeps NodeSyncProgress byte-identical in both apps", () => {
    // Resolved from the working directory rather than import.meta.url: this
    // file runs under jsdom, where import.meta.url is an http URL and
    // fileURLToPath refuses it.
    const here = process.cwd();
    const phone = readFileSync(
      join(here, "src", "components", "NodeSyncProgress.tsx"),
      "utf8",
    );
    const desktop = readFileSync(
      join(here, "..", "desktop", "src", "components", "NodeSyncProgress.tsx"),
      "utf8",
    );
    expect(phone).toEqual(desktop);
  });
});

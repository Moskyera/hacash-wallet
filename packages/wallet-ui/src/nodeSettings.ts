export const OFFICIAL_NODE_URL = "http://nodeapi.hacash.org";

const OFFICIAL_NODE_HOSTS = new Set(["nodeapi.hacash.org", "nodeapi.org"]);

export function isOfficialNodeUrl(value: string): boolean {
  const raw = value.trim();
  if (!raw) return false;

  const hasScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(raw);
  if (!hasScheme && raw.startsWith("/")) return false;
  const candidate = hasScheme ? raw : `http://${raw}`;

  let url: URL;
  try {
    url = new URL(candidate);
  } catch {
    return false;
  }

  return (
    (url.protocol === "http:" || url.protocol === "https:") &&
    OFFICIAL_NODE_HOSTS.has(url.hostname.toLowerCase()) &&
    url.username === "" &&
    url.password === "" &&
    url.port === "" &&
    url.pathname === "/" &&
    url.search === "" &&
    url.hash === ""
  );
}

/* ---------------------------------------------------------------------------
 * WHAT A NODE SYNC IS ALLOWED TO SAY WHILE IT IS STILL RUNNING.
 *
 * A Hacash sync took about seven minutes on the machine this was built
 * against, and can take far longer. For that whole time a real mainnet
 * catch-up and a node that has quietly started a private chain of its own look
 * the same: both show a climbing height. That is the trap written up in
 * docs/l2/YOUR-FIRST-MAINNET-CHANNEL.md, and it costs days because nothing
 * reports it.
 *
 * A spinner would make that worse. It turns identically in both cases, for
 * seven minutes, and it would cover the one moment the mistake is still cheap
 * to catch. So the sync surface is three lines, in this order:
 *
 *   1. Which chain, and whether it matched. Answerable the moment the node
 *      answers at all, from the block one hash this wallet pins.
 *   2. How far along, in the node's own numbers.
 *   3. How much longer, and only when it can be measured.
 *
 * Two rules hold this together and neither may be softened:
 *
 *   - Nothing animates over an unknown. No percentage exists unless both the
 *     height and a denominator do; when there is no denominator the surface
 *     says the distance is not known rather than drawing a bar with a guess in
 *     it.
 *   - Every number that reaches a percentage came out of the node. There is no
 *     compiled-in block interval here. The seconds per block are measured
 *     across exactly the blocks this node just ingested, from two readings of
 *     its own tip timestamp, so a chain that mines at a different rate than
 *     whoever wrote this expected still gets an honest denominator.
 *
 * This lives in an existing wallet-ui file on purpose. The package is
 * hardlinked into each app's node_modules, so an edit to an existing file
 * reaches both apps and a new file would reach neither.
 * ------------------------------------------------------------------------- */

/** What the block one comparison decided, before any height is believed. */
export type SyncChainVerdict = "matched" | "mismatched" | "unestablished" | "unknown";

export type SyncTone = "ok" | "warn" | "bad" | "idle";

/** The mainnet block one this wallet was built with. Pinned, never fetched. */
export const MAINNET_BLOCK_ONE_HASH =
  "001e231cb03f9938d54f04407797b8188f0375eb10f0bcb426dccae87dcadb56";

export const MAINNET_CHAIN_NAME = "Hacash mainnet";

/**
 * One reading of a node, in the node's own numbers.
 *
 * `observedUnix` is the node's clock at the moment it answered, not this
 * computer's, so a skewed desktop clock cannot push a percentage around.
 */
export type SyncSample = {
  height: number;
  tipTimestampUnix: number;
  observedUnix: number;
  tipAgeSeconds: number;
};

/**
 * How long a run of readings has to span before it may produce a number.
 * Under this, two polls apart, the measured block interval is one block's
 * jitter and the estimate would swing between refreshes.
 */
export const MIN_SYNC_WINDOW_SECONDS = 8;

/** Readings older than this are dropped: a sync that speeds up should show it. */
export const MAX_SYNC_WINDOW_SECONDS = 600;

/**
 * Sanity bounds on a measured block interval. Outside these the reading is not
 * a measurement of a chain: it is an archive replay or a clock that jumped,
 * and no estimate is offered rather than a wrong one.
 */
const MIN_PLAUSIBLE_BLOCK_SECONDS = 1;
const MAX_PLAUSIBLE_BLOCK_SECONDS = 86_400;

/**
 * Keep the history an estimate is measured over.
 *
 * A height that went backwards is not slow progress. It is a restart, another
 * node, or a reorg, so the run starts again rather than averaging across the
 * discontinuity.
 */
export function recordSyncSample(history: SyncSample[], sample: SyncSample): SyncSample[] {
  const previous = history[history.length - 1];
  if (!previous) return [sample];
  if (sample.height < previous.height) return [sample];
  if (sample.observedUnix < previous.observedUnix) return [sample];
  if (sample.height === previous.height && sample.observedUnix === previous.observedUnix) {
    return history;
  }
  const next = [...history, sample];
  while (
    next.length > 2 &&
    next[next.length - 1].observedUnix - next[0].observedUnix > MAX_SYNC_WINDOW_SECONDS
  ) {
    next.shift();
  }
  return next;
}

export type SyncEstimate = {
  /** The height the node is heading for. Derived from readings, not declared. */
  targetHeight: number;
  blocksBehind: number;
  /** 0 to 100. Only ever produced when both heights exist. */
  percent: number;
  /** Seconds per block, measured across the blocks just taken in. */
  blockSeconds: number;
  /** How long the run of readings this was measured over spans. */
  windowSeconds: number;
  blocksIngested: number;
  /** How many blocks the chain itself added during the same window. */
  chainBlocksAdded: number;
  /**
   * Seconds until this node reaches the tip, or null when it is not closing
   * the gap at all. Null is said out loud rather than smoothed into a number.
   */
  secondsLeft: number | null;
};

/**
 * Turn a run of readings into a target height, a percentage and a time.
 *
 * Nothing here is a constant about Hacash. `blockSeconds` is the node's own
 * tip timestamp moving divided by its own height moving, which is the average
 * spacing of exactly the blocks it just validated. `blocksBehind` is the age
 * of its newest block divided by that spacing. The node supplied every term.
 */
export function estimateSyncTarget(history: SyncSample[]): SyncEstimate | null {
  if (history.length < 2) return null;
  const first = history[0];
  const last = history[history.length - 1];

  const windowSeconds = last.observedUnix - first.observedUnix;
  if (windowSeconds < MIN_SYNC_WINDOW_SECONDS) return null;

  const blocksIngested = last.height - first.height;
  if (blocksIngested <= 0) return null;

  const tipSeconds = last.tipTimestampUnix - first.tipTimestampUnix;
  if (tipSeconds <= 0) return null;

  const blockSeconds = tipSeconds / blocksIngested;
  if (
    !Number.isFinite(blockSeconds) ||
    blockSeconds < MIN_PLAUSIBLE_BLOCK_SECONDS ||
    blockSeconds > MAX_PLAUSIBLE_BLOCK_SECONDS
  ) {
    return null;
  }

  const blocksBehind = Math.max(0, Math.round(last.tipAgeSeconds / blockSeconds));
  const targetHeight = last.height + blocksBehind;
  if (targetHeight <= 0) return null;
  const percent = Math.min(100, Math.max(0, Math.floor((last.height / targetHeight) * 100)));

  const ingestPerSecond = blocksIngested / windowSeconds;
  const tipAdvancePerSecond = 1 / blockSeconds;
  const closingPerSecond = ingestPerSecond - tipAdvancePerSecond;
  let secondsLeft: number | null = null;
  if (blocksBehind === 0) {
    secondsLeft = 0;
  } else if (closingPerSecond > 0) {
    secondsLeft = Math.round(blocksBehind / closingPerSecond);
  }

  return {
    targetHeight,
    blocksBehind,
    percent,
    blockSeconds,
    windowSeconds,
    blocksIngested,
    chainBlocksAdded: windowSeconds / blockSeconds,
    secondsLeft,
  };
}

/** Plain words for a span of seconds. */
export function describeSyncDuration(seconds: number): string {
  if (seconds < 1) return "less than a second";
  if (seconds < 90) return `${Math.round(seconds)} seconds`;
  if (seconds < 5400) return `${Math.round(seconds / 60)} minutes`;
  if (seconds < 172800) return `${Math.round(seconds / 3600)} hours`;
  return `${Math.round(seconds / 86400)} days`;
}

function count(value: number): string {
  return Math.round(value).toLocaleString("en-US");
}

/**
 * The block one comparison, done against the hash this wallet pins.
 *
 * This is the first-second question. It does not wait for a sync, it does not
 * need a height, and it is the only thing on this surface that decides whether
 * any of the waiting is worth doing.
 */
export function syncChainVerdict(input: {
  blockOneAvailable: boolean;
  blockOneHash: string | null | undefined;
  chainId?: number | null;
  mainnet?: boolean | null;
  expectedBlockOneHash?: string;
}): SyncChainVerdict {
  const expected = (input.expectedBlockOneHash ?? MAINNET_BLOCK_ONE_HASH).toLowerCase();
  if (!input.blockOneAvailable) return "unestablished";
  const seen = input.blockOneHash?.toLowerCase();
  if (!seen) return "unestablished";
  if (seen !== expected) return "mismatched";
  if (input.chainId != null && input.chainId !== 0) return "mismatched";
  if (input.mainnet === false) return "mismatched";
  return "matched";
}

/**
 * The desktop supervisor already decided this against the same pinned hash.
 * Its word is translated here, not taken again, so there is one source of
 * truth about the chain rather than two that can disagree on screen.
 */
export function syncVerdictFromAnchor(
  anchor: "confirmed" | "wrong" | "not_yet_available" | "unknown",
): SyncChainVerdict {
  switch (anchor) {
    case "confirmed":
      return "matched";
    case "wrong":
      return "mismatched";
    case "not_yet_available":
      return "unestablished";
    default:
      return "unknown";
  }
}

export function syncChainTone(verdict: SyncChainVerdict): SyncTone {
  switch (verdict) {
    case "matched":
      return "ok";
    case "mismatched":
      return "bad";
    case "unestablished":
      return "warn";
    default:
      return "idle";
  }
}

/**
 * The chain line, for a caller that does not already have a better one.
 *
 * The desktop supervisor writes its own, with boot node counts in it, and
 * passes that through instead. This is what the phone says, where the only
 * thing read is the node's capability answer.
 */
export function syncChainSentence(
  verdict: SyncChainVerdict,
  input: { blockOneHash?: string | null; chainName?: string; expectedBlockOneHash?: string } = {},
): string {
  const chain = input.chainName ?? MAINNET_CHAIN_NAME;
  const expected = input.expectedBlockOneHash ?? MAINNET_BLOCK_ONE_HASH;
  switch (verdict) {
    case "matched":
      return `Checked: this node is on ${chain}. Its block one is ${expected}, which is the one this wallet was built with.`;
    case "mismatched":
      return `This node is NOT on ${chain}. Its block one is ${input.blockOneHash ?? "not the one this wallet was built with"}, and ${chain} begins with ${expected}. A height climbing here is a chain of its own, and money sent on it reaches nobody.`;
    case "unestablished":
      return `Which chain this node is on has not been established yet: it has no block one to compare. A climbing height proves nothing until it does, because a node alone on a private chain climbs too.`;
    default:
      return "Nothing has been read from this node yet, so which chain it is on is not known.";
  }
}

export type NodeSyncInput = {
  verdict: SyncChainVerdict;
  /** The chain line, in whichever words the caller already has. */
  chainSentence: string;
  chainName?: string;
  height: number | null | undefined;
};

export type NodeSyncView = {
  chain: { verdict: SyncChainVerdict; tone: SyncTone; text: string };
  distance: {
    text: string;
    /** Null whenever a bar would be a guess. Nothing draws without this. */
    percent: number | null;
    atHeight: number | null;
    targetHeight: number | null;
  };
  remaining: { text: string; known: boolean };
  /** The single gate on drawing anything that fills, moves or animates. */
  showsBar: boolean;
};

/**
 * The three lines, assembled.
 *
 * The order of the fields here is the order on the screen and the order in the
 * DOM, because the chain answer is the one that decides whether the other two
 * matter, and a screen reader that hears the percentage first has been told
 * the least useful thing first.
 */
export function nodeSyncView(input: NodeSyncInput, history: SyncSample[] = []): NodeSyncView {
  const chainName = input.chainName ?? MAINNET_CHAIN_NAME;
  const verdict = input.verdict;
  const height = typeof input.height === "number" ? input.height : null;
  /*
   * A PERCENTAGE ONLY EXISTS ONCE THE CHAIN DOES.
   *
   * Not only for the wrong chain, where measuring how fast somebody is walking
   * in the wrong direction is useless. Also for a chain that has not been
   * identified yet: a node alone on a private chain of its own is a hundred
   * percent of the way to its own tip, and that number is true, meaningless and
   * reassuring, which is the worst combination a screen can offer. So the bar
   * arrives when block one does, and not before.
   */
  const estimate = verdict === "matched" ? estimateSyncTarget(history) : null;

  const chain = { verdict, tone: syncChainTone(verdict), text: input.chainSentence };

  if (verdict === "mismatched") {
    return {
      chain,
      distance: {
        text:
          height === null
            ? `No percentage is shown, because progress toward the wrong chain is not progress. Nothing this node reports is about ${chainName}.`
            : `This node is at block ${count(height)}, but that is a height on another chain. No percentage is shown, because progress toward the wrong chain is not progress.`,
        percent: null,
        atHeight: height,
        targetHeight: null,
      },
      remaining: {
        text: `No time is worked out. Waiting for this to finish would not put you on ${chainName}. Stop this node and point the wallet at one that is on the chain your money is on.`,
        known: false,
      },
      showsBar: false,
    };
  }

  if (height === null) {
    return {
      chain,
      distance: {
        text: "This node has not said what height it is at yet, so there is no percentage to show.",
        percent: null,
        atHeight: null,
        targetHeight: null,
      },
      remaining: { text: "Working out how long. It needs a height first.", known: false },
      showsBar: false,
    };
  }

  if (verdict !== "matched") {
    return {
      chain,
      distance: {
        text: `At block ${count(height)}. No percentage is shown while it is still unknown which chain that height is on, because a node alone on a chain of its own is at the top of it.`,
        percent: null,
        atHeight: height,
        targetHeight: null,
      },
      remaining: {
        text: `Working out how long comes after working out which chain. Until this node produces a block one to compare against ${chainName}, a finishing time would be a time to finish something nobody has identified.`,
        known: false,
      },
      showsBar: false,
    };
  }

  if (!estimate) {
    return {
      chain,
      distance: {
        text: `At block ${count(height)}. How far that is from the tip of the chain is not known yet, so no percentage is shown.`,
        percent: null,
        atHeight: height,
        targetHeight: null,
      },
      remaining: {
        text: "Working out how long. That needs two readings that both moved, and there is not enough measured progress yet.",
        known: false,
      },
      showsBar: false,
    };
  }

  const distanceText = `Block ${count(height)} of about ${count(estimate.targetHeight)}, which is ${estimate.percent} percent of the way there. About ${count(estimate.blocksBehind)} blocks still to go.`;

  const remaining =
    estimate.secondsLeft === null
      ? {
          text: `Not gaining on the tip yet. In the last ${describeSyncDuration(estimate.windowSeconds)} this node took in ${count(estimate.blocksIngested)} blocks while the chain added about ${count(estimate.chainBlocksAdded)}, so no finishing time can be worked out from that.`,
          known: false,
        }
      : {
          text: `About ${describeSyncDuration(estimate.secondsLeft)} left, worked out from the last ${describeSyncDuration(estimate.windowSeconds)} of measured progress, at about ${describeSyncDuration(estimate.blockSeconds)} per block.`,
          known: true,
        };

  return {
    chain,
    distance: {
      text: distanceText,
      percent: estimate.percent,
      atHeight: height,
      targetHeight: estimate.targetHeight,
    },
    remaining,
    showsBar: true,
  };
}

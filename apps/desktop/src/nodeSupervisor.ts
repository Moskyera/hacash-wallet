/**
 * WHAT THE SCREEN MAY SAY ABOUT THE NODE THIS WALLET RUNS.
 *
 * The measured cost of running a node today is 21 shell commands, 2 hand
 * written config files and 22 values a person has to understand rather than
 * copy. Bundling and supervising the node removes six of those in one move.
 * This pass builds the supervising half, so the state a person will mostly
 * land on right now is "there is no node here yet", and that state has to read
 * as an offer rather than as a fault.
 *
 * The sentences live here rather than in JSX for the same reason
 * `relayReach.ts` does: the risk in this feature is the copy. Four rules, and
 * the tests beside this file are what hold the screen to them.
 *
 * 1. A node this wallet did not start is never described as this wallet's.
 *    Foreign is a state with its own words and no stop button, not a footnote
 *    under Ready.
 * 2. The word "synced" is never printed on its own. It is printed as an age,
 *    with the node's own freshness budget beside it.
 * 3. During a sync, a real mainnet catch-up and a node alone on a private
 *    chain of its own look identical: both show a climbing height. So the
 *    screen always names which chain is being watched, by the pinned block one
 *    hash, and says so while the height is still climbing rather than after.
 * 4. Nothing here says the wallet ships a node, because it does not yet.
 */
import type { SyncSample } from "@hacash/wallet-ui";
import type { NodeSupervisorReport, NodeSupervisorState } from "./api";

export type Tone = "ok" | "warn" | "bad" | "idle" | "busy";

export type NodeSupervisorView = {
  state: NodeSupervisorState;
  tone: Tone;
  headline: string;
  /** Why this state, in the backend's own words, built from something read. */
  detail: string;
  /**
   * Which chain is being watched, named by its block one. Present in every
   * state where a height is being shown, because a height on its own is the
   * thing that cannot be told apart from a private chain.
   */
  watching: string | null;
  /** The progress line, with a number in it. Never a bare "please wait". */
  progress: string | null;
  /**
   * Ready means the wallet can trust this node about the chain. It does not
   * mean anybody can reach it, and these are never allowed to blur into one
   * green tick.
   */
  reach: string | null;
  /** Whose process this is, said out loud. */
  ownership: string;
  /** What can be pressed. */
  canStart: boolean;
  canStop: boolean;
  /** What is on offer when there is nothing to start. */
  offers: string[];
  /** Where the wallet looked for a node, and what it found. */
  searched: { path: string; verdict: string }[];
};

const TONES: Record<NodeSupervisorState, Tone> = {
  not_present: "idle",
  blocked: "warn",
  starting: "busy",
  catching_up: "busy",
  ready: "ok",
  foreign: "warn",
  failed: "bad",
  stopping: "busy",
  stopped: "idle",
};

/**
 * THE SENTENCE THAT SAYS WHOSE PROCESS IT IS.
 *
 * `ours` is set by one thing in the backend: a live child this process is
 * holding, whose own stdout said it took the API port. Everything else is
 * somebody else's, and this is where that stops being an implementation detail
 * and becomes something a person reads.
 */
export function ownershipSentence(report: NodeSupervisorReport): string {
  if (report.ours) {
    return "This wallet started this node and can stop it. It stops when you close the wallet.";
  }
  if (report.state === "foreign") {
    return "This wallet did not start this node, so it will not stop it and does not claim it. It can read it exactly as it reads any node you point it at.";
  }
  return "This wallet is not running a node.";
}

/**
 * The progress line, and the reason it always carries a number.
 *
 * A sync took about seven minutes on the machine this was built against and
 * can take considerably longer elsewhere. A screen that says "still catching
 * up" for seven minutes and nothing else is indistinguishable from a screen
 * that has stopped working, and a person who cannot tell the difference will
 * either wait forever or kill it.
 */
export function progressLine(report: NodeSupervisorReport): string | null {
  if (report.state === "catching_up") {
    const height = report.height ?? 0;
    const age = report.tip_age_seconds;
    if (age === null || age === undefined) {
      return `At block ${height.toLocaleString()}, and this node has not said how old its newest block is yet.`;
    }
    return `At block ${height.toLocaleString()}. Its newest block is ${describeAge(age)} old, and it counts anything under ${describeAge(report.max_tip_age_seconds ?? 3600)} as current.`;
  }
  if (report.state === "ready" && report.height !== null && report.height !== undefined) {
    return `At block ${report.height.toLocaleString()}, which arrived ${describeAge(report.tip_age_seconds ?? 0)} ago.`;
  }
  return null;
}

/**
 * One reading of the node, for the run a finishing time is measured over.
 *
 * All four numbers or none. A partial reading is not a cheaper reading, it is
 * a reading that would put a wrong denominator under a percentage, so it is
 * refused here rather than defaulted to zero somewhere further down.
 */
export function syncSampleOf(report: NodeSupervisorReport): SyncSample | null {
  const { height, tip_timestamp_unix, observed_unix, tip_age_seconds } = report;
  if (
    typeof height !== "number" ||
    typeof tip_timestamp_unix !== "number" ||
    typeof observed_unix !== "number" ||
    typeof tip_age_seconds !== "number"
  ) {
    return null;
  }
  return {
    height,
    tipTimestampUnix: tip_timestamp_unix,
    observedUnix: observed_unix,
    tipAgeSeconds: tip_age_seconds,
  };
}

export function describeAge(seconds: number): string {
  if (seconds < 90) return `${Math.round(seconds)} seconds`;
  if (seconds < 5400) return `${Math.round(seconds / 60)} minutes`;
  if (seconds < 172800) return `${Math.round(seconds / 3600)} hours`;
  return `${Math.round(seconds / 86400)} days`;
}

export function nodeSupervisorView(report: NodeSupervisorReport): NodeSupervisorView {
  // The anchor decides the tone during a sync, not the height. A climbing
  // height on an unanchored chain is the trap, so it is never allowed to look
  // like progress.
  let tone = TONES[report.state] ?? "idle";
  if (report.anchor === "wrong") tone = "bad";
  if (report.state === "catching_up" && report.anchor === "not_yet_available") tone = "warn";

  // The chain is named wherever a height is shown, and wherever a height is
  // absent because the chain is wrong.
  const showsWatching =
    report.state === "catching_up" ||
    report.state === "ready" ||
    report.anchor === "wrong" ||
    report.anchor === "not_yet_available";

  return {
    state: report.state,
    tone,
    headline: report.headline,
    detail: report.detail,
    watching: showsWatching ? report.watching : null,
    progress: progressLine(report),
    reach: report.state === "ready" || report.state === "catching_up" ? report.reach : null,
    ownership: ownershipSentence(report),
    canStart: report.can_start,
    canStop: report.can_stop,
    offers: report.offers ?? [],
    searched: (report.binary?.searched ?? []).map((entry) => ({
      path: entry.path,
      verdict: entry.verdict,
    })),
  };
}

/**
 * What the wallet is, and is not, promising about where this node came from.
 *
 * "The node we shipped with the wallet" and "the node you pointed us at" are
 * different promises. Blurring them would be the same lie as adopting a
 * foreign process, so the source is shown rather than hidden behind the word
 * "node".
 */
export function binaryProvenance(report: NodeSupervisorReport): string | null {
  const binary = report.binary;
  if (!binary?.path) return null;
  const version = binary.version ?? "a Hacash fullnode";
  switch (binary.source) {
    case "bundled":
      return `${version}, shipped inside this wallet, at ${binary.path}.`;
    case "picked":
      return `${version}, at ${binary.path}, which is the one you pointed this wallet at.`;
    case "found":
      return `${version}, found at ${binary.path}, where you or something else put it. This wallet did not put it there and cannot vouch for it.`;
    case "legacy":
      return `${version}, found at ${binary.path}, which is where the guide tells people to build one. This wallet did not put it there and cannot vouch for it.`;
    default:
      return `${version}, at ${binary.path}.`;
  }
}

// @vitest-environment jsdom
/**
 * WHAT THE NODE SCREEN ACTUALLY RENDERS, IN EVERY STATE.
 *
 * `relaySurface.test.tsx` reads the screen rather than the strings, and for the
 * same reason: the failure this feature can produce is not a wrong string in a
 * module somewhere, it is a person looking at a screen that tells them a node
 * is fine when it is on a chain of its own, or that a stranger's node is
 * theirs. So this renders the real component with the report the backend
 * really returns and reads the markup.
 */
import { describe, expect, it, vi } from "vitest";
import type { NodeSupervisorReport } from "./api";
import { mountComponent, settle } from "./domHarness";

vi.mock("@tauri-apps/api/core", () => ({
  invoke: vi.fn(async () => undefined),
}));

const { default: NodeSupervisorPanel } = await import("./components/NodeSupervisorPanel");

const MAINNET_BLOCK_ONE =
  "001e231cb03f9938d54f04407797b8188f0375eb10f0bcb426dccae87dcadb56";

const BASE: NodeSupervisorReport = {
  state: "stopped",
  ours: false,
  headline: "",
  detail: "",
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
  data_dir: "C:\\Users\\a\\AppData\\Local\\HacashWallet\\chain",
  config_path: "C:\\Users\\a\\AppData\\Roaming\\HacashWallet\\node\\hacash.config.ini",
  config: null,
  height: null,
  tip_age_seconds: null,
  max_tip_age_seconds: null,
  // No readings at all. Every state below that shows a height still shows one;
  // none of them get a percentage, because a percentage needs two of these.
  tip_timestamp_unix: null,
  observed_unix: null,
  fresh: null,
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
  can_stop: false,
  offers: [],
  api_port_holder: { holder: "not_checked" },
};

/**
 * The panel polls on mount, so the report reaches the screen the way it really
 * does: through the status command, into an effect, and out the other side.
 * `mountComponent` is the harness that runs effects; `settle` is what lets the
 * promise the effect started resolve. Rendering this with
 * `renderToStaticMarkup` would only ever show the "still reading" first paint.
 */
async function screen(report: NodeSupervisorReport): Promise<string> {
  const core = await import("@tauri-apps/api/core");
  vi.mocked(core.invoke).mockResolvedValue(report as never);
  const mounted = mountComponent(<NodeSupervisorPanel onInfo={() => {}} onError={() => {}} />);
  await settle();
  const html = mounted.html();
  mounted.unmount();
  return html;
}

describe("the node screen", () => {
  it("says nothing is bundled yet without making the wallet look broken", async () => {
    const html = await screen({
      ...BASE,
      state: "not_present",
      headline: "No node to run yet",
      detail:
        "This version of the wallet does not carry a Hacash node inside it, so there is nothing here to start yet. Your wallet is not broken and nothing is missing from it: it is working against the node it is already pointed at, exactly as before.",
      offers: [
        "Point the wallet at a fullnode you already have, by giving it the path.",
        "Keep using the node this wallet is already pointed at. Nothing here is required.",
        "This wallet will not download a node for you. There is no publisher signature to check it against, and a substituted node does not crash, it lies about money.",
      ],
      binary: {
        ...BASE.binary,
        searched: [
          {
            path: "C:\\Program Files\\HPAY\\hacash\\fullnode.exe",
            source: "bundled",
            verdict: "nothing is at this path",
          },
        ],
      },
    });
    expect(html).toContain("not broken");
    expect(html).toContain("already pointed at");
    expect(html).toContain("lies about money");
    // Where it looked, so a dead end is a fixable one.
    expect(html).toContain("C:\\Program Files\\HPAY\\hacash\\fullnode.exe");
    expect(html).not.toContain("Stop my node");
  });

  it("prints an age rather than the bare word synced, and keeps reachability separate", async () => {
    const html = await screen({
      ...BASE,
      state: "ready",
      ours: true,
      can_stop: true,
      headline: "Your node is up to date",
      detail:
        "Block 776647 arrived 898 seconds ago, and this node treats anything under 3600 seconds as current.",
      height: 776647,
      tip_age_seconds: 898,
      max_tip_age_seconds: 3600,
      fresh: true,
      anchor: "confirmed",
      watching: `Watching Hacash mainnet. This node's block one is ${MAINNET_BLOCK_ONE}, which is the one this wallet was built with, on chain 0.`,
      peer_role: "leaf",
      peers_inbound: 0,
      peers_outbound: 10,
      reach:
        "This node is a leaf: it has dialed out to 10 peers and nobody has dialed in. It is right about the chain, because it validated these blocks itself. What is not proven is that a transaction you send leaves through it, and four of them did not, here, for two days.",
      binary: {
        path: "C:\\hpay\\fullnode.exe",
        source: "legacy",
        version: "full node v1.0.10",
        database_type: 8,
        searched: [],
        picked_path: null,
        picked_problem: null,
      },
    });
    expect(html).toContain("15 minutes ago");
    expect(html).toContain(MAINNET_BLOCK_ONE);
    // Up to date is never allowed to swallow reachability.
    expect(html).toContain("nobody has dialed in");
    expect(html).toContain("Stop my node");
    expect(html).toContain("started this node and can stop it");
    // And the provenance is not blurred into the word "node".
    expect(html).toContain("cannot vouch for it");
  });

  /**
   * THE ONE THIS SCREEN EXISTS FOR. A real sync and an isolated private chain
   * both show a climbing height. The screen has to name the difference while it
   * is happening, not once it has gone wrong.
   */
  it("names a climbing height with no block one and no boot nodes as a private chain", async () => {
    const html = await screen({
      ...BASE,
      state: "catching_up",
      ours: true,
      can_stop: true,
      headline: "Catching up, at block 105",
      detail: "This node is at block 105 and is still downloading.",
      height: 105,
      tip_age_seconds: 90000,
      max_tip_age_seconds: 3600,
      fresh: false,
      anchor: "not_yet_available",
      watching:
        "This node has no block one and has connected to 0 boot nodes. A height that climbs while that is true is a private chain of its own, not Hacash mainnet, and money sent on it reaches nobody.",
    });
    expect(html).toContain("private chain of its own");
    expect(html).toContain("reaches nobody");
    expect(html).toContain("0 boot nodes");
    // The number is on the screen, never a bare "please wait".
    expect(html).toContain("At block 105");
  });

  it("never calls a node it did not start its own, and draws no stop button for one", async () => {
    const html = await screen({
      ...BASE,
      state: "foreign",
      ours: false,
      headline: "A node is already running on this computer",
      detail:
        "hacash-fullnode 1.0.10 is answering on 127.0.0.1:8080. This wallet did not start it, so it cannot stop it and will not claim it.",
      anchor: "unknown",
    });
    expect(html).toContain("did not start it");
    expect(html).not.toContain("Stop my node");
    expect(html).not.toContain("started this node and can stop it");
  });

  it("shows a refusal before a start as a refusal, with what was in the way", async () => {
    const html = await screen({
      ...BASE,
      state: "blocked",
      headline: "The wallet did not start a node",
      detail:
        "A node this wallet started (process 4242) is already using the chain folder C:\\chain. Two programs writing one chain store is how a chain gets corrupted, so a second one will not be started.",
    });
    expect(html).toContain("process 4242");
    expect(html).toContain("how a chain gets corrupted");
    expect(html).not.toContain("Stop my node");
  });

  it("shows a failure with the node's own last words rather than a bare code", async () => {
    const html = await screen({
      ...BASE,
      state: "failed",
      headline: "Your node stopped on its own",
      detail:
        "The node exited immediately because another program is already using the chain folder C:\\chain.",
      exit_code: 101,
      can_start: true,
      last_error_lines: ['thread \'main\' panicked: could not acquire lock on "db"'],
    });
    expect(html).toContain("another program is already using the chain folder");
    expect(html).toContain("could not acquire lock");
    expect(html).toContain("Start my node");
  });

  it("says when a config the person edited was left alone", async () => {
    const html = await screen({
      ...BASE,
      state: "stopped",
      can_start: true,
      headline: "Your node is not running",
      detail: "full node v1.0.10 is ready to start.",
      config: {
        outcome: "left_alone",
        reason:
          "hacash.config.ini was written by this wallet and has been edited since. It has been left exactly as it is, so the node will start with your version and not the wallet's.",
      },
      binary: {
        path: "C:\\hpay\\fullnode.exe",
        source: "picked",
        version: "full node v1.0.10",
        database_type: 8,
        searched: [],
        picked_path: null,
        picked_problem: null,
      },
    });
    expect(html).toContain("left exactly as it is");
    expect(html).toContain("your version and not the wallet");
  });

  it("says a stop that had to kill so the next start is not a mystery", async () => {
    const html = await screen({
      ...BASE,
      state: "stopped",
      stopped_hard: true,
      can_start: true,
      headline: "Your node is not running",
      detail:
        "The node was closed the hard way when it did not shut down within 20 seconds. Nothing is lost: the chain store survives that. The next start may pause while it checks the last few blocks it had not finished writing.",
    });
    expect(html).toContain("Nothing is lost");
    expect(html).toContain("may pause");
  });

  it("never puts a green header or the mainnet anchor on a port it cannot prove is its own", async () => {
    // The measured lie: the child announced the port and never bound it, a
    // plain TCP responder took it, and the screen said "Your node is up to
    // date", "Block 776647 arrived 42 seconds ago" and printed the mainnet
    // block one hash, with a Stop button. Every number came from a process the
    // wallet did not start.
    const html = await screen({
      ...BASE,
      state: "failed",
      ours: true,
      can_stop: true,
      headline: "Your node stopped answering",
      detail:
        "Port 8080 is now held by a different program on this computer (process 9001), not by the node this wallet started, which is still running. Nothing is being read from that port.",
      api_port_holder: { holder: "stranger", pid: 9001 },
      watching: "No chain is being watched. The wallet is not reading anything on this port.",
    });
    expect(html).toContain("process 9001");
    expect(html).not.toContain("Your node is up to date");
    expect(html).not.toContain(MAINNET_BLOCK_ONE);
    expect(html).not.toContain("tone-ok");
    // It is still our process, so it is still ours to stop.
    expect(html).toContain("Stop my node");
  });

  it("says the node you chose is gone rather than quietly running a different one", async () => {
    const html = await screen({
      ...BASE,
      state: "not_present",
      headline: "The node you chose is not there any more",
      detail:
        "You pointed this wallet at C:\\mine\\mynode.exe, and now nothing is at this path. Nothing has been started. This wallet will not quietly run a different fullnode instead, even though it can see others on this computer, because a node that is not the one you chose can say anything it likes about your money. Put that file back, or point the wallet at another one.",
      binary: {
        ...BASE.binary,
        picked_path: "C:\\mine\\mynode.exe",
        picked_problem: "nothing is at this path",
        searched: [
          {
            path: "C:\\mine\\mynode.exe",
            source: "picked",
            verdict: "nothing is at this path",
          },
        ],
      },
      offers: [
        "Put the file back where it was, or point the wallet at wherever it is now.",
      ],
    });
    expect(html).toContain("C:\\mine\\mynode.exe");
    expect(html).toContain("will not quietly run a different");
    // The fullnode the wallet can see elsewhere is never named as what will run.
    expect(html).not.toContain("Starting your node");
    expect(html).not.toContain("C:\\hpay\\fullnode.exe");
    expect(html).not.toContain("Start my node");
  });

  it("shows the warning when the node is running with settings this wallet did not choose", async () => {
    // This sentence could not appear on a real screen at all before: the
    // backend left report.config null on every live path, and only a
    // hand-built test fixture ever produced it.
    const html = await screen({
      ...BASE,
      state: "catching_up",
      ours: true,
      can_stop: true,
      height: 400000,
      tip_age_seconds: 90000,
      max_tip_age_seconds: 3600,
      fresh: false,
      anchor: "confirmed",
      headline: "Catching up, at block 400000",
      detail: "This node is at block 400000 and the newest block it holds is 90000 seconds old.",
      watching: `Watching Hacash mainnet. This node's block one is ${MAINNET_BLOCK_ONE}, which is the one this wallet was built with, on chain 0.`,
      config: {
        outcome: "left_alone",
        reason:
          "C:\\node\\hacash.config.ini was written by this wallet and has been edited since. It has been left exactly as it is, so the node will start with your version and not the wallet's, and the peer count and boot nodes this wallet would have set are whatever your file says.",
      },
    });
    expect(html).toContain("has been edited since");
    expect(html).toContain("peer count");
    expect(html).toContain(MAINNET_BLOCK_ONE);
  });

  it("gives a node that is running with no way in a failed state rather than starting for ever", async () => {
    const html = await screen({
      ...BASE,
      state: "failed",
      ours: true,
      can_stop: true,
      can_start: false,
      headline: "Your node is running with no way in",
      detail:
        "The node this wallet started said it could not take port 8080: [Error] api server failed to bind 127.0.0.1:8080: address in use. It keeps the chain going without an API, so the wallet has a node it cannot read a single number out of, and it is still holding the chain folder. Stop it, free port 8080, and start it again.",
    });
    expect(html).toContain("running with no way in");
    expect(html).toContain("could not take port 8080");
    // The old copy described conduct the code did not have.
    expect(html).not.toContain("being treated as");
    expect(html).not.toContain("Starting your node");
    expect(html).toContain("Stop my node");
  });

  it("puts a number on a start that has not finished, so one second and one hour read differently", async () => {
    const html = await screen({
      ...BASE,
      state: "starting",
      ours: true,
      can_stop: true,
      headline: "Starting your node",
      detail:
        "The node has been started and has not printed anything yet. It has been running for 412 seconds.",
    });
    expect(html).toContain("412 seconds");
  });
});

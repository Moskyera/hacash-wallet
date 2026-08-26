/**
 * THE SAME THREE LINES, ON THE PHONE.
 *
 * The phone does not run a node, it reads one, and that changes nothing about
 * the question a person needs answered first. A remote node can be behind, and
 * a remote node can be on a chain that is not Hacash mainnet, and both look
 * like a wallet that is merely slow. So this reads the node's own capability
 * answer, compares the block one against the hash this wallet pins, and hands
 * the result to the same component the desktop draws.
 *
 * What is deliberately absent: any spinner while the first answer is in
 * flight. The line while waiting says what is being waited on, and no element
 * that fills or moves is drawn until there are two real heights.
 */
import { nodeSyncView, recordSyncSample, syncChainSentence, syncChainVerdict } from "@hacash/wallet-ui";
import type { NodeCapabilities, SyncSample } from "@hacash/wallet-ui";
import { useEffect, useRef, useState } from "react";
import { api } from "../api";
import { formatInvokeError } from "../formatInvokeError";
import NodeSyncProgress from "./NodeSyncProgress";

/**
 * How often the phone asks. The estimate needs two readings that both moved,
 * so this is the thing that decides how long "working out how long" is on
 * screen. A capability read is one request and changes nothing on the node.
 */
const POLL_MS = 5000;

export default function NodeSyncSection() {
  const [capabilities, setCapabilities] = useState<NodeCapabilities | null>(null);
  const [problem, setProblem] = useState<string | null>(null);
  const [samples, setSamples] = useState<SyncSample[]>([]);
  const alive = useRef(true);

  useEffect(() => {
    alive.current = true;
    const read = async () => {
      try {
        const next = await api.nodeCapabilities();
        if (!alive.current) return;
        setCapabilities(next);
        setProblem(null);
        const sync = next.sync;
        // No freshness block means an older node that cannot say how old its
        // newest block is. That is a missing denominator, not a zero one, so
        // the run is cleared and the screen says the distance is not known.
        setSamples((history) =>
          sync
            ? recordSyncSample(history, {
                height: next.chain.height,
                tipTimestampUnix: sync.tip_timestamp_unix,
                observedUnix: sync.observed_unix,
                tipAgeSeconds: sync.tip_age_seconds,
              })
            : [],
        );
      } catch (error) {
        if (!alive.current) return;
        setProblem(formatInvokeError(error));
        setSamples([]);
      }
    };
    void read();
    const timer = setInterval(() => void read(), POLL_MS);
    return () => {
      alive.current = false;
      clearInterval(timer);
    };
  }, []);

  if (!capabilities) {
    return (
      <div className="node-sync node-sync-waiting" data-testid="node-sync-waiting">
        <p className="node-sync-chain tone-idle" role="status">
          {problem
            ? `This node has not answered, so which chain it is on is not known. ${problem}`
            : "Asking this node which chain it is on. Nothing about a height is believed until it says."}
        </p>
      </div>
    );
  }

  const verdict = syncChainVerdict({
    blockOneAvailable: capabilities.network?.block_1_available ?? false,
    blockOneHash: capabilities.network?.block_1_hash,
    chainId: capabilities.chain.id,
    mainnet: capabilities.chain.mainnet,
  });

  const view = nodeSyncView(
    {
      verdict,
      chainSentence: syncChainSentence(verdict, {
        blockOneHash: capabilities.network?.block_1_hash,
      }),
      height: capabilities.chain.height,
    },
    samples,
  );

  return <NodeSyncProgress view={view} />;
}

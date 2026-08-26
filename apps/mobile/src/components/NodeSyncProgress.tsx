/**
 * THE THREE LINES A NODE SYNC IS ALLOWED TO SHOW.
 *
 * The owner asked for something on screen during the wait, and they were
 * right: seven minutes of silence loses people. But a spinner would have made
 * the worst case worse. During a sync, a real mainnet catch-up and a node that
 * has quietly started a private chain of its own look identical, because both
 * show a climbing height. A spinner turns the same way for both, for seven
 * minutes, and would cover the one moment that mistake is still cheap.
 *
 * So the order here is the order of importance, in the DOM as well as on the
 * screen:
 *
 *   1. Which chain, and whether it matched. Answerable in the first second.
 *   2. How far along, in numbers the node supplied.
 *   3. How much longer, and only when it was measured.
 *
 * The bar is drawn from `view.showsBar` and nothing else. There is no
 * indeterminate variant of it: when the distance is unknown the words say so
 * and no element that fills or moves is rendered at all.
 *
 * THIS FILE IS BYTE-IDENTICAL TO apps/mobile/src/components/NodeSyncProgress.tsx.
 * `nodeSyncShapeMatches.test.ts` fails if the two drift. It is duplicated
 * rather than shared because packages/wallet-ui is hardlinked into each app's
 * node_modules, so a new file there would reach neither app. The sentences and
 * every number in them come from the one shared module both apps import.
 */
import type { NodeSyncView } from "@hacash/wallet-ui";

export default function NodeSyncProgress({ view }: { view: NodeSyncView }) {
  return (
    <section className="node-sync" data-testid="node-sync" data-chain={view.chain.verdict}>
      {/*
        FIRST, ALWAYS. Not because it is prettier at the top, but because a
        person on a private chain has to learn it in seconds rather than at the
        end of a seven minute wait, and a screen reader reads this order.
      */}
      <p
        className={`node-sync-chain tone-${view.chain.tone}`}
        data-testid="node-sync-chain"
        role="status"
      >
        {view.chain.text}
      </p>

      {/*
        The part that changes while somebody watches, so it is the part that is
        announced. Polite, because it updates every few seconds and assertive
        would talk over everything else on the screen.
      */}
      <div className="node-sync-live" data-testid="node-sync-live" aria-live="polite">
        <p className="node-sync-distance" data-testid="node-sync-distance">
          {view.distance.text}
        </p>

        {/*
          The only thing on this screen that fills. It exists only when both
          numbers exist, which is what keeps it from being a spinner wearing a
          bar's clothes. Its text is already in the paragraph above, so it is
          a progressbar with a value rather than an image needing a label.
        */}
        {view.showsBar && view.distance.percent !== null ? (
          <div
            className="node-sync-track"
            data-testid="node-sync-track"
            role="progressbar"
            aria-valuemin={0}
            aria-valuemax={100}
            aria-valuenow={view.distance.percent}
            aria-valuetext={view.distance.text}
          >
            <span
              className="node-sync-fill"
              style={{ width: `${view.distance.percent}%` }}
            />
          </div>
        ) : null}

        <p
          className={`node-sync-eta${view.remaining.known ? "" : " node-sync-unknown"}`}
          data-testid="node-sync-eta"
        >
          {view.remaining.text}
        </p>
      </div>
    </section>
  );
}

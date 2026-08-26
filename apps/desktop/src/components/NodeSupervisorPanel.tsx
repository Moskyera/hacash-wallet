/**
 * THE NODE SCREEN.
 *
 * Nine states, and every one of them says what is true, what was checked and
 * what can be pressed. The hard part of this screen is the sync: it takes
 * minutes, and while it runs a real mainnet catch-up and a node that has
 * quietly started a private chain of its own look identical, because both show
 * a climbing height. So the chain being watched is named next to the height
 * whenever a height is shown, and it is named by the pinned block one hash
 * rather than by the node's own say-so.
 *
 * The state that most people will land on in this build is "no node here yet",
 * because this pass ships the supervisor and not the binary. That state is
 * written as an offer, and it says plainly that the wallet still works against
 * the node it is already pointed at.
 */
import { useCallback, useEffect, useRef, useState } from "react";
import { api, type NodeSupervisorReport } from "../api";
import { formatInvokeError } from "../formatInvokeError";
import { binaryProvenance, nodeSupervisorView } from "../nodeSupervisor";

type Props = {
  onInfo: (message: string) => void;
  onError: (message: string) => void;
};

/**
 * How often the screen asks.
 *
 * The interesting state lasts minutes, so this is polled rather than returned
 * once. The status command starts nothing and stops nothing, so asking often
 * costs a loopback request and nothing else.
 */
const POLL_MS = 3000;

export default function NodeSupervisorPanel({ onInfo, onError }: Props) {
  const [report, setReport] = useState<NodeSupervisorReport | null>(null);
  const [busy, setBusy] = useState(false);
  const [pickedPath, setPickedPath] = useState("");
  const alive = useRef(true);

  const refresh = useCallback(async () => {
    try {
      const next = await api.nodeSupervisorStatus();
      if (alive.current) setReport(next);
    } catch (error) {
      if (alive.current) onError(formatInvokeError(error));
    }
  }, [onError]);

  useEffect(() => {
    alive.current = true;
    void refresh();
    const timer = setInterval(() => void refresh(), POLL_MS);
    return () => {
      alive.current = false;
      clearInterval(timer);
    };
  }, [refresh]);

  if (!report) {
    return (
      <div className="node-supervisor" data-testid="node-supervisor">
        <h3>Your own Hacash node</h3>
        <p className="muted">Reading what is running on this computer.</p>
      </div>
    );
  }

  const view = nodeSupervisorView(report);
  const provenance = binaryProvenance(report);

  /**
   * A TOAST THAT DESCRIBES WHAT HAPPENED, NOT WHAT WAS ASKED FOR.
   *
   * The Start button used to pop "The node was asked to start." on every press,
   * including presses where nothing was started at all: a refused start and a
   * frozen dead child both produced the same green sentence. The report that
   * comes back is the only thing that knows, so the caller reads it rather than
   * being told in advance.
   */
  const run = async (
    what: () => Promise<NodeSupervisorReport>,
    said: (next: NodeSupervisorReport) => string | null,
  ) => {
    setBusy(true);
    try {
      const next = await what();
      setReport(next);
      const message = said(next);
      if (message) onInfo(message);
    } catch (error) {
      onError(formatInvokeError(error));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="node-supervisor" data-testid="node-supervisor" data-state={view.state}>
      <h3>Your own Hacash node</h3>
      <p data-testid="node-headline" className={`node-headline tone-${view.tone}`}>
        {view.headline}
      </p>
      <p data-testid="node-detail" className="muted">
        {view.detail}
      </p>

      {view.progress ? (
        <p data-testid="node-progress" className="node-progress">
          {view.progress}
        </p>
      ) : null}

      {/*
        THE ANCHOR. Never omitted while a height is on screen, because a height
        is exactly the thing that cannot be told apart from a private chain.
      */}
      {view.watching ? (
        <p data-testid="node-watching" className={`node-watching tone-${view.tone}`}>
          {view.watching}
        </p>
      ) : null}

      {/*
        Reachability is a different question from being up to date, and it is
        shown even under a green header. A node the whole network can read is
        not the same as a node that can get your transaction to a miner.
      */}
      {view.reach ? (
        <p data-testid="node-reach" className="muted">
          {view.reach}
        </p>
      ) : null}

      <p data-testid="node-ownership" className="muted">
        {view.ownership}
      </p>

      {provenance ? (
        <p data-testid="node-provenance" className="muted">
          {provenance}
        </p>
      ) : null}

      {report.state === "ready" || report.state === "catching_up" || report.ours ? (
        <p className="muted" data-testid="node-locations">
          Chain folder: {report.data_dir}. Config written by this wallet:{" "}
          {report.config_path}. API: {report.api_url}.
        </p>
      ) : null}

      {/*
        THE SETTINGS THE NODE IS ACTUALLY BEING GIVEN.
        This is read off disk on every poll rather than remembered from a write,
        because the file can be edited between one start and the next, and the
        peer count in it is the difference between a transaction being mined in
        two minutes and sitting unmined for two days.
      */}
      {report.config && report.config.outcome === "left_alone" ? (
        <p data-testid="node-config-untouched" className="node-warn">
          {report.config.reason}
        </p>
      ) : null}

      {report.last_error_lines.length > 0 ? (
        <pre data-testid="node-last-lines" className="node-log">
          {report.last_error_lines.join("\n")}
        </pre>
      ) : null}

      {view.offers.length > 0 ? (
        <ul data-testid="node-offers">
          {view.offers.map((offer) => (
            <li key={offer}>{offer}</li>
          ))}
        </ul>
      ) : null}

      {view.searched.length > 0 && report.state === "not_present" ? (
        <details data-testid="node-searched">
          <summary>Where this wallet looked</summary>
          <ul>
            {view.searched.map((entry) => (
              <li key={entry.path}>
                <code>{entry.path}</code>: {entry.verdict}
              </li>
            ))}
          </ul>
        </details>
      ) : null}

      <div className="node-actions">
        {view.canStart ? (
          <button
            type="button"
            disabled={busy}
            onClick={() =>
              void run(api.nodeSupervisorStart, (next) =>
                // Only the states where a child of ours is actually running now
                // count as "started". Everything else already says why on the
                // panel itself, in a sentence that stays put.
                next.ours ? "Your node is starting." : null,
              )
            }
          >
            Start my node
          </button>
        ) : null}
        {/*
          Drawn only for a process this wallet is holding. A foreign node has no
          stop button because this wallet has no way to stop it and no right to
          pretend otherwise.
        */}
        {view.canStop ? (
          <button
            type="button"
            disabled={busy}
            onClick={() =>
              void run(api.nodeSupervisorStop, (next) =>
                next.ours ? null : "The node this wallet started has been stopped.",
              )
            }
          >
            Stop my node
          </button>
        ) : null}
      </div>

      {report.state === "not_present" || report.state === "blocked" ? (
        <div className="node-pick">
          {/*
            A typed path rather than a file picker, and that is a gap rather
            than a choice: opening a native picker needs a Tauri dialog plugin
            this app does not carry yet. Said plainly rather than dressed up.
          */}
          <label htmlFor="node-binary-path">
            Path to a Hacash fullnode you already have on this computer
          </label>
          <input
            id="node-binary-path"
            type="text"
            value={pickedPath}
            placeholder="C:\\hpay\\fullnode.exe"
            onChange={(event) => setPickedPath(event.target.value)}
          />
          <button
            type="button"
            disabled={busy || pickedPath.trim().length === 0}
            onClick={() =>
              void run(
                () => api.nodeSupervisorSetBinary(pickedPath.trim()),
                () => "That file answered as a Hacash fullnode and the wallet will use it.",
              )
            }
          >
            Use this one
          </button>
          <p className="muted">
            The wallet runs whatever you point it at once, with a config file that does not
            exist, purely to read the version it prints. That tells it whether the file is a
            Hacash fullnode without letting it open a port, a folder or a database.
          </p>
        </div>
      ) : null}
    </div>
  );
}

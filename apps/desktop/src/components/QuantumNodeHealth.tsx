import { useCallback, useEffect, useState } from "react";
import { quantumApi } from "../api";
import { formatInvokeError } from "../formatInvokeError";

type Props = {
  nodeUrl?: string;
};

export default function QuantumNodeHealth({ nodeUrl }: Props) {
  const [metrics, setMetrics] = useState<Record<string, unknown> | null>(null);
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);

  const refresh = useCallback(async () => {
    setBusy(true);
    setErr("");
    try {
      const m = await quantumApi.nodePing();
      setMetrics(m);
    } catch (e) {
      setMetrics(null);
      setErr(formatInvokeError(e));
    } finally {
      setBusy(false);
    }
  }, []);

  useEffect(() => {
    refresh();
  }, [refresh]);

  const ok = metrics != null && !err;

  return (
    <section className="panel quantum-node-health">
      <div className="panel-head row-between">
        <div>
          <h3>Node health</h3>
          <p className="muted">
            PQC fullnode · <code>{nodeUrl ?? "http://127.0.0.1:8080"}</code>
          </p>
        </div>
        <button type="button" className="btn-ghost" disabled={busy} onClick={refresh}>
          {busy ? "Checking…" : "Refresh"}
        </button>
      </div>
      <div className={`quantum-node-status ${ok ? "ok" : "bad"}`}>
        <span className="quantum-node-dot" />
        {ok ? "Node reachable" : "Node unreachable or PQC metrics missing"}
      </div>
      {metrics && (
        <pre className="mono quantum-metrics">{JSON.stringify(metrics, null, 2)}</pre>
      )}
      {err && <p className="error">{err}</p>}
    </section>
  );
}
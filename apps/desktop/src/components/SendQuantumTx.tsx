import { useState } from "react";
import { quantumApi, QuantumAccountInfo } from "../api";
import AddressBadge from "./AddressBadge";

const DEFAULT_TO = "1MzNY1oA3kfgYi75zquj3SRUPYztzXHzK9";

type Props = {
  account: QuantumAccountInfo | null;
  nodeUrl?: string;
  disabled?: boolean;
};

export default function SendQuantumTx({ account, nodeUrl, disabled }: Props) {
  const [to, setTo] = useState(DEFAULT_TO);
  const [amount, setAmount] = useState("0.1");
  const [pass, setPass] = useState("");
  const [phase, setPhase] = useState<"idle" | "busy" | "ok" | "err">("idle");
  const [hash, setHash] = useState("");
  const [fee, setFee] = useState("40:244");
  const [err, setErr] = useState("");

  async function send(isTest: boolean) {
    if (!account) {
      setErr("Create or import a quantum account first.");
      return;
    }
    setPhase("busy");
    setErr("");
    try {
      if (isTest) {
        const test = await quantumApi.sendTestTx(pass);
        setHash(test.hash);
        setFee(test.fee_used ?? "40:244");
      } else {
        const res = await quantumApi.sendType4(to, amount, pass);
        setHash(res.hash);
        setFee(res.fee_used ?? "40:244");
      }
      setPhase("ok");
    } catch (e) {
      setErr(String(e));
      setPhase("err");
    }
  }

  return (
    <section className="panel send-quantum">
      <h3>Send Type 4 (Quantum)</h3>
      <p className="muted">
        Node: <code>{nodeUrl ?? "http://127.0.0.1:8080"}</code> · auto-fee <code>{fee}</code>
      </p>

      <div className="from-row quantum-active">
        <span className="muted">From</span>
        {account ? (
          <>
            <AddressBadge
              address={account.address}
              version={account.address_version}
              kind={account.kind}
            />
            <code className="mono">{account.address}</code>
          </>
        ) : (
          <span className="muted">— no quantum account —</span>
        )}
      </div>

      <label className="field">
        To
        <input className="mono" value={to} onChange={(e) => setTo(e.target.value)} />
      </label>
      <label className="field">
        Amount (HAC)
        <input value={amount} onChange={(e) => setAmount(e.target.value)} />
      </label>
      <label className="field">
        Keystore password
        <input type="password" value={pass} onChange={(e) => setPass(e.target.value)} />
      </label>

      <div className="actions-row">
        <button disabled={disabled || phase === "busy"} onClick={() => send(false)}>
          Sign &amp; Send Type 4
        </button>
        <button
          className="btn-test"
          disabled={disabled || phase === "busy"}
          onClick={() => send(true)}
        >
          Send Test Quantum TX
        </button>
      </div>

      {phase === "ok" && (
        <div className="quantum-success">
          <div className="quantum-success__ring" />
          <p>Quantum transaction accepted</p>
          <code className="mono">{hash}</code>
        </div>
      )}
      {err && <p className="error">{err}</p>}
    </section>
  );
}
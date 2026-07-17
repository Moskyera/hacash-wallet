import { QuantumAccountSummary } from "../api";
import AddressBadge from "./AddressBadge";
import { copyWithPrivacyClear } from "../privacy";

type Props = {
  account: QuantumAccountSummary | null;
  balance: number | null;
  legacyAddress?: string | null;
  onGoToSend?: () => void;
};

export default function QuantumFundingCard({
  account,
  balance,
  legacyAddress,
  onGoToSend,
}: Props) {
  if (!account) {
    return (
      <section className="panel quantum-funding">
        <h3>Fund quantum account</h3>
        <p className="muted">Create or import a quantum keystore first, then fund it from your legacy wallet.</p>
      </section>
    );
  }

  async function copyAddress() {
    if (!account) return;
    await copyWithPrivacyClear(account.address, 30);
  }

  return (
    <section className="panel quantum-funding">
      <h3>Fund quantum account</h3>
      <p className="muted">
        Send legacy Type 1 HAC from your main wallet <strong>to</strong> this quantum address. The node
        credits the same on-chain balance used for Type 4 sends.
      </p>
      <div className="quantum-active">
        <AddressBadge address={account.address} version={account.address_version} kind={account.kind} />
        <code className="mono">{account.address}</code>
        <button type="button" className="btn-ghost" onClick={copyAddress}>
          Copy
        </button>
      </div>
      <p className="quantum-balance-line">
        Quantum balance:{" "}
        <strong>{balance == null ? "N/A" : `${balance.toFixed(3)} HAC`}</strong>
      </p>
      {legacyAddress && (
        <p className="muted small">
          Legacy send-from: <code className="mono">{legacyAddress}</code>
        </p>
      )}
      {onGoToSend && (
        <button type="button" className="btn-ghost" onClick={onGoToSend}>
          Open legacy Send tab
        </button>
      )}
    </section>
  );
}
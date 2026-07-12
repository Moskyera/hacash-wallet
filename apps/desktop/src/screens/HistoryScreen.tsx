import { TxRecord } from "../api";
import { maskAddress, maskHash } from "../privacy";

type Props = {
  txHistory: TxRecord[];
  hideAddresses: boolean;
  hideBalances: boolean;
};

export default function HistoryScreen({ txHistory, hideAddresses, hideBalances }: Props) {
  return (
    <section className="panel panel-wide">
      <h2>Transaction history</h2>
      {txHistory.length === 0 ? (
        <p className="muted">No transactions recorded yet.</p>
      ) : (
        <div className="table-wrap">
          <table className="data-table">
            <thead>
              <tr>
                <th>Time</th>
                <th>Rail</th>
                <th>From</th>
                <th>To</th>
                <th>Amount</th>
                <th>Tx hash</th>
              </tr>
            </thead>
            <tbody>
              {txHistory.map((tx) => (
                <tr key={`${tx.tx_hash}-${tx.timestamp}`}>
                  <td>{tx.timestamp}</td>
                  <td>
                    {tx.rail === "L2Fast"
                      ? "Fast Pay"
                      : tx.rail === "L1OnChain"
                        ? "On-chain"
                        : tx.rail}
                  </td>
                  <td>
                    <code>{maskAddress(tx.from, hideAddresses)}</code>
                  </td>
                  <td>
                    <code>{maskAddress(tx.to, hideAddresses)}</code>
                  </td>
                  <td>
                    {hideBalances ? "•••• HAC" : `${tx.amount_mei.toFixed(3)} HAC`}
                  </td>
                  <td>
                    <code>{maskHash(tx.tx_hash, hideAddresses)}</code>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}
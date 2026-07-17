import { TxRecord } from "../api";
import TxStatusMark from "../components/TxStatusMark";
import { canOpenTxInExplorer } from "../explorer";
import { formatHacMei, maskAddress, maskHash } from "../privacy";
import { openTxInExplorer } from "../txHistory";

type Props = {
  txHistory: TxRecord[];
  hideAddresses: boolean;
  hideBalances: boolean;
  onNotify: (msg: string, kind: "error" | "info" | "success") => void;
};

function railLabel(rail: string): string {
  if (rail === "L2Fast") return "Fast Pay";
  if (rail === "L1OnChain") return "On-chain";
  return rail;
}

export default function HistoryScreen({ txHistory, hideAddresses, hideBalances, onNotify }: Props) {
  return (
    <section className="panel panel-wide">
      <h2>Transaction history</h2>
      {txHistory.length === 0 ? (
        <p className="muted">No transactions recorded yet.</p>
      ) : (
        <div className="table-wrap">
          <table className="data-table history-table">
            <thead>
              <tr>
                <th aria-label="Status" />
                <th>Time</th>
                <th>Rail</th>
                <th>From</th>
                <th>To</th>
                <th>Amount</th>
                <th>Tx hash</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {txHistory.map((tx) => {
                const showExplorer = canOpenTxInExplorer(tx.rail, tx.tx_hash);
                return (
                  <tr
                    key={`${tx.tx_hash}-${tx.timestamp}`}
                    className="history-row-clickable"
                    onClick={() => void openTxInExplorer(tx, onNotify)}
                    title={showExplorer ? "Open in block explorer" : "View transaction details"}
                  >
                    <td>
                      <TxStatusMark status={tx.status} />
                    </td>
                    <td className="history-time">{tx.timestamp}</td>
                    <td>{railLabel(tx.rail)}</td>
                    <td>
                      <code>{maskAddress(tx.from, hideAddresses)}</code>
                    </td>
                    <td>
                      <code>{maskAddress(tx.to, hideAddresses)}</code>
                    </td>
                    <td>{hideBalances ? "•••• HAC" : `${formatHacMei(tx.amount_mei)} HAC`}</td>
                    <td>
                      <code>{maskHash(tx.tx_hash, hideAddresses)}</code>
                    </td>
                    <td>
                      {showExplorer ? (
                        <button
                          type="button"
                          className="ghost small"
                          onClick={(e) => {
                            e.stopPropagation();
                            void openTxInExplorer(tx, onNotify);
                          }}
                        >
                          Explorer
                        </button>
                      ) : (
                        <span className="muted">N/A</span>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
      <p className="muted small-note" style={{ marginTop: 12 }}>
        <span className="tx-status tx-status-confirmed">✓</span> completed &nbsp;
        <span className="tx-status tx-status-pending">●</span> processing &nbsp;
        <span className="tx-status tx-status-failed">✕</span> failed
      </p>
    </section>
  );
}
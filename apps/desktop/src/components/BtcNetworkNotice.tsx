import { open } from "@tauri-apps/plugin-shell";

const OFFICIAL_BTC_GUIDE = "https://hacash.org/BTC";

type Props = {
  onNotify?: (message: string, kind: "success" | "info" | "error") => void;
};

export default function BtcNetworkNotice({ onNotify }: Props) {
  const openGuide = async () => {
    try {
      await open(OFFICIAL_BTC_GUIDE);
    } catch (error) {
      onNotify?.(`Could not open the official BTC guide: ${String(error)}`, "error");
    }
  };

  return (
    <aside className="btc-network-card" aria-label="About BTC on the Hacash Network">
      <div className="btc-network-heading">
        <span className="btc-network-mark" aria-hidden>B</span>
        <div>
          <strong>BTC on Hacash</strong>
          <span>Bitcoin transferred one way into the Hacash network</span>
        </div>
        <span className="network-pill">Hacash L1</span>
      </div>
      <p>
        This balance represents BTC circulating on the Hacash Network after a one-way transfer. It
        is not a native Bitcoin UTXO in this wallet and it cannot be transferred back to Bitcoin.
      </p>
      <div className="btc-network-facts">
        <span>Use a Hacash address beginning with 1</span>
        <span>Amounts stay denominated in BTC and satoshi</span>
        <span>Hacash network fees are paid in HAC</span>
      </div>
      <p className="btc-network-warning">
        Do not send Bitcoin L1 directly to a Hacash address. Bitcoin-to-Hacash transfer is a
        separate, irreversible protocol. Check the official guide for current network availability
        and instructions.
      </p>
      <button type="button" className="text-button" onClick={() => void openGuide()}>
        Read the official one-way transfer guide
      </button>
    </aside>
  );
}

import { useState } from "react";
import ReceivePanel from "../components/ReceivePanel";

type Props = {
  address?: string | null;
  ownedHacdNames?: string[];
  hideAddresses: boolean;
  clipboardSecs: number;
  busy: boolean;
  onCopyAddress: () => void;
  onNotify: (msg: string, kind: "error" | "info" | "success") => void;
};

export default function ReceiveScreen({
  address,
  ownedHacdNames,
  hideAddresses,
  clipboardSecs,
  busy,
  onCopyAddress,
  onNotify,
}: Props) {
  const [receiveQrAmount, setReceiveQrAmount] = useState("");

  return (
    <section className="panel">
      <h2>Receive</h2>
      <ReceivePanel
        address={address}
        ownedHacdNames={ownedHacdNames}
        receiveAmount={receiveQrAmount}
        setReceiveAmount={setReceiveQrAmount}
        hideAddresses={hideAddresses}
        clipboardSecs={clipboardSecs}
        busy={busy}
        onCopyAddress={onCopyAddress}
        onNotify={onNotify}
      />
    </section>
  );
}
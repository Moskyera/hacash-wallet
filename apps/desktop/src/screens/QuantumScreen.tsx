import { useState } from "react";
import { WalletSettings, WalletStatus } from "../api";
import { quantumApi, QuantumAccountSummary } from "../api";
import QuantumToggle from "../components/QuantumToggle";
import SendQuantumTx from "../components/SendQuantumTx";
import QuantumFundingCard from "../components/QuantumFundingCard";
import QuantumNodeHealth from "../components/QuantumNodeHealth";
import type { Screen } from "./types";

type Props = {
  status: WalletStatus | null;
  settings: WalletSettings | null;
  busy: boolean;
  nativeBioAvailable: boolean;
  onNavigate: (screen: Screen) => void;
  onSetSendTo: (address: string) => void;
};

export default function QuantumScreen({
  status,
  settings,
  busy,
  nativeBioAvailable,
  onNavigate,
  onSetSendTo,
}: Props) {
  const [quantumAccount, setQuantumAccount] = useState<QuantumAccountSummary | null>(null);
  const [quantumBalance, setQuantumBalance] = useState<number | null>(null);

  return (
    <section className="stack">
      <QuantumToggle
        onAccountChange={(acc) => {
          setQuantumAccount(acc);
          if (acc) {
            quantumApi
              .balance()
              .then(setQuantumBalance)
              .catch(() => setQuantumBalance(null));
          } else {
            setQuantumBalance(null);
          }
        }}
      />
      <QuantumNodeHealth nodeUrl={settings?.node_url ?? status?.node_url} />
      <QuantumFundingCard
        account={quantumAccount}
        balance={quantumBalance}
        legacyAddress={status?.address}
        onGoToSend={() => {
          if (quantumAccount?.address) onSetSendTo(quantumAccount.address);
          onNavigate("send");
        }}
      />
      <SendQuantumTx
        account={quantumAccount}
        nodeUrl={settings?.node_url ?? status?.node_url}
        disabled={busy || !!status?.locked}
        webauthnEnabled={status?.webauthn_enabled}
        securityProfile={status?.security_profile}
        nativeBioAvailable={nativeBioAvailable}
      />
    </section>
  );
}
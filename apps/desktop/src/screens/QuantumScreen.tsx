import { QuantumFundingCard, useType4Probe } from "@hacash/wallet-ui";
import { useState } from "react";
import { WalletSettings, WalletStatus } from "../api";
import { quantumApi, QuantumAccountSummary } from "../api";
import AddressBadge from "../components/AddressBadge";
import QuantumToggle from "../components/QuantumToggle";
import SendQuantumTx from "../components/SendQuantumTx";
import QuantumNodeHealth from "../components/QuantumNodeHealth";
import { formatInvokeError } from "../formatInvokeError";
import { useLocale } from "../locale";
import { copyWithPrivacyClear } from "../privacy";
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
  const { t } = useLocale();
  const [quantumAccount, setQuantumAccount] = useState<QuantumAccountSummary | null>(null);
  const { probe } = useType4Probe(
    quantumAccount?.address,
    quantumApi.balanceProbe,
    formatInvokeError,
  );

  return (
    <section className="stack">
      <div className="panel quantum-lab-banner">
        <h2 style={{ marginTop: 0 }}>{t("quantum.lab.title")}</h2>
        <p className="muted" style={{ marginBottom: "0.5rem" }}>
          {t("quantum.lab.tagline")}
        </p>
        <p className="muted small-note">{t("quantum.lab.disclaimer")}</p>
      </div>
      <QuantumToggle onAccountChange={setQuantumAccount} />
      <QuantumNodeHealth nodeUrl={settings?.node_url ?? status?.node_url} />
      <QuantumFundingCard
        account={
          quantumAccount
            ? {
                address: quantumAccount.address,
                addressVersion: quantumAccount.address_version,
                kind: quantumAccount.kind,
              }
            : null
        }
        probe={probe}
        legacyAddress={status?.address}
        accountBadge={
          quantumAccount ? (
            <AddressBadge
              address={quantumAccount.address}
              version={quantumAccount.address_version}
              kind={quantumAccount.kind}
            />
          ) : undefined
        }
        containerClassName="panel quantum-funding"
        actionClassName="btn-ghost"
        headingLevel={3}
        onCopyAddress={(address) => copyWithPrivacyClear(address, 30)}
        onOpenLegacyFund={() => {
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
import type { ReactNode } from "react";

import { useLocale } from "./i18n";
import { canOpenLegacyFund, type Type4Probe } from "./type4Probe";

export type QuantumFundingAccount = {
  address: string;
  addressVersion: number;
  kind: string;
};

type Props = {
  account: QuantumFundingAccount | null;
  probe: Type4Probe;
  legacyAddress?: string | null;
  accountBadge?: ReactNode;
  containerClassName?: string;
  actionClassName?: string;
  headingLevel?: 2 | 3;
  onCopyAddress?: (address: string) => void | Promise<void>;
  onOpenLegacyFund?: () => void;
};

function ProbeStatus({ probe }: { probe: Type4Probe }) {
  const { t } = useLocale();
  switch (probe.status) {
    case "idle":
      return null;
    case "loading":
      return <p className="muted small">{t("quantum.funding.checking")}</p>;
    case "ok":
      return <p className="muted small">{t("quantum.funding.verified")}</p>;
    case "failed":
      return (
        <p className="error">
          {probe.kind === "unsupported"
            ? t("quantum.funding.unsupported")
            : `${t("quantum.funding.failed")}: ${probe.message}`}
        </p>
      );
  }
}

export function QuantumFundingCard({
  account,
  probe,
  legacyAddress,
  accountBadge,
  containerClassName = "card quantum-funding",
  actionClassName = "primary",
  headingLevel = 2,
  onCopyAddress,
  onOpenLegacyFund,
}: Props) {
  const { t } = useLocale();
  const Heading = headingLevel === 3 ? "h3" : "h2";

  if (!account) {
    return (
      <section className={containerClassName}>
        <Heading>{t("quantum.funding.title")}</Heading>
        <p className="muted">{t("quantum.funding.createFirst")}</p>
      </section>
    );
  }

  const balance = probe.status === "ok" ? `${probe.balance.toFixed(3)} HAC` : "N/A";
  const canFund = canOpenLegacyFund(probe);

  return (
    <section className={containerClassName}>
      <Heading>{t("quantum.funding.title")}</Heading>
      <p className="muted">{t("quantum.funding.warning")}</p>
      <div className="quantum-active">
        {accountBadge}
        <code className="mono">{account.address}</code>
        {onCopyAddress && (
          <button type="button" onClick={() => void onCopyAddress(account.address)}>
            {t("quantum.funding.copy")}
          </button>
        )}
      </div>
      <p className="quantum-balance-line">
        {t("quantum.funding.balance")}: <strong>{balance}</strong>
      </p>
      <ProbeStatus probe={probe} />
      {legacyAddress && (
        <p className="muted small">
          {t("quantum.funding.legacy")}: <code className="mono">{legacyAddress}</code>
        </p>
      )}
      {onOpenLegacyFund && (
        <button
          type="button"
          className={actionClassName}
          onClick={onOpenLegacyFund}
          disabled={!canFund}
          title={!canFund ? t("quantum.funding.verifyFirst") : undefined}
        >
          {t("quantum.funding.openLegacy")}
        </button>
      )}
    </section>
  );
}

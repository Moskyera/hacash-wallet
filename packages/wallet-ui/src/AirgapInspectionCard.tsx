import { useLocale } from "./i18n";

export type AirgapInspection = {
  kind: "unsigned" | "signed";
  tx_type: number;
  network_mode: string;
  from: string;
  to: string;
  amount_mei: number;
  amount_wire: string;
  network_fee: string;
  wallet_fee_mei: number;
  wallet_fee_wire: string;
  wallet_fee_treasury: string;
  body_sha256: string;
  summary: string;
};

type Props = {
  inspection: AirgapInspection;
  className?: string;
  title?: string;
};

export function AirgapInspectionCard({
  inspection,
  className = "airgap-inspection",
  title,
}: Props) {
  const { t } = useLocale();
  const heading = title ?? t("airgap.inspection.verifiedTitle");

  return (
    <div className={className} aria-label={heading}>
      <h4>{heading}</h4>
      <dl>
        <div>
          <dt>{t("airgap.inspection.network")}</dt>
          <dd>{inspection.network_mode}</dd>
        </div>
        <div>
          <dt>{t("airgap.inspection.transactionType")}</dt>
          <dd>{inspection.tx_type}</dd>
        </div>
        <div>
          <dt>{t("airgap.inspection.from")}</dt>
          <dd><code>{inspection.from}</code></dd>
        </div>
        <div>
          <dt>{t("airgap.inspection.to")}</dt>
          <dd><code>{inspection.to}</code></dd>
        </div>
        <div>
          <dt>{t("airgap.inspection.amount")}</dt>
          <dd>{inspection.amount_wire} HAC</dd>
        </div>
        <div>
          <dt>{t("airgap.inspection.networkFee")}</dt>
          <dd>{inspection.network_fee}</dd>
        </div>
        <div>
          <dt>{t("airgap.inspection.walletFee")}</dt>
          <dd>{inspection.wallet_fee_wire} HAC</dd>
        </div>
        <div>
          <dt>{t("airgap.inspection.walletFeeRecipient")}</dt>
          <dd><code>{inspection.wallet_fee_treasury}</code></dd>
        </div>
        <div>
          <dt>{t("airgap.inspection.bodyHash")}</dt>
          <dd><code>{inspection.body_sha256}</code></dd>
        </div>
      </dl>
      <p className="muted small">{t("airgap.inspection.matchedNote")}</p>
    </div>
  );
}

import { PAYMENT_ASSETS, type PaymentAsset } from "../utils/paymentAssets";

type Props = {
  value: PaymentAsset;
  onChange: (asset: PaymentAsset) => void;
};

export default function AssetSelector({ value, onChange }: Props) {
  return (
    <div className="asset-selector" role="tablist" aria-label="Payment asset">
      {PAYMENT_ASSETS.map((a) => (
        <button
          key={a.id}
          type="button"
          role="tab"
          aria-selected={value === a.id}
          className={`asset-chip ${value === a.id ? "selected" : ""}`}
          onClick={() => onChange(a.id)}
        >
          <span className="asset-symbol">{a.symbol}</span>
          <span className="asset-label">{a.label}</span>
        </button>
      ))}
    </div>
  );
}
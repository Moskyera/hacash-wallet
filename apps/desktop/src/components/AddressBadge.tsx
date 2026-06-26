import "../quantum.css";

type Props = {
  address: string;
  version?: number;
  kind?: string;
  compact?: boolean;
};

function inferVersion(address: string, kind?: string, version?: number): number {
  if (version === 6 || version === 7) return version;
  if (kind === "hybrid") return 7;
  if (kind === "pqckey") return 6;
  if (address.startsWith("3x")) return 7;
  if (address.startsWith("3")) return 6;
  return 0;
}

export default function AddressBadge({ address, version, kind, compact }: Props) {
  const v = inferVersion(address, kind, version);
  const meta =
    v === 6
      ? { label: "PQC", cls: "badge-pqc", icon: "◇" }
      : v === 7
        ? { label: "Hybrid", cls: "badge-hybrid", icon: "⬡" }
        : { label: "Legacy", cls: "badge-legacy", icon: "●" };

  return (
    <span className={`addr-badge ${meta.cls}`} title={`${meta.label} — ${address}`}>
      <span className="addr-badge__icon">{meta.icon}</span>
      {!compact && <span className="addr-badge__label">{meta.label}</span>}
    </span>
  );
}
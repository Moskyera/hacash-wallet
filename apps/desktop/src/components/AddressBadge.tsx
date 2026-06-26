import "../quantum.css";
import { badgeVersion } from "../quantumMeta";

type Props = {
  address: string;
  version?: number | null;
  kind?: string | null;
  compact?: boolean;
};

export default function AddressBadge({ address, version, kind, compact }: Props) {
  const v = badgeVersion(kind, version);
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
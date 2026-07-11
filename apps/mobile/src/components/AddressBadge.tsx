import { badgeVersion } from "../quantumMeta";

type Props = {
  address: string;
  version?: number | null;
  kind?: string | null;
};

export default function AddressBadge({ address, version, kind }: Props) {
  const v = badgeVersion(kind, version);
  const meta =
    v === 6
      ? { label: "PQC", cls: "badge-pqc" }
      : v === 7
        ? { label: "Hybrid", cls: "badge-hybrid" }
        : { label: "Legacy", cls: "badge-legacy" };

  return (
    <span className={`addr-badge ${meta.cls}`} title={`${meta.label} — ${address}`}>
      {meta.label}
    </span>
  );
}
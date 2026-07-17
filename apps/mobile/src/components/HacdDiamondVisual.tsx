import { useMemo, useState } from "react";
import { openUrl } from "@tauri-apps/plugin-opener";
import { useHacdDiamond } from "../hooks/useHacdDiamond";
import { renderHip5Svg, resolveVisualGene } from "../lib/hip5";
import { isValidHacdName, normalizeHacdName } from "../utils/paymentAssets";

type Props = {
  name: string;
  size?: "sm" | "lg";
};

const EXPLORER_BASE = "https://explorer.hacash.org/diamond/";

export default function HacdDiamondVisual({ name, size = "lg" }: Props) {
  const normalized = normalizeHacdName(name);
  const lookupName = isValidHacdName(normalized) ? normalized : null;
  const diamondState = useHacdDiamond(lookupName);
  const [showDetails, setShowDetails] = useState(false);
  const [actionStatus, setActionStatus] = useState("");

  const svgUrl = useMemo(() => {
    if (diamondState.status !== "ready") return null;
    const gene = resolveVisualGene({
      name: diamondState.info.name,
      visualGene: diamondState.info.visual_gene,
      lifeGene: diamondState.info.life_gene,
    });
    if (!gene) return null;
    const svgSize = size === "lg" ? 240 : 144;
    return `data:image/svg+xml;charset=utf-8,${encodeURIComponent(renderHip5Svg(gene, svgSize))}`;
  }, [diamondState, size]);

  const copyCode = async () => {
    await navigator.clipboard.writeText(`hacd:${normalized}`);
    setActionStatus("Copied");
    window.setTimeout(() => setActionStatus(""), 1800);
  };

  const openExplorer = async () => {
    if (!lookupName) return;
    try {
      await openUrl(`${EXPLORER_BASE}${lookupName}`);
    } catch {
      setActionStatus("Could not open explorer");
    }
  };

  if (!normalized) {
    return <MetadataState size={size} message="Enter a HACD name to load its metadata." />;
  }

  if (!lookupName) {
    return <MetadataState size={size} title={normalized} message="HACD names use 4 to 6 valid letters." />;
  }

  if (diamondState.status === "loading") {
    return <MetadataState size={size} title={normalized} message="Loading on-chain metadata…" loading />;
  }

  if (diamondState.status === "not_found") {
    return <MetadataState size={size} title={normalized} message="Not found on chain. Check the name." />;
  }

  if (diamondState.status === "error") {
    return <MetadataState size={size} title={normalized} message="The configured Hacash node did not return metadata." />;
  }

  if (diamondState.status !== "ready") {
    return <MetadataState size={size} title={normalized} message="Metadata is unavailable." />;
  }

  const info = diamondState.info;
  const inscription = info.inscriptions.length > 0 ? info.inscriptions.join(" · ") : "None";

  return (
    <article className={`hacd-metadata-card hacd-metadata-${size}`}>
      <header className="hacd-metadata-header">
        <div>
          <span className="eyebrow">HACD metadata</span>
          <h3>{normalized}</h3>
        </div>
        <span className="hacd-number">{info.number != null ? `#${info.number}` : "On-chain"}</span>
      </header>
      {info.metadata_source === "mainnet" ? (
        <p className="muted small" role="status">
          Mainnet metadata is read-only. Ownership and sends still use your configured node.
        </p>
      ) : null}

      <div className="hacd-metadata-main">
        <div className="hacd-art-frame">
          {svgUrl ? (
            <img src={svgUrl} alt={`HIP-5 visual for HACD ${normalized}`} className="hacd-hip5-svg" />
          ) : (
            <span className="muted">HIP-5 visual unavailable</span>
          )}
        </div>

        <dl className="hacd-facts">
          <div>
            <dt>Born block</dt>
            <dd>{info.born?.height ?? "N/A"}</dd>
          </div>
          <div>
            <dt>Average burn</dt>
            <dd>{info.average_bid_burn != null ? `${info.average_bid_burn} HACD` : "N/A"}</dd>
          </div>
          <div>
            <dt>Bid fee (wire)</dt>
            <dd>{info.bid_fee ?? "N/A"}</dd>
          </div>
          <div>
            <dt>Inscriptions</dt>
            <dd title={inscription}>{inscription}</dd>
          </div>
        </dl>
      </div>

      <div className="hacd-card-actions">
        <button type="button" className="primary" onClick={() => void copyCode()}>
          {actionStatus === "Copied" ? "Copied" : "Copy HACD code"}
        </button>
        <button type="button" onClick={() => setShowDetails((value) => !value)} aria-expanded={showDetails}>
          {showDetails ? "Hide details" : "Details"}
        </button>
        <button type="button" className="text-button" onClick={() => void openExplorer()}>
          Explorer
        </button>
      </div>

      {actionStatus && actionStatus !== "Copied" && <p className="form-error">{actionStatus}</p>}

      {showDetails && (
        <dl className="hacd-details">
          <MetadataRow label="Owner" value={info.belong} />
          <MetadataRow label="Miner" value={info.miner} />
          <MetadataRow label="Born hash" value={info.born?.hash} />
          <MetadataRow label="Previous hash" value={info.prev_hash} />
          <MetadataRow label="Visual gene" value={info.visual_gene} />
          <MetadataRow label="Life gene" value={info.life_gene} />
        </dl>
      )}
    </article>
  );
}

function MetadataState({
  size,
  title,
  message,
  loading = false,
}: {
  size: "sm" | "lg";
  title?: string;
  message: string;
  loading?: boolean;
}) {
  return (
    <div className={`hacd-metadata-card hacd-metadata-${size} hacd-metadata-empty`} aria-busy={loading}>
      <span className="eyebrow">HACD metadata</span>
      {title && <strong>{title}</strong>}
      <span className="muted">{message}</span>
    </div>
  );
}

function MetadataRow({ label, value }: { label: string; value?: string | null }) {
  return (
    <div>
      <dt>{label}</dt>
      <dd><code>{value || "N/A"}</code></dd>
    </div>
  );
}

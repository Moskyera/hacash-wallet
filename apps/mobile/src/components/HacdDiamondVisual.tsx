import { useMemo } from "react";
import { useHacdDiamond } from "../hooks/useHacdDiamond";
import { hip5MainColors, renderHip5Svg, resolveVisualGene } from "../lib/hip5";
import { hacdArchetype, normalizeHacdName } from "../utils/paymentAssets";

type Props = {
  name: string;
  size?: "sm" | "lg";
};

export default function HacdDiamondVisual({ name, size = "lg" }: Props) {
  const normalized = normalizeHacdName(name);
  const diamondState = useHacdDiamond(isValidForLookup(normalized) ? normalized : null);

  const visual = useMemo(() => {
    if (diamondState.status !== "ready") return null;
    const info = diamondState.info;
    const gene = resolveVisualGene({
      name: info.name,
      visualGene: info.visual_gene,
      lifeGene: info.life_gene,
    });
    if (!gene) return null;
    const svgSize = size === "lg" ? 220 : 140;
    const [c0, c1] = hip5MainColors(gene);
    return {
      gene,
      svg: renderHip5Svg(gene, svgSize),
      gradient: `linear-gradient(135deg, #${c0}55, #${c1}33)`,
      number: info.number,
    };
  }, [diamondState, size]);

  if (!normalized) {
    return (
      <div className={`hacd-visual hacd-visual-${size} hacd-visual-empty`}>
        <span className="muted">Enter HACD name</span>
      </div>
    );
  }

  if (diamondState.status === "loading") {
    return (
      <div className={`hacd-visual hacd-visual-${size} hacd-visual-empty`}>
        <span className="muted">Loading HIP-5 visual…</span>
      </div>
    );
  }

  if (diamondState.status === "not_found") {
    return (
      <div className={`hacd-visual hacd-visual-${size} hacd-visual-empty`}>
        <div className="hacd-visual-meta">
          <strong>{normalized}</strong>
          <span className="muted">Not found on chain. Check the name.</span>
        </div>
      </div>
    );
  }

  if (diamondState.status === "error") {
    return (
      <div className={`hacd-visual hacd-visual-${size} hacd-visual-empty`}>
        <div className="hacd-visual-meta">
          <strong>{normalized}</strong>
          <span className="muted">Failed to load visual</span>
        </div>
      </div>
    );
  }

  if (!visual) {
    return (
      <div className={`hacd-visual hacd-visual-${size} hacd-visual-empty`}>
        <span className="muted">HIP-5 visual unavailable</span>
      </div>
    );
  }

  const archetype = hacdArchetype(normalized);

  return (
    <div className={`hacd-visual hacd-visual-${size}`} style={{ backgroundImage: visual.gradient }}>
      <div
        className="hacd-hip5-svg"
        dangerouslySetInnerHTML={{ __html: visual.svg }}
        aria-label={`HIP-5 visualization for ${normalized}`}
      />
      <div className="hacd-visual-meta">
        <strong>{normalized}</strong>
        {visual.number != null && <span className="muted">#{visual.number}</span>}
        <span className="muted">{archetype} · HIP-5</span>
      </div>
    </div>
  );
}

function isValidForLookup(name: string): boolean {
  return name.length >= 4 && name.length <= 6;
}
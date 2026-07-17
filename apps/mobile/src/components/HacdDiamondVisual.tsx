import { useLayoutEffect, useMemo, useRef, useState } from "react";
import { openUrl } from "@tauri-apps/plugin-opener";
import { useHacdDiamond } from "../hooks/useHacdDiamond";
import type { HacdDiamondInfo } from "../api";
import { hip5MainColors, renderHip5Svg, resolveVisualGene } from "../lib/hip5";
import { isValidHacdName, normalizeHacdName } from "../utils/paymentAssets";

type Props = {
  name: string;
  size?: "sm" | "lg";
};

const EXPLORER_BASE = "https://explorer.hacash.org/diamond/";

/** Single Explorer-style metadata card — all identity art + genes + bid in one poster. */
export default function HacdDiamondVisual({ name }: Props) {
  const normalized = normalizeHacdName(name);
  const lookupName = isValidHacdName(normalized) ? normalized : null;
  const diamondState = useHacdDiamond(lookupName);
  const hostRef = useRef<HTMLDivElement>(null);
  const [scale, setScale] = useState(0.36);

  useLayoutEffect(() => {
    const host = hostRef.current;
    if (!host) return;
    const fit = () => {
      const w = host.clientWidth || 320;
      setScale(Math.max(0.14, Math.min(0.48, w / 800)));
    };
    fit();
    if (typeof ResizeObserver === "undefined") return;
    const ro = new ResizeObserver(fit);
    ro.observe(host);
    return () => ro.disconnect();
  }, [diamondState.status, lookupName]);

  if (!normalized) {
    return <PendingCard message="Enter a HACD name" />;
  }
  if (!lookupName) {
    return <PendingCard title={normalized} message="Use 4–6 letters from WTYUIAHXVMEKBSZN" />;
  }
  if (diamondState.status === "loading" || diamondState.status === "idle") {
    return <PendingCard title={normalized} message="Loading metadata…" />;
  }
  if (diamondState.status === "not_found") {
    return <PendingCard title={normalized} message="Not found on chain" />;
  }
  if (diamondState.status === "error") {
    return <PendingCard title={normalized} message={diamondState.message} />;
  }

  return (
    <div ref={hostRef} className="hacd-metadata-host">
      <ExplorerMetadataCard
        info={diamondState.info}
        displayName={normalized}
        scale={scale}
      />
    </div>
  );
}

function ExplorerMetadataCard({
  info,
  displayName,
  scale,
}: {
  info: HacdDiamondInfo;
  displayName: string;
  scale: number;
}) {
  const gene = useMemo(
    () =>
      resolveVisualGene({
        name: info.name || displayName,
        visualGene: info.visual_gene,
        lifeGene: info.life_gene,
      }),
    [info, displayName],
  );

  const art = useMemo(() => {
    if (!gene) return null;
    try {
      const svg = renderHip5Svg(gene, 500);
      const colors = hip5MainColors(gene);
      return { svg, colors, gene };
    } catch {
      return null;
    }
  }, [gene]);

  const openExplorer = async (e: React.MouseEvent) => {
    e.preventDefault();
    try {
      await openUrl(`${EXPLORER_BASE}${encodeURIComponent(displayName)}`);
    } catch {
      /* ignore */
    }
  };

  const bornTail = info.born?.hash ? `···${info.born.hash.slice(-20)}` : "";
  const minerShort = info.miner ? `${info.miner.slice(0, 12)}···` : "";
  const bid = formatBidFee(info.bid_fee);
  const lifeHtml = formatLifeGeneHtml(info.life_gene);
  const visualHtml = formatVisualGeneHtml(art?.gene ?? "");
  const gradient = art
    ? `linear-gradient(to right bottom, #${art.colors[0]}99, #${art.colors[1]})`
    : "#1a0a2e";

  return (
    <article className="hacd-metadata-card" data-hacd-name={displayName}>
      <a
        className="hacd-meta-cdit"
        href={`${EXPLORER_BASE}${encodeURIComponent(displayName)}`}
        onClick={(e) => void openExplorer(e)}
        title="View on Hacash Explorer"
      >
        <div
          className="hacd-meta-cdcon"
          style={{
            transform: `scale(${scale})`,
            backgroundImage: gradient,
          }}
        >
          {art && (
            <>
              <div
                className="hacd-meta-ibg"
                aria-hidden
                dangerouslySetInnerHTML={{ __html: art.svg }}
              />
              <div className="hacd-meta-ldz" aria-hidden />
              <div
                className="hacd-meta-img"
                aria-hidden
                dangerouslySetInnerHTML={{ __html: art.svg }}
              />
            </>
          )}
          <div className="hacd-meta-overlay">
            <div className="hacd-meta-blk">
              {bornTail}
              <br />
              BORN BLOCK: <b>{info.born?.height ?? "—"}</b>
            </div>
            <div className="hacd-meta-clb" aria-hidden />
            <div className="hacd-meta-num">{info.number ?? ""}</div>
            <div
              className="hacd-meta-dn"
              style={
                art
                  ? {
                      backgroundImage: `linear-gradient(90deg, #${art.colors[0]}, #${art.colors[1]})`,
                    }
                  : undefined
              }
            >
              {displayName}
            </div>
            <p className="hacd-meta-lgn">LIFE GENES</p>
            <p
              className="hacd-meta-lg"
              style={
                art
                  ? {
                      backgroundImage: `linear-gradient(-21deg, #${art.colors[0]}, #${art.colors[1]})`,
                    }
                  : undefined
              }
              dangerouslySetInnerHTML={{ __html: lifeHtml || "—" }}
            />
            <div
              className="hacd-meta-vg"
              dangerouslySetInnerHTML={{ __html: visualHtml || "—" }}
            />
            <p className="hacd-meta-gmn">LIFE GAME CODE</p>
            <p className="hacd-meta-bid">
              BID: {bid}
              <br />
              {minerShort}
            </p>
            <div className="hacd-meta-cll" aria-hidden />
          </div>
        </div>
      </a>
      {info.metadata_source === "mainnet" && (
        <p className="muted small hacd-meta-source">Mainnet metadata (read-only)</p>
      )}
    </article>
  );
}

function PendingCard({ title, message }: { title?: string; message: string }) {
  return (
    <div className="hacd-metadata-host">
      <div className="hacd-metadata-card hacd-metadata-card-pending">
        <div className="hacd-meta-pending">
          {title && <strong>{title}</strong>}
          <span>{message}</span>
        </div>
      </div>
    </div>
  );
}

function formatBidFee(fee?: string | null): string {
  const raw = String(fee || "").trim();
  if (!raw) return "—";
  return `ㄜ${raw}`;
}

function insertAt(str: string, sep: string, positions: number[]): string {
  const chars = str.split("");
  let offset = 0;
  for (const pos of positions) {
    const idx = pos - 1 + offset;
    if (idx > 0 && idx < chars.length) {
      chars.splice(idx, 0, sep);
      offset += sep.length;
    }
  }
  return chars.join("");
}

function formatLifeGeneHtml(lifeGene?: string | null): string {
  const lg = String(lifeGene || "");
  if (!lg) return "";
  return insertAt(lg, "<br>", [8, 16, 24, 32, 40, 48, 56]);
}

function formatVisualGeneHtml(visualGene: string): string {
  const vg = String(visualGene || "").toUpperCase();
  if (!vg) return "";
  const spaced = insertAt(vg, " ", [2, 6, 10, 14, 18]);
  return spaced
    .replace(/^0/, '<span class="hacd-meta-vg-a">0</span>')
    .replace(/(.{2})$/, '<span class="hacd-meta-vg-dim">$1</span>');
}

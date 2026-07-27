import {
  Fragment,
  useEffect,
  useLayoutEffect,
  useMemo,
  useRef,
  useState,
  type MouseEvent,
} from "react";

import "./hacd.css";
import { renderHip8Svg, renderHip9Svg } from "./hacdArt";
import { hip5ColorPalette, hip5MainColors, renderHip5Svg, resolveVisualGene } from "./hip5";
import { isValidHacdName, normalizeHacdName } from "./paymentAssets";

export type HacdDiamondBornInfo = {
  height: number;
  hash: string;
};

export type HacdDiamondInfo = {
  name: string;
  metadata_source: "configured" | "mainnet" | string;
  number?: number | null;
  visual_gene?: string | null;
  life_gene?: string | null;
  belong?: string | null;
  miner?: string | null;
  bid_fee?: string | null;
  average_bid_burn?: number | null;
  born?: HacdDiamondBornInfo | null;
  prev_hash?: string | null;
  inscriptions: string[];
};

export type QueryHacdDiamond = (name: string) => Promise<HacdDiamondInfo>;
export type OpenExternal = (url: string) => void | Promise<void>;

export type HacdMetadataCopy = {
  metadataLoading: string;
  metadataUnavailable: string;
  metadataNotFound: string;
  invalidName: string;
  viewExplorer: string;
  bornBlock: string;
  lifeGenes: string;
  lifeGameCode: string;
  bid: string;
  mainnetMetadata: string;
  notAvailable: string;
  details: string;
  owner: string;
  minerFull: string;
  averageBidBurn: string;
  bornHash: string;
  prevHash: string;
  inscriptions: string;
  noInscriptions: string;
  noVisual: string;
};

export const DEFAULT_HACD_METADATA_COPY: HacdMetadataCopy = {
  metadataLoading: "Loading on-chain metadata...",
  metadataUnavailable: "Metadata is temporarily unavailable. Try Refresh again.",
  metadataNotFound: "No on-chain metadata was found for this owned HACD.",
  invalidName: "The wallet returned an invalid HACD name.",
  viewExplorer: "View on Hacash Explorer",
  bornBlock: "BORN BLOCK",
  lifeGenes: "LIFE GENES",
  lifeGameCode: "LIFE GAME CODE",
  bid: "BID",
  mainnetMetadata: "Mainnet metadata (read-only)",
  notAvailable: "N/A",
  details: "On-chain details",
  owner: "Owner",
  minerFull: "Miner",
  averageBidBurn: "Average bid burn",
  bornHash: "Born block hash",
  prevHash: "Previous diamond hash",
  inscriptions: "Inscriptions",
  noInscriptions: "None",
  noVisual: "This node returned no usable visual gene, so the diamond cannot be drawn.",
};

export function translatedHacdMetadataCopy(t: (key: string) => string): HacdMetadataCopy {
  return {
    metadataLoading: t("hacd.metadataLoading"),
    metadataUnavailable: t("hacd.metadataUnavailable"),
    metadataNotFound: t("hacd.metadataNotFound"),
    invalidName: t("hacd.invalidName"),
    viewExplorer: t("hacd.viewExplorer"),
    bornBlock: t("hacd.bornBlock"),
    lifeGenes: t("hacd.lifeGenes"),
    lifeGameCode: t("hacd.lifeGameCode"),
    bid: t("hacd.bid"),
    mainnetMetadata: t("hacd.mainnetMetadata"),
    notAvailable: t("common.notAvailable"),
    details: t("hacd.details"),
    owner: t("hacd.owner"),
    minerFull: t("hacd.minerFull"),
    averageBidBurn: t("hacd.averageBidBurn"),
    bornHash: t("hacd.bornHash"),
    prevHash: t("hacd.prevHash"),
    inscriptions: t("hacd.inscriptions"),
    noInscriptions: t("hacd.noInscriptions"),
    noVisual: t("hacd.noVisual"),
  };

}
export type HacdDiamondState =
  | { status: "idle" }
  | { status: "loading" }
  | { status: "ready"; info: HacdDiamondInfo }
  | { status: "not_found" }
  | { status: "error" };

export const HACD_EXPLORER_BASE = "https://explorer.hacash.org/diamond/";
const LIFE_GENE_RE = /^[0-9a-f]{64}$/i;
const VISUAL_GENE_RE = /^[0-9a-f]{18,20}$/i;

export function hacdExplorerUrl(rawName: string): string | null {
  const name = rawName.trim().toUpperCase();
  return isValidHacdName(name) ? `${HACD_EXPLORER_BASE}${encodeURIComponent(name)}` : null;
}

export function splitLifeGene(value?: string | null): string[] {
  if (!value || !LIFE_GENE_RE.test(value)) return [];
  return value.toLowerCase().match(/.{8}/g) ?? [];
}

export function formatVisualGene(value?: string | null): {
  first: string;
  middle: string;
  tail: string;
  highlightFirst: boolean;
} | null {
  if (!value || !VISUAL_GENE_RE.test(value)) return null;
  const chars = value.toUpperCase().split("");
  let offset = 0;
  for (const position of [2, 6, 10, 14, 18]) {
    chars.splice(position - 1 + offset, 0, " ");
    offset += 1;
  }
  const formatted = chars.join("");
  return {
    first: formatted.slice(0, 1),
    middle: formatted.slice(1, -2),
    tail: formatted.slice(-2),
    highlightFirst: formatted.startsWith("0"),
  };
}

export function useHacdDiamond(
  name: string | null,
  queryDiamond: QueryHacdDiamond,
): HacdDiamondState {
  const [state, setState] = useState<HacdDiamondState>({ status: "idle" });

  useEffect(() => {
    if (!name || !isValidHacdName(name)) {
      setState({ status: "idle" });
      return;
    }
    let cancelled = false;
    setState({ status: "loading" });
    void queryDiamond(name)
      .then((info) => {
        if (!cancelled) setState({ status: "ready", info });
      })
      .catch((cause: unknown) => {
        if (cancelled) return;
        const message = cause instanceof Error ? cause.message : String(cause);
        const lower = message.toLowerCase();
        if (
          lower.includes("not found") ||
          lower.includes("cannot find diamond") ||
          lower.includes("find diamond") ||
          message.includes("ret=1")
        ) {
          setState({ status: "not_found" });
        } else {
          setState({ status: "error" });
        }
      });
    return () => {
      cancelled = true;
    };
  }, [name, queryDiamond]);

  return state;
}

export function HacdDiamondVisual({
  name,
  queryDiamond,
  openExternal,
  copy,
}: {
  name: string;
  queryDiamond: QueryHacdDiamond;
  openExternal: OpenExternal;
  copy?: Partial<HacdMetadataCopy>;
}) {
  const labels = { ...DEFAULT_HACD_METADATA_COPY, ...copy };
  const normalized = normalizeHacdName(name);
  const lookupName = isValidHacdName(normalized) ? normalized : null;
  const diamondState = useHacdDiamond(lookupName, queryDiamond);
  const hostRef = useRef<HTMLDivElement>(null);
  const [scale, setScale] = useState(0.32);

  useLayoutEffect(() => {
    const host = hostRef.current;
    if (!host) return;
    const fit = () => {
      const width = host.clientWidth || 320;
      setScale(Math.max(0.2, Math.min(1, width / 800)));
    };
    fit();
    if (typeof ResizeObserver === "undefined") return;
    const observer = new ResizeObserver(fit);
    observer.observe(host);
    return () => observer.disconnect();
  }, [diamondState.status, lookupName]);

  if (!normalized) return <PendingCard message={labels.invalidName} />;
  if (!lookupName) {
    return <PendingCard title={normalized} message={labels.invalidName} />;
  }
  if (diamondState.status === "loading" || diamondState.status === "idle") {
    return <PendingCard title={normalized} message={labels.metadataLoading} />;
  }
  if (diamondState.status === "not_found") {
    return <PendingCard title={normalized} message={labels.metadataNotFound} />;
  }
  if (diamondState.status === "error") {
    return <PendingCard title={normalized} message={labels.metadataUnavailable} />;
  }

  return (
    <div ref={hostRef} className="hacd-metadata-host">
      <ExplorerMetadataCard
        info={diamondState.info}
        displayName={normalized}
        scale={scale}
        openExternal={openExternal}
        copy={labels}
      />
    </div>
  );
}

function ExplorerMetadataCard({
  info,
  displayName,
  scale,
  openExternal,
  copy,
}: {
  info: HacdDiamondInfo;
  displayName: string;
  scale: number;
  openExternal: OpenExternal;
  copy: HacdMetadataCopy;
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
      const svg = renderHip5Svg(gene, 1000);
      const colors = hip5MainColors(gene);
      return {
        palette: hip5ColorPalette(gene),
        colors,
        gene,
        dataUrl: `data:image/svg+xml;charset=utf-8,${encodeURIComponent(svg)}`,
        hip8Url: svgDataUrl(() => renderHip8Svg(gene, 250, "#ffffff66", displayName)),
        hip9Url: info.life_gene
          ? svgDataUrl(() => renderHip9Svg(info.life_gene as string, 200))
          : null,
      };
    } catch {
      return null;
    }
  }, [displayName, gene, info.life_gene]);

  const explorerUrl = hacdExplorerUrl(displayName);
  const openExplorer = async (event: MouseEvent<HTMLAnchorElement>) => {
    event.preventDefault();
    if (!explorerUrl) return;
    try {
      await openExternal(explorerUrl);
    } catch {
      // Keep metadata usable if the platform URL opener is unavailable.
    }
  };

  const bornTail = info.born?.hash ? `...${info.born.hash.slice(-20)}` : "";
  const minerShort = info.miner ? `${info.miner.slice(0, 12)}...` : "";
  const lifeRows = splitLifeGene(info.life_gene);
  const visual = formatVisualGene(info.visual_gene ?? art?.gene);
  const gradient = art
    ? `linear-gradient(to right bottom, #${art.colors[0]}99, #${art.colors[1]})`
    : "#000000";
  const nameGradient = art ? paletteGradient(90, art.palette.slice(0, 6)) : undefined;
  const lifeGradient = art ? stripedGradient(-21, art.palette, false, 0) : undefined;
  const leftStripeGradient = art ? stripedGradient(135, art.palette, true, 6) : undefined;
  const rightStripeGradient = art
    ? paletteGradient(0, [art.palette[14], art.palette[12], art.palette[13], art.palette[15]])
    : undefined;
  const stripeSize =
    info.number == null
      ? 12
      : Math.max(2, Math.min(48, ((100_001 - info.number) / 100_000) * 48));

  return (
    <article className="hacd-metadata-card" data-hacd-name={displayName}>
      <a
        className="hacd-meta-cdit"
        href={explorerUrl ?? undefined}
        onClick={(event) => void openExplorer(event)}
        title={copy.viewExplorer}
      >
        <div
          className="hacd-meta-cdcon"
          style={{ transform: `scale(${scale})`, backgroundImage: gradient }}
        >
          {!art && (
            <div className="hacd-meta-noart">{copy.noVisual}</div>
          )}
          {art && (
            <>
              <div className="hacd-meta-ibg" aria-hidden>
                <img src={art.dataUrl} alt="" />
              </div>
              <div
                className="hacd-meta-ldz"
                aria-hidden
                style={{ backgroundSize: `${stripeSize}px ${stripeSize}px` }}
              />
              <div className="hacd-meta-img" aria-hidden>
                <img src={art.dataUrl} alt="" />
              </div>
              {art.hip8Url && (
                <div className="hacd-meta-oh hacd-meta-h8" aria-hidden>
                  <img src={art.hip8Url} alt="" />
                </div>
              )}
              {art.hip9Url && (
                <div className="hacd-meta-oh hacd-meta-h9" aria-hidden>
                  <img src={art.hip9Url} alt="" />
                </div>
              )}
            </>
          )}
          <div className="hacd-meta-overlay">
            <div className="hacd-meta-blk">
              {bornTail}
              <br />
              {copy.bornBlock}: <b>{info.born?.height ?? copy.notAvailable}</b>
            </div>
            <div
              className="hacd-meta-clb"
              aria-hidden
              style={{ backgroundImage: leftStripeGradient }}
            />
            <div className="hacd-meta-num">{info.number ?? ""}</div>
            <div
              className="hacd-meta-dn"
              style={{ backgroundImage: nameGradient }}
            >
              {displayName}
            </div>
            <p className="hacd-meta-lgn">{copy.lifeGenes}</p>
            <p
              className="hacd-meta-lg"
              style={{ backgroundImage: lifeGradient }}
            >
              {lifeRows.length > 0
                ? lifeRows.map((row, index) => (
                    <Fragment key={`${row}-${index}`}>
                      {row}
                      {index < lifeRows.length - 1 && <br />}
                    </Fragment>
                  ))
                : copy.notAvailable}
            </p>
            <div className="hacd-meta-vg">
              {visual ? (
                <>
                  <span className={visual.highlightFirst ? "hacd-meta-vg-a" : undefined}>
                    {visual.first}
                  </span>
                  {visual.middle}
                  <span className="hacd-meta-vg-dim">{visual.tail}</span>
                </>
              ) : (
                copy.notAvailable
              )}
            </div>
            <p className="hacd-meta-gmn">{copy.lifeGameCode}</p>
            <p className="hacd-meta-bid">
              {copy.bid}: {formatBidFee(info.bid_fee, copy.notAvailable)}
              <br />
              {minerShort}
            </p>
            <div
              className="hacd-meta-cll"
              aria-hidden
              style={{ backgroundImage: rightStripeGradient }}
            />
          </div>
        </div>
      </a>
      {info.metadata_source === "mainnet" && (
        <p className="hacd-meta-source">{copy.mainnetMetadata}</p>
      )}
      {/* The art above is a fixed replica of the official card, so it shows only what
          fits and truncates the miner and the born hash. Everything else the node
          returns is listed here in full: an owner or an inscription is worth more to
          the holder than a prettier layout. */}
      <dl className="hacd-meta-details">
        <dt>{copy.details}</dt>
        <dd />
        <dt>{copy.owner}</dt>
        <dd className="mono wrap">{info.belong ?? copy.notAvailable}</dd>
        <dt>{copy.minerFull}</dt>
        <dd className="mono wrap">{info.miner ?? copy.notAvailable}</dd>
        <dt>{copy.averageBidBurn}</dt>
        <dd>{info.average_bid_burn ?? copy.notAvailable}</dd>
        <dt>{copy.bornHash}</dt>
        <dd className="mono wrap">{info.born?.hash ?? copy.notAvailable}</dd>
        <dt>{copy.prevHash}</dt>
        <dd className="mono wrap">{info.prev_hash ?? copy.notAvailable}</dd>
        <dt>{copy.inscriptions}</dt>
        <dd>
          {info.inscriptions.length > 0 ? (
            <ul className="hacd-meta-inscriptions">
              {info.inscriptions.map((text, index) => (
                <li key={`${text}-${index}`}>{text}</li>
              ))}
            </ul>
          ) : (
            copy.noInscriptions
          )}
        </dd>
      </dl>
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

function formatBidFee(fee: string | null | undefined, notAvailable: string): string {
  const raw = String(fee || "").trim();
  return raw ? `\u311c${raw}` : notAvailable;
}

function svgDataUrl(factory: () => string): string | null {
  try {
    return `data:image/svg+xml;charset=utf-8,${encodeURIComponent(factory())}`;
  } catch {
    return null;
  }
}

function paletteGradient(
  angle: number,
  palette: ReadonlyArray<readonly [string, string]>,
): string {
  return `linear-gradient(${angle}deg, ${palette
    .flatMap((pair) => [`#${pair[0]}`, `#${pair[1]}`])
    .join(", ")})`;
}

function stripedGradient(
  angle: number,
  palette: ReadonlyArray<readonly [string, string]>,
  secondColor: boolean,
  offset: number,
): string {
  const stops: string[] = [];
  for (let index = 0; index < palette.length - 1; index += 1) {
    const start = index * (100 / palette.length) + offset;
    const colorIndex = secondColor ? 1 : 0;
    stops.push(
      `#${palette[index][colorIndex]} ${start}%`,
      `transparent ${start}%`,
      `transparent ${start + 1}%`,
      `#${palette[index + 1][colorIndex]} ${start + 1}%`,
    );
  }
  return `linear-gradient(${angle}deg, ${stops.join(", ")})`;
}

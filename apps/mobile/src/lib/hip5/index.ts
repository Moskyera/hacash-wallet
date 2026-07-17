import { diamondLifeGeneToVisualGene } from "./diamondGene";
// @ts-expect-error official Hacash explorer HIP-5 renderer (ported from hacash/explorer)
import { CreateDiamondImageTagSVG, GetDiamondMainColor } from "./diamondSvgImg.source.js";

export type Hip5RenderInput = {
  name: string;
  visualGene?: string | null;
  lifeGene?: string | null;
};

const VISUAL_GENE_RE = /^[0-9a-f]{20}$/i;
const LIFE_GENE_RE = /^[0-9a-f]{64}$/i;
const DIAMOND_NAME_RE = /^[WTYUIAHXVMEKBSZN]{4,6}$/i;
const HEX_COLOR_RE = /^[0-9a-f]{6}$/i;
const EMBEDDED_SVG_STYLE =
  "<style>.st16{fill:none;stroke:#f5e1da;stroke-width:2;stroke-linecap:round;stroke-linejoin:round;stroke-miterlimit:10}</style>";

export function resolveVisualGene(input: Hip5RenderInput): string | null {
  if (input.visualGene && VISUAL_GENE_RE.test(input.visualGene)) {
    return input.visualGene.toLowerCase();
  }
  if (input.lifeGene && LIFE_GENE_RE.test(input.lifeGene) && DIAMOND_NAME_RE.test(input.name)) {
    return diamondLifeGeneToVisualGene(input.lifeGene.toLowerCase(), input.name.toUpperCase());
  }
  return null;
}

export function renderHip5Svg(visualGene: string, size = 220): string {
  const normalized = requireVisualGene(visualGene);
  if (!Number.isInteger(size) || size < 32 || size > 1024) {
    throw new Error("Invalid HIP-5 image size");
  }
  const svg = CreateDiamondImageTagSVG(normalized, size);
  if (typeof svg !== "string" || svg.length > 250_000 || !/^<svg\b/i.test(svg.trimStart())) {
    throw new Error("Invalid HIP-5 renderer output");
  }
  return svg.replace(/(<svg\b[^>]*>)/i, `$1${EMBEDDED_SVG_STYLE}`);
}

export function hip5MainColors(visualGene: string): [string, string] {
  const pair = GetDiamondMainColor(requireVisualGene(visualGene), 1) as unknown;
  if (
    !Array.isArray(pair) ||
    pair.length !== 2 ||
    typeof pair[0] !== "string" ||
    typeof pair[1] !== "string" ||
    !HEX_COLOR_RE.test(pair[0]) ||
    !HEX_COLOR_RE.test(pair[1])
  ) {
    throw new Error("Invalid HIP-5 color output");
  }
  return [pair[0].toLowerCase(), pair[1].toLowerCase()];
}

function requireVisualGene(visualGene: string): string {
  if (!VISUAL_GENE_RE.test(visualGene)) {
    throw new Error("Invalid HIP-5 visual gene");
  }
  return visualGene.toLowerCase();
}

import { diamondLifeGeneToVisualGene } from "./diamondGene";
// @ts-expect-error official Hacash explorer HIP-5 renderer (ported from hacash/explorer)
import { CreateDiamondImageTagSVG, GetDiamondMainColor } from "./diamondSvgImg.source.js";

export type Hip5RenderInput = {
  name: string;
  visualGene?: string | null;
  lifeGene?: string | null;
};

export function resolveVisualGene(input: Hip5RenderInput): string | null {
  if (input.visualGene && input.visualGene.length >= 19) {
    return input.visualGene.toLowerCase();
  }
  if (input.lifeGene && input.lifeGene.length >= 64 && input.name.length >= 4) {
    return diamondLifeGeneToVisualGene(input.lifeGene.toLowerCase(), input.name.toUpperCase());
  }
  return null;
}

export function renderHip5Svg(visualGene: string, size = 220): string {
  return CreateDiamondImageTagSVG(visualGene.toLowerCase(), size);
}

export function hip5MainColors(visualGene: string): [string, string] {
  const pair = GetDiamondMainColor(visualGene.toLowerCase(), 1) as [string, string];
  return pair;
}
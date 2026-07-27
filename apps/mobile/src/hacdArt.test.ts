import { describe, expect, it } from "vitest";
import {
  hip5ColorPalette,
  renderHip8Svg,
  renderHip9Svg,
} from "@hacash/wallet-ui";

const VISUAL_GENE = "eaf6922956faf0e64f80";
const LIFE_GENE = "4a33dd1cbb53c422ddd30422eedc5504db559b88b5b6ef0a3fa0ce56647f68ea";

describe("HACD metadata artwork", () => {
  it("derives all sixteen official metadata palette entries", () => {
    const palette = hip5ColorPalette(VISUAL_GENE);
    expect(palette).toHaveLength(16);
    expect(palette[0]).toEqual(["f9e2ae", "a8dee0"]);
    expect(palette[15]).toEqual(["f9e2ae", "a8dee0"]);
  });

  it("renders deterministic, self-contained HIP-8 brilliance", () => {
    const first = renderHip8Svg(VISUAL_GENE, 125, "#ffffff66", "NHMYYM");
    const second = renderHip8Svg(VISUAL_GENE, 125, "#ffffff66", "NHMYYM");
    expect(first).toBe(second);
    expect(first).toContain('class="dvhip8"');
    expect(first).toContain('viewBox="0 0 1200 1200"');
    expect(first).not.toMatch(
      /<(?:script|foreignObject)\b|(?:href|src)\s*=\s*["']?\s*(?:https?:|javascript:)/i,
    );
  });

  it("renders the complete static HIP-9 Life Game seed without active content", () => {
    const svg = renderHip9Svg(LIFE_GENE, 100);
    const liveCells = Array.from(
      Uint8Array.from(LIFE_GENE.match(/.{2}/g)!.map((pair) => Number.parseInt(pair, 16))),
    ).reduce((total, byte) => total + byte.toString(2).replaceAll("0", "").length, 0);
    const renderedCells = (svg.match(/<(?:rect|circle|polygon)\b/g) ?? []).length - 1;

    expect(svg).toContain('class="dvhip9"');
    expect(renderedCells).toBeGreaterThanOrEqual(liveCells);
    expect(svg).not.toMatch(
      /<(?:script|foreignObject)\b|(?:href|src)\s*=\s*["']?\s*(?:https?:|javascript:)/i,
    );
  });

  it("rejects malformed genes instead of drawing misleading art", () => {
    expect(() => renderHip8Svg("bad")).toThrow();
    expect(() => renderHip9Svg("bad")).toThrow();
  });
});

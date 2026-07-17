import { describe, expect, it } from "vitest";
import { hip5MainColors, renderHip5Svg, resolveVisualGene } from "./index";

const VALID_VISUAL_GENE = "abcdef0123456789abcd";

describe("HIP-5 input validation", () => {
  it("accepts only exact hexadecimal visual genes", () => {
    expect(resolveVisualGene({ name: "WTYU", visualGene: VALID_VISUAL_GENE.toUpperCase() })).toBe(
      VALID_VISUAL_GENE,
    );

    for (const visualGene of ["0".repeat(19), "0".repeat(21), `${"0".repeat(19)}g`]) {
      expect(resolveVisualGene({ name: "WTYU", visualGene })).toBeNull();
    }
  });

  it("derives a visual gene only from a valid life gene and HACD name", () => {
    expect(resolveVisualGene({ name: "WTYU", lifeGene: "00".repeat(32) })).toMatch(/^[0-9a-f]{20}$/);
    expect(resolveVisualGene({ name: "WTYU<", lifeGene: "00".repeat(32) })).toBeNull();
    expect(resolveVisualGene({ name: "WTYU", lifeGene: `${"00".repeat(31)}0g` })).toBeNull();
  });

  it("rejects unsafe renderer inputs and returns bounded trusted output", () => {
    expect(() => renderHip5Svg(`${"0".repeat(19)}<`, 220)).toThrow("Invalid HIP-5 visual gene");
    expect(() => renderHip5Svg(VALID_VISUAL_GENE, 2048)).toThrow("Invalid HIP-5 image size");

    const svg = renderHip5Svg(VALID_VISUAL_GENE, 220);
    expect(svg.trimStart().startsWith("<svg")).toBe(true);
    expect(svg).toContain("<style>.st16{");
    expect(svg).not.toContain("<script");

    const colors = hip5MainColors(VALID_VISUAL_GENE);
    expect(colors).toHaveLength(2);
    expect(colors.every((color) => /^[0-9a-f]{6}$/.test(color))).toBe(true);
  });
});

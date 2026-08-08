import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const HERE = dirname(fileURLToPath(import.meta.url));
const ASSET_ROOT = join(HERE, "../../../packages/wallet-ui/src/assets");

describe("official Hacash asset marks", () => {
  for (const [file, id] of [
    ["hac.svg", "hac"],
    ["hacd.svg", "hacd"],
    ["btc-on-hacash.svg", "btc"],
  ] as const) {
    it(`keeps ${file} as a passive official-gold SVG`, () => {
      const svg = readFileSync(join(ASSET_ROOT, file), "utf8");
      expect(svg).toContain('viewBox="0 0 1200 1200"');
      expect(svg).toContain(`id="${id}"`);
      expect(svg.toLowerCase()).toContain("#f7af34");
      expect(svg).not.toMatch(/<script|<foreignObject|onload=/i);
    });
  }
});
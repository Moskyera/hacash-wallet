import { readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOTS = [HERE, join(HERE, "../../desktop/src"), join(HERE, "../../../packages/wallet-ui/src")];
const SOURCE_FILE = /\.(?:ts|tsx|js|jsx)$/;
const SKIP_FILE = /(?:\.test\.|uiCopy\.test\.ts$)/;

function sourceFiles(root: string): string[] {
  return readdirSync(root, { withFileTypes: true }).flatMap((entry) => {
    const path = join(root, entry.name);
    if (entry.isDirectory()) return sourceFiles(path);
    return SOURCE_FILE.test(entry.name) && !SKIP_FILE.test(entry.name) ? [path] : [];
  });
}

describe("wallet UI copy", () => {
  it("contains no replacement characters, common UTF-8 mojibake or em dashes", () => {
    const invalid: string[] = [];
    const patterns = [
      { label: "replacement character U+FFFD", value: /\uFFFD/u },
      {
        label: "UTF-8 mojibake",
        value:
          /(?:\u00C3[\u0080-\u00BF]|\u00C2[\u0080-\u00BF]|\u00E2\u20AC[\u00A0-\u00BF\u2018-\u201D]|\u00E2\u2030[\u00A0-\u00BF])/u,
      },
      { label: "em dash U+2014", value: /\u2014/u },
    ];

    for (const file of ROOTS.flatMap(sourceFiles)) {
      const source = readFileSync(file, "utf8");
      for (const pattern of patterns) {
        if (pattern.value.test(source)) invalid.push(`${file}: ${pattern.label}`);
      }
    }

    expect(invalid).toEqual([]);
  });
});

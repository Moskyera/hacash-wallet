import { readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const HERE = dirname(fileURLToPath(import.meta.url));
const APP_ROOT = join(HERE, "..");

/**
 * A test file that is never run is worse than no test at all.
 *
 * The `test` script names every vitest file explicitly rather than globbing.
 * That is a deliberate choice and it is kept, because the script also runs a
 * `node --test` file first and the explicit list makes the boundary between the
 * two runners visible. The cost is that adding a new `*.test.ts` under `src/`
 * does nothing: it passes when run by hand, it is silent in CI, and the person
 * who wrote it believes they are covered.
 *
 * That already happened once, to the guard that pins the mainnet node transport
 * rule on the agent create screen. It was written, it passed, and `yarn test`
 * reported the same 765 tests as before it existed.
 *
 * So the list has to be checked by something that runs. This is that something.
 * It is deliberately a comparison in both directions: a file on disk that the
 * script forgot is a silent gap, and a file in the script that no longer exists
 * would make the whole command fail for a reason nobody would guess.
 */
function testFilesUnder(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir)) {
    if (entry === "node_modules" || entry.startsWith(".")) continue;
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) {
      out.push(...testFilesUnder(full));
    } else if (/\.test\.tsx?$/.test(entry)) {
      out.push(relative(APP_ROOT, full).split("\\").join("/"));
    }
  }
  return out;
}

describe("the test script runs every test file", () => {
  const script: string = JSON.parse(
    readFileSync(join(APP_ROOT, "package.json"), "utf8"),
  ).scripts.test;
  const listed = new Set(
    script.split(/\s+/).filter((token) => /\.test\.tsx?$/.test(token)),
  );
  const onDisk = testFilesUnder(join(APP_ROOT, "src"));

  it("finds the files at all, so this test cannot pass by looking at nothing", () => {
    expect(onDisk.length).toBeGreaterThan(40);
    expect(listed.size).toBeGreaterThan(40);
  });

  it("names every test file that exists under src", () => {
    const forgotten = onDisk.filter((file) => !listed.has(file));
    expect(
      forgotten,
      `these test files exist but "yarn test" never runs them, so they are silent: ${forgotten.join(", ")}`,
    ).toEqual([]);
  });

  it("does not name a file that no longer exists", () => {
    const onDiskSet = new Set(onDisk);
    const stale = [...listed].filter(
      (file) => file.startsWith("src/") && !onDiskSet.has(file),
    );
    expect(
      stale,
      `these files are in the test script but not on disk, which fails the whole command: ${stale.join(", ")}`,
    ).toEqual([]);
  });
});

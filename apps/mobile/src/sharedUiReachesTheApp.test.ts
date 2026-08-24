import { readFileSync, readdirSync, statSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const HERE = dirname(fileURLToPath(import.meta.url));
const SHARED = join(HERE, "../../../packages/wallet-ui/src");

/**
 * A shared UI file the app cannot actually see is worse than a missing one.
 *
 * `@hacash/wallet-ui` installs as `file:../../packages/wallet-ui`, and most of
 * its sources land in node_modules as hardlinks, so editing them shows up in
 * the app straight away. Files added AFTER the last install do not: they are
 * copied, and the copy then never changes again. On 2026-08-24 both
 * HubDeclarationCard.tsx and signingTransport.ts were stale copies in both
 * apps, so every edit to the Hub declaration card since it was written had
 * been invisible to the running app while the source looked correct.
 *
 * This compares the bytes rather than the timestamps. It passes trivially in
 * CI, which installs fresh; its whole job is to fail on a developer's machine
 * before somebody spends an hour wondering why their change does nothing.
 *
 * Fix when it fails: reinstall, or copy the named file into the resolved
 * package directory.
 */
function resolvedSharedDir(app: "mobile" | "desktop"): string | null {
  const pnpm = join(HERE, `../../${app}/node_modules/.pnpm`);
  let entries: string[];
  try {
    entries = readdirSync(pnpm);
  } catch {
    return null;
  }
  for (const entry of entries) {
    if (!entry.startsWith("@hacash+wallet-ui@")) continue;
    const candidate = join(pnpm, entry, "node_modules/@hacash/wallet-ui/src");
    try {
      if (statSync(candidate).isDirectory()) return candidate;
    } catch {
      // keep looking
    }
  }
  return null;
}

const SOURCES = readdirSync(SHARED).filter((name) => /\.tsx?$/.test(name));

describe("shared wallet-ui reaches both apps", () => {
  it("has sources to check", () => {
    expect(SOURCES.length).toBeGreaterThan(5);
  });

  for (const app of ["mobile", "desktop"] as const) {
    it(`${app} resolves the same bytes this repo has`, () => {
      const resolved = resolvedSharedDir(app);
      if (!resolved) {
        // Dependencies are not installed for this app; nothing to compare.
        return;
      }
      const stale: string[] = [];
      for (const name of SOURCES) {
        let installed: string;
        try {
          installed = readFileSync(join(resolved, name), "utf8");
        } catch {
          stale.push(`${name} (missing from the installed package)`);
          continue;
        }
        if (installed !== readFileSync(join(SHARED, name), "utf8")) {
          stale.push(name);
        }
      }
      expect(stale).toEqual([]);
    });
  }
});

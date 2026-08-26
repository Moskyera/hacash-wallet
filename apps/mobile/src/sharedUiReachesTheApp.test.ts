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
/**
 * EVERY directory this package resolves to, not just the tidy one.
 *
 * This used to look only under `node_modules/.pnpm`, and that is the copy the
 * app does not read. On this machine `apps/<app>/node_modules/@hacash/wallet-ui`
 * is a real directory holding its own copies, not a link to the .pnpm store,
 * and node's own resolver names it:
 *
 * ```
 * $ node -e "require.resolve('@hacash/wallet-ui/package.json')"
 * ERR_PACKAGE_PATH_NOT_EXPORTED ... apps\mobile\node_modules\@hacash\wallet-ui\package.json
 * ```
 *
 * So the check was watching one shelf while the app read from another. A file
 * could be stale in the copy that renders on screen and this test would pass.
 * Proven by corrupting `securityPolicy.ts` in the top-level directory: three
 * tests passed, and the corrupted string was the one the app would have shown.
 *
 * Both are compared now. Duplicates cost a few file reads and nothing else,
 * and if one path is ever a link to the other the bytes simply agree twice.
 */
function resolvedSharedDirs(app: "mobile" | "desktop"): string[] {
  const found: string[] = [];
  const direct = join(HERE, `../../${app}/node_modules/@hacash/wallet-ui/src`);
  try {
    if (statSync(direct).isDirectory()) found.push(direct);
  } catch {
    // not installed for this app
  }
  const pnpm = join(HERE, `../../${app}/node_modules/.pnpm`);
  let entries: string[];
  try {
    entries = readdirSync(pnpm);
  } catch {
    return found;
  }
  for (const entry of entries) {
    if (!entry.startsWith("@hacash+wallet-ui@")) continue;
    const candidate = join(pnpm, entry, "node_modules/@hacash/wallet-ui/src");
    try {
      if (statSync(candidate).isDirectory()) found.push(candidate);
    } catch {
      // keep looking
    }
  }
  return found;
}

/**
 * Every shared source, including the ones in subdirectories.
 *
 * This used to read the top level only, and the gap had teeth: `locales/` is
 * where the product's copy lives, so the one directory whose whole purpose is
 * words a person reads was the one directory the drift check could not see. A
 * stale `locales/en.ts` shows the old sentence on screen while the repository
 * shows the new one, which is precisely the hour-of-confusion this file exists
 * to prevent.
 */
function sharedSources(dir = SHARED, prefix = ""): string[] {
  const found: string[] = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const name = prefix ? `${prefix}/${entry.name}` : entry.name;
    if (entry.isDirectory()) {
      found.push(...sharedSources(join(dir, entry.name), name));
    } else if (/\.tsx?$/.test(entry.name)) {
      found.push(name);
    }
  }
  return found;
}

const SOURCES = sharedSources();

describe("shared wallet-ui reaches both apps", () => {
  it("has sources to check", () => {
    expect(SOURCES.length).toBeGreaterThan(5);
  });

  for (const app of ["mobile", "desktop"] as const) {
    it(`${app} resolves the same bytes this repo has`, () => {
      const resolved = resolvedSharedDirs(app);
      if (resolved.length === 0) {
        // Dependencies are not installed for this app; nothing to compare.
        return;
      }
      const stale: string[] = [];
      for (const dir of resolved) {
        for (const name of SOURCES) {
          let installed: string;
          try {
            installed = readFileSync(join(dir, name), "utf8");
          } catch {
            stale.push(`${dir}: ${name} (missing from the installed package)`);
            continue;
          }
          if (installed !== readFileSync(join(SHARED, name), "utf8")) {
            stale.push(`${dir}: ${name}`);
          }
        }
      }
      expect(stale).toEqual([]);
    });
  }
});

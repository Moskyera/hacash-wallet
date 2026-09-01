import path from "node:path";
import { fileURLToPath } from "node:url";
import { execSync } from "node:child_process";
import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";

const appRoot = path.dirname(fileURLToPath(import.meta.url));

/**
 * Short identifier for the build actually running on a device.
 *
 * Every build produces the same file name and the same versionName, so a field report
 * like "nothing changed" cannot be told apart from "you installed the wrong file". The
 * commit, plus a dirty marker for uncommitted work, makes that unambiguous.
 */
function buildId(): string {
  try {
    const commit = execSync("git rev-parse --short=8 HEAD", { cwd: appRoot })
      .toString()
      .trim();
    const dirty = execSync("git status --porcelain -- . ../../crates ../../packages", {
      cwd: appRoot,
    })
      .toString()
      .trim();
    return dirty ? `${commit}+local` : commit;
  } catch {
    return "unknown";
  }
}

export default defineConfig({
  root: appRoot,
  test: {
    environment: "node",
    /*
     * `.tsx` as well as `.ts`.
     *
     * The mobile suite could not contain a component test, because the glob only
     * matched `.ts`. Every mobile assertion was therefore about a pure function
     * or about the text of a source file, and a whole family of defects - a
     * control that renders but is never reachable, a message the core produces
     * and the screen never prints - was invisible to all 344 of them by
     * construction. Individual files opt into a DOM with `@vitest-environment
     * jsdom`; the default stays `node`, so nothing already here pays for it.
     */
    include: ["src/**/*.test.ts", "src/**/*.test.tsx"],
  },
  define: {
    __BUILD_ID__: JSON.stringify(buildId()),
  },
  plugins: [react()],
  optimizeDeps: {
    include: ["html5-qrcode/esm/index.js", "qrcode"],
  },
  clearScreen: false,
  server: {
    host: "127.0.0.1",
    port: 1421,
    strictPort: true,
  },
  envPrefix: ["VITE_", "TAURI_"],
});
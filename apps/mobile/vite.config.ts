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
    include: ["src/**/*.test.ts"],
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
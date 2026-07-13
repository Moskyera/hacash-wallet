import path from "node:path";
import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";

const appRoot = path.dirname(fileURLToPath(import.meta.url));

export default defineConfig({
  root: appRoot,
  test: {
    environment: "node",
    include: ["src/**/*.test.ts"],
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
/**
 * NO CONTROL MAY REPORT A FILE IT DID NOT WRITE.
 *
 * Three mobile controls exported something a person depends on - the encrypted
 * post-quantum keystore, one Fast Pay dispute bill, and all of them at once -
 * and all three used the same dead path:
 *
 *     a.download = filename; a.click(); URL.revokeObjectURL(url);
 *     setMsg("Exported ...");           // unconditional
 *
 * Android's System WebView routes downloads through a `DownloadListener`, and
 * the generated shell installs none: grep the generated `RustWebView.kt` for
 * "download" and there are zero hits, while `RustWebChromeClient.kt` does
 * implement `onJsAlert`, `onJsConfirm` and `onShowFileChooser`. So the click is
 * inert, nothing throws, the catch never runs, and the success message always
 * prints. A person was told their dispute evidence and their keystore were off
 * the device when no file had been created.
 *
 * These are source-level assertions on purpose. The defect is a SHAPE, and the
 * shape is what must not come back.
 */
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

function source(relative: string): string {
  return readFileSync(new URL(relative, import.meta.url), "utf8");
}

const EXPORTING_FILES = [
  "./components/KeystoreV3Modal.tsx",
  "./components/BillDetailModal.tsx",
  "./screens/more/MoreRouter.tsx",
  "./utils/downloadJson.ts",
];

describe("the dead anchor-download path is gone from every export control", () => {
  for (const file of EXPORTING_FILES) {
    it(`${file} does not click a detached download anchor`, () => {
      const text = source(file);
      expect(
        text,
        `${file} still sets a.download and clicks it, which does nothing on Android`,
      ).not.toMatch(/\.download\s*=/);
    });

    it(`${file} does not revoke an object URL synchronously`, () => {
      const text = source(file);
      // The revoke that runs in the same task as the click breaks the download
      // even on platforms where downloads work at all.
      expect(text).not.toContain("URL.revokeObjectURL");
    });
  }
});

describe("every export control reports the real outcome", () => {
  it("the keystore export branches on the handoff result", () => {
    const text = source("./components/KeystoreV3Modal.tsx");
    expect(text).toContain("handOffTextFile");
    expect(text).toContain("handoff.ok");
    // The old sentence claimed a completed export outright.
    expect(text).not.toContain('setMsg(`Exported ${meta.address ?? "keystore"}`)');
  });

  it("the single-bill export branches on the handoff result", () => {
    const text = source("./components/BillDetailModal.tsx");
    expect(text).toContain("handOffTextFile");
    expect(text).toContain("handoff.ok");
    expect(text).not.toContain('setMsg("Bill JSON downloaded.")');
  });

  it("the all-bills export branches on the handoff result", () => {
    const text = source("./screens/more/MoreRouter.tsx");
    expect(text).toContain("handoff.ok");
    expect(text).not.toContain('onToast("All bills exported.", "success")');
  });

  it("names the copy control that does work, when the file one cannot", () => {
    // "Copy bill hex" is proven to work on this platform. A refusal that offers
    // no route is only half the fix.
    const bill = source("./components/BillDetailModal.tsx");
    const bills = source("./screens/more/MoreRouter.tsx");
    expect(bill).toContain("Copy bill hex");
    expect(bills).toContain("Copy bill hex");
  });

  it("downloadJson returns a result rather than void", () => {
    const text = source("./utils/downloadJson.ts");
    // A `void` return is what let three callers assume success. The type now
    // makes the outcome impossible to ignore silently.
    expect(text).toMatch(/downloadJson\([^)]*\)\s*:\s*Promise<FileHandoff>/s);
  });
});

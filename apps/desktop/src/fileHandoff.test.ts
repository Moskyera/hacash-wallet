/**
 * A SUCCESS MESSAGE THAT IS NOT EVIDENCE OF A FILE.
 *
 * Six controls across the two apps shared one shape:
 *
 *   const url = URL.createObjectURL(blob);
 *   const a = document.createElement("a");
 *   a.download = filename;
 *   a.click();
 *   URL.revokeObjectURL(url);      // same synchronous task
 *   onInfo("... exported.");       // unconditional
 *
 * `a.click()` returns void, so nothing can ever reach the catch, and the
 * success sentence is printed whether or not a byte was written. Two separate
 * things are wrong with it:
 *
 * 1. The revoke runs in the same task as the click, before the WebView has had
 *    a turn to read the blob. That can break the download even where downloads
 *    work at all.
 * 2. On Android it cannot work under any circumstances. Downloads there are
 *    routed through a DownloadListener and the generated shell installs none
 *    (0 hits for "download" in the generated RustWebView.kt, while
 *    RustWebChromeClient.kt does implement onJsAlert, onJsConfirm and
 *    onShowFileChooser - so this is a specific gap, not a blanket one).
 *
 * The controls affected are the wallet backup, the encrypted post-quantum
 * keystore, and the signed Fast Pay dispute bills. For a wallet backup, being
 * told a file exists when it does not is the most expensive lie in the app.
 *
 * This helper never claims more than it did.
 */
import { describe, expect, it, vi } from "vitest";
import { browserDownloadIsHonoured, handOffTextFile } from "@hacash/wallet-ui";

const ANDROID_UA =
  "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) " +
  "Version/4.0 Chrome/120.0.0.0 Mobile Safari/537.36";
const WINDOWS_UA =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) " +
  "Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0";

describe("knowing whether a browser download can work at all", () => {
  it("says no on an Android WebView", () => {
    expect(browserDownloadIsHonoured(ANDROID_UA, true)).toBe(false);
  });

  it("says yes on the desktop WebView2", () => {
    expect(browserDownloadIsHonoured(WINDOWS_UA, true)).toBe(true);
  });

  it("says no when the anchor has no download attribute support", () => {
    expect(browserDownloadIsHonoured(WINDOWS_UA, false)).toBe(false);
  });
});

/** A fake anchor that records what was done to it. */
function fakeDom() {
  const clicks: string[] = [];
  const revoked: string[] = [];
  const anchor = {
    href: "",
    download: "",
    style: {} as Record<string, string>,
    click: () => clicks.push(anchor.download),
    remove: () => undefined,
  };
  return {
    clicks,
    revoked,
    doc: {
      createElement: () => anchor,
      body: { appendChild: () => undefined, removeChild: () => undefined },
    } as unknown as Document,
    urls: {
      createObjectURL: () => "blob:fake",
      revokeObjectURL: (u: string) => revoked.push(u),
    },
  };
}

describe("handing a file to the browser, and saying only what happened", () => {
  it("clicks an anchor carrying the filename when downloads are honoured", async () => {
    const dom = fakeDom();
    const result = await handOffTextFile("bills.json", "{}", {
      userAgent: WINDOWS_UA,
      documentRef: dom.doc,
      urlRef: dom.urls,
      revokeAfterMs: 0,
    });
    expect(dom.clicks).toEqual(["bills.json"]);
    expect(result.ok).toBe(true);
  });

  it("does NOT revoke the blob in the same task as the click", async () => {
    // The synchronous revoke is what could break the download even on a
    // platform that supports it.
    const dom = fakeDom();
    await handOffTextFile("bills.json", "{}", {
      userAgent: WINDOWS_UA,
      documentRef: dom.doc,
      urlRef: dom.urls,
      revokeAfterMs: 5000,
    });
    expect(dom.revoked).toEqual([]);
  });

  it("refuses to click at all on Android, and says so", async () => {
    const dom = fakeDom();
    const result = await handOffTextFile("bills.json", "{}", {
      userAgent: ANDROID_UA,
      documentRef: dom.doc,
      urlRef: dom.urls,
    });
    expect(dom.clicks).toEqual([]);
    expect(result.ok).toBe(false);
    expect(result.message.toLowerCase()).toContain("no file was written");
  });

  it("hands the text back when it could not write it, so nothing is lost", async () => {
    const dom = fakeDom();
    const result = await handOffTextFile("bills.json", '{"a":1}', {
      userAgent: ANDROID_UA,
      documentRef: dom.doc,
      urlRef: dom.urls,
    });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.text).toBe('{"a":1}');
    }
  });

  it("never says the word exported when nothing was exported", async () => {
    const dom = fakeDom();
    const result = await handOffTextFile("wallet-backup.json", "{}", {
      userAgent: ANDROID_UA,
      documentRef: dom.doc,
      urlRef: dom.urls,
    });
    expect(result.message.toLowerCase()).not.toContain("exported.");
  });

  it("does not overclaim on the platform where it does work either", async () => {
    // Even on WebView2 the page cannot observe whether the user's browser
    // actually wrote the file, so the wording is about the handoff.
    const dom = fakeDom();
    const result = await handOffTextFile("wallet-backup.json", "{}", {
      userAgent: WINDOWS_UA,
      documentRef: dom.doc,
      urlRef: dom.urls,
      revokeAfterMs: 0,
    });
    expect(result.message).toContain("wallet-backup.json");
    expect(result.message.toLowerCase()).toContain("check your downloads");
  });

  it("reports a thrown failure instead of swallowing it", async () => {
    const dom = fakeDom();
    const result = await handOffTextFile("bills.json", "{}", {
      userAgent: WINDOWS_UA,
      documentRef: dom.doc,
      urlRef: {
        createObjectURL: () => {
          throw new Error("createObjectURL blew up");
        },
        revokeObjectURL: () => undefined,
      },
    });
    expect(result.ok).toBe(false);
    // The old shape could not report this at all: `a.click()` returns void and
    // the whole block was outside any catch that reached the person.
    expect(result.message).toContain("createObjectURL blew up");
  });
});

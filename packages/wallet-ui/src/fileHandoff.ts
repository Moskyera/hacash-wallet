/**
 * Handing a file to the platform, and saying only what actually happened.
 *
 * WHY THIS EXISTS. Six controls across the two apps shared one shape:
 *
 *     const url = URL.createObjectURL(blob);
 *     const a = document.createElement("a");
 *     a.download = filename;
 *     a.click();
 *     URL.revokeObjectURL(url);        // same synchronous task
 *     onInfo("... exported.");         // unconditional
 *
 * `a.click()` returns void, so no failure can ever reach the catch, and the
 * success sentence printed whether or not a byte was written. Two separate
 * things are wrong with that:
 *
 * 1. The revoke runs in the same task as the click, before the WebView has had
 *    a turn to read the blob. That can break the download even where downloads
 *    work at all.
 * 2. On Android it cannot work under any circumstances. Downloads there are
 *    routed through a `DownloadListener` and the generated shell installs none.
 *    `onJsAlert`, `onJsConfirm` and `onShowFileChooser` ARE implemented in
 *    `RustWebChromeClient.kt`, so this is a specific gap rather than a blanket
 *    one, and `<a download>` is simply inert.
 *
 * The controls affected are the full wallet backup, the encrypted post-quantum
 * keystore, and the signed Fast Pay dispute bills - a wallet's keys and the
 * evidence needed to contest a channel. Being told a file exists when it does
 * not is the most expensive lie in the app.
 *
 * So this never claims more than it did. Where it cannot write, it says no file
 * was written and hands the text back, so the caller can offer a route that does
 * work: the native Downloads command, or the clipboard, both of which are
 * already proven on the platform.
 */

export type FileHandoff =
  | { ok: true; message: string }
  | { ok: false; message: string; text: string };

export type FileHandoffOptions = {
  /** Injected for tests; defaults to the real navigator. */
  userAgent?: string;
  /** Injected for tests; defaults to the real document. */
  documentRef?: Document;
  /** Injected for tests; defaults to the real URL object. */
  urlRef?: { createObjectURL: (b: Blob) => string; revokeObjectURL: (u: string) => void };
  /**
   * How long to leave the object URL alive after the click.
   *
   * Never zero in production. The original code revoked synchronously, which is
   * the half of this defect that also bites on platforms where downloads work.
   */
  revokeAfterMs?: number;
  mimeType?: string;
};

/**
 * Can a `<a download>` click possibly result in a file on this platform?
 *
 * `hasDownloadAttribute` is passed separately so the check is testable without
 * a DOM, and so a browser too old to support the attribute is also excluded.
 */
export function browserDownloadIsHonoured(
  userAgent: string,
  hasDownloadAttribute: boolean,
): boolean {
  if (!hasDownloadAttribute) return false;
  // The Android System WebView needs a DownloadListener that this shell does
  // not install. Nothing the page does can compensate for that.
  if (/\bAndroid\b/i.test(userAgent)) return false;
  return true;
}

function defaultDownloadSupport(documentRef: Document | undefined): boolean {
  if (!documentRef) return false;
  try {
    return "download" in documentRef.createElement("a");
  } catch {
    return false;
  }
}

export async function handOffTextFile(
  filename: string,
  text: string,
  options: FileHandoffOptions = {},
): Promise<FileHandoff> {
  const documentRef =
    options.documentRef ?? (typeof document === "undefined" ? undefined : document);
  const urlRef =
    options.urlRef ?? (typeof URL === "undefined" ? undefined : URL);
  const userAgent =
    options.userAgent ??
    (typeof navigator === "undefined" ? "" : navigator.userAgent);
  const revokeAfterMs = options.revokeAfterMs ?? 60_000;

  const unavailable = (why: string): FileHandoff => ({
    ok: false,
    message: `No file was written: ${why}`,
    text,
  });

  if (!documentRef || !urlRef) {
    return unavailable("this window has no document to hand a file to.");
  }
  if (!browserDownloadIsHonoured(userAgent, defaultDownloadSupport(documentRef))) {
    // Deliberately does not order somebody to press a named control. Not every
    // screen that reaches this has one: the bill sheets carry "Copy bill hex"
    // and say so themselves, and the post-quantum keystore modal carries no
    // copy route at all. Naming a control here that a given screen does not
    // have is the same kind of lie as the success message this replaces, so the
    // shared sentence states the platform fact and each caller names its own
    // route where it has one.
    return unavailable(
      "this app's webview does not carry out browser downloads, so a save link here " +
        "would do nothing at all. Where this screen offers a copy control or a " +
        "Downloads export, that route does work.",
    );
  }

  try {
    const blob = new Blob([text], { type: options.mimeType ?? "application/json" });
    const url = urlRef.createObjectURL(blob);
    const anchor = documentRef.createElement("a");
    anchor.href = url;
    anchor.download = filename;
    anchor.style.display = "none";
    documentRef.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    // NOT in this task. The synchronous revoke is the half of the original
    // defect that bites even where downloads work.
    setTimeout(() => urlRef.revokeObjectURL(url), revokeAfterMs);
    return {
      ok: true,
      // Deliberately about the handoff, not about a file. The page cannot
      // observe whether the browser wrote anything, so it does not say it did.
      message: `${filename} was handed to your browser to save. Check your downloads folder, and if it is not there your browser blocked it.`,
    };
  } catch (error) {
    return unavailable(
      error instanceof Error ? error.message : String(error),
    );
  }
}

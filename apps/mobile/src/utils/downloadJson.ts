import { handOffTextFile, type FileHandoff } from "@hacash/wallet-ui";

/**
 * Hand a JSON file to the platform, and report what actually happened.
 *
 * THE OLD VERSION OF THIS FILE COULD NOT WORK ON ANDROID AT ALL. It built a
 * blob, set `a.download`, called `a.click()` and revoked the object URL in the
 * same synchronous task. Android's System WebView routes downloads through a
 * `DownloadListener` and the generated shell installs none: grep the generated
 * `RustWebView.kt` for "download" and there are zero hits, while
 * `RustWebChromeClient.kt` does implement `onJsAlert`, `onJsConfirm` and
 * `onShowFileChooser`. So this is a specific gap, not a blanket one, and
 * `<a download>` is inert. Nothing threw, so every caller printed its success
 * message and the person was told their dispute evidence or their keystore was
 * off the device when no file had been created.
 *
 * The return value is now a result the caller MUST turn into a message. It is
 * deliberately not `void`: a caller that ignores it will not typecheck into a
 * false success the way the old signature invited.
 */
export function downloadJson(filename: string, content: string): Promise<FileHandoff> {
  return handOffTextFile(filename, content);
}

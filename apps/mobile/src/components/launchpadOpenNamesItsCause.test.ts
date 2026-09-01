/**
 * "OPEN" ON THE HACD LAUNCHPAD, AND THE WRONG CAUSE IT REPORTED.
 *
 * The Launchpad's "Open" mounts a dApp in an embedded panel with
 * `new Webview(getCurrentWindow(), LAUNCHPAD_WEBVIEW_LABEL, {...})`, which
 * invokes `plugin:webview|create_webview`.
 *
 * In tauri 2.11.3 that command is registered as
 * `#[cfg(desktop)] desktop_commands::create_webview` (src/webview/plugin.rs:236)
 * inside a `#[cfg(desktop)] mod desktop_commands` (line 43). On Android the
 * command is not compiled in at all, so the promise rejects with a
 * command-not-found error. The mobile default capability DOES grant
 * `core:webview:allow-create-webview`, so the ACL is not what stops it.
 *
 * The mount's catch was `catch {` with no binding: it discarded the error and
 * called a fixed handler that toasted `copy.connectionError`. The panel flashed,
 * disappeared, and the person was told their dApp CONNECTION had failed - a
 * different and untrue cause, which sends them to check their network.
 *
 * The platform limit is real and is not being papered over. What changes is that
 * the sentence names it.
 */
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

const source = readFileSync(new URL("./LaunchpadScreen.tsx", import.meta.url), "utf8");

describe("a failed dApp open reports what actually failed", () => {
  it("does not throw the error away with a bare catch", () => {
    expect(
      source,
      "`catch {` with no binding is how the real cause was lost",
    ).not.toMatch(/}\s*catch\s*\{\s*\n\s*if \(webview\)/);
  });

  it("passes a reason to the error handler", () => {
    // `onError: () => void` could not carry one. It has to take the reason.
    expect(source).toMatch(/onError:\s*\(reason/);
  });

  it("recognises the platform limit specifically", () => {
    expect(source).toMatch(/embeddedDappSupport|dappPanelUnsupported/);
  });

  it("names the desktop requirement rather than blaming the network", () => {
    expect(source).toMatch(/desktop/i);
  });

  it("still keeps the generic connection wording for a real connection failure", () => {
    // The false cause was wrong here, not wrong everywhere. A genuine transport
    // failure should still say so.
    expect(source).toContain("connectionError");
  });
});

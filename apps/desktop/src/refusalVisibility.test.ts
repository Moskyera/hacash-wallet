import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { describe, it } from "vitest";

/**
 * The desktop app produced its refusals and then threw them away.
 *
 * `onError` does two things: it sets `wallet.error`, which renders as
 * `<div className="alert">` at the top of `<main>`, and it calls `showToast`,
 * which renders `<div className="toast toast-error">` in the same place and
 * deletes itself after 4000ms. Both sit above `<DesktopRouter>` in normal
 * document flow, and only `.desktop-topbar` is sticky, so neither follows the
 * scroll. The "Enable Fast Pay" button is roughly two thousand pixels below
 * that point.
 *
 * On top of that, no desktop stylesheet defined `.toast` at ALL. Mobile has the
 * rule at mobile.css:935 (position fixed, top 16px, z-index 200); the desktop
 * app never got it. So the toast was an unstyled block, off-screen, that then
 * removed itself. Pressing a button that refused was indistinguishable from
 * pressing a button that did nothing.
 *
 * These assertions are about the CSS being present and being of the kind that
 * can reach the eye from anywhere on a long page: fixed positioning and a stacking
 * order above the sticky topbar. A `.toast` rule that scrolled away with the
 * document would satisfy "defined" and still not be readable.
 */
const styles = readFileSync(new URL("./styles.css", import.meta.url), "utf8");
const dashboard = readFileSync(new URL("./dashboard.css", import.meta.url), "utf8");
const allDesktopCss = `${styles}\n${dashboard}`;
const appSource = readFileSync(new URL("./App.tsx", import.meta.url), "utf8");

function ruleBody(css: string, selector: string): string {
  const at = css.indexOf(`${selector} {`);
  assert.notEqual(at, -1, `no desktop stylesheet defines a "${selector} {" rule`);
  const open = css.indexOf("{", at);
  const close = css.indexOf("}", open);
  return css.slice(open + 1, close);
}

describe("desktop refusals are visible from the control that produced them", () => {
  it("defines a .toast rule at all", () => {
    // grep -c toast returned 0 for every desktop stylesheet before this fix.
    assert.ok(
      allDesktopCss.includes(".toast {"),
      "the desktop app renders <div className={`toast toast-${kind}`}> but no desktop " +
        "stylesheet defines .toast, so every toast is an unstyled block in normal flow",
    );
  });

  it("pins the toast to the viewport so it is readable from the bottom of a long screen", () => {
    const body = ruleBody(allDesktopCss, ".toast");
    assert.match(
      body,
      /position:\s*fixed/,
      ".toast must be position:fixed. In normal flow it renders at the top of <main>, " +
        "above the router, and the Enable Fast Pay button is far below the fold.",
    );
  });

  it("stacks the toast above the sticky topbar", () => {
    const body = ruleBody(allDesktopCss, ".toast");
    const zIndex = /z-index:\s*(\d+)/.exec(body);
    assert.ok(zIndex, ".toast must declare a z-index");
    const topbar = ruleBody(dashboard, ".desktop-topbar");
    const topbarZ = /z-index:\s*(\d+)/.exec(topbar);
    assert.ok(topbarZ, ".desktop-topbar is expected to declare a z-index");
    assert.ok(
      Number(zIndex[1]) > Number(topbarZ[1]),
      `.toast z-index ${zIndex[1]} must be above .desktop-topbar z-index ${topbarZ[1]}, ` +
        "or the sticky header covers the refusal",
    );
  });

  it("styles the error toast distinctly from the success toast", () => {
    assert.ok(allDesktopCss.includes(".toast-error"), "no .toast-error rule");
    assert.ok(allDesktopCss.includes(".toast-success"), "no .toast-success rule");
    assert.notEqual(
      ruleBody(allDesktopCss, ".toast-error").trim(),
      ruleBody(allDesktopCss, ".toast-success").trim(),
      "a refusal and a confirmation must not look identical",
    );
  });

  it("keeps the persistent error banner pinned too, since the toast self-deletes", () => {
    // useToast clears itself after TOAST_MS = 4000. The `.alert` banner is the
    // copy that stays, so it is the one a person can still read after walking
    // back to the screen. It is rendered in the same off-screen position.
    assert.ok(
      appSource.includes('className="alert alert-floating"'),
      'the wallet.error banner must carry a pinned class; it renders above <DesktopRouter> ' +
        "in normal flow and is off-screen for any control below the fold",
    );
    const body = ruleBody(allDesktopCss, ".alert-floating");
    assert.match(body, /position:\s*fixed/, ".alert-floating must be position:fixed");
  });

  it("gives the persistent error banner a way to be dismissed", () => {
    // A pinned banner that cannot be closed is an obstruction. The toast expires
    // on its own; this one does not, so it needs a control.
    assert.ok(
      appSource.includes("alert-floating-dismiss"),
      "the pinned error banner must offer a dismiss control",
    );
  });

  it("marks the error banner as an alert for assistive technology", () => {
    assert.match(
      appSource,
      /className="alert alert-floating"[\s\S]{0,120}role="alert"/,
      'the refusal banner must carry role="alert" so it is announced, not just drawn',
    );
  });
});

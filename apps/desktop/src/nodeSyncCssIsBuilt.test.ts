/**
 * EVERY CLASS THIS SURFACE RENDERS, PROVEN PRESENT IN THE SHIPPED CSS.
 *
 * Yesterday the wallet had a whole family of invisible failures because
 * `.toast` was written into the markup and defined in no desktop stylesheet at
 * all: grep counted 0 in styles.css, 0 in dashboard.css, 0 in quantum.css,
 * while mobile.css had the rule. Every refusal on the Fast Pay screen went into
 * an unstyled block off screen and deleted itself four seconds later, which is
 * why the Enable button looked dead for two days.
 *
 * So this test does not read the source stylesheets. Source is where a rule
 * looks defined. It reads the BUILT asset in dist, which is the only file the
 * person running the wallet ever sees, and it reads both apps, because "styled
 * on desktop, bare on the phone" is the same defect wearing a different hat.
 *
 * If this fails with "no built stylesheet", the fix is to build, not to relax
 * the assertion:
 *
 *   npm --prefix apps/desktop run build
 *   npm --prefix apps/mobile run build
 */
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, it } from "vitest";

const DESKTOP_DIST = fileURLToPath(new URL("../dist/assets", import.meta.url));
const MOBILE_DIST = fileURLToPath(new URL("../../mobile/dist/assets", import.meta.url));

/**
 * Every class the sync surface puts in the DOM. Kept as a literal list rather
 * than scraped from the component, because a list that derives itself from the
 * markup agrees with the markup by construction and would have passed happily
 * while `.toast` was undefined.
 */
const CLASSES_RENDERED = [
  ".node-sync",
  ".node-sync-chain",
  ".node-sync-live",
  ".node-sync-distance",
  ".node-sync-track",
  ".node-sync-fill",
  ".node-sync-eta",
  ".node-sync-unknown",
  ".node-sync-waiting",
];

/** The four tones the chain line is drawn with, one per verdict. */
const TONES = [
  ".node-sync-chain.tone-ok",
  ".node-sync-chain.tone-warn",
  ".node-sync-chain.tone-bad",
  ".node-sync-chain.tone-idle",
];

function builtCss(dist: string, app: string): string {
  let entries: string[] = [];
  try {
    entries = readdirSync(dist);
  } catch {
    assert.fail(
      `no built assets for ${app} at ${dist}. Run \`npm --prefix apps/${app} run build\`; ` +
        "this gate reads the shipped stylesheet on purpose, because a rule that " +
        "does not survive the bundler is a rule that does not exist.",
    );
  }
  const sheets = entries.filter((name) => name.endsWith(".css"));
  assert.ok(sheets.length > 0, `${app} built no .css asset at all`);
  return sheets.map((name) => readFileSync(join(dist, name), "utf8")).join("\n");
}

const desktop = builtCss(DESKTOP_DIST, "desktop");
const mobile = builtCss(MOBILE_DIST, "mobile");

describe("the sync surface is styled in the file that actually ships", () => {
  for (const [app, css] of [
    ["desktop", desktop],
    ["mobile", mobile],
  ] as const) {
    for (const selector of CLASSES_RENDERED) {
      it(`defines ${selector} in the built ${app} stylesheet`, () => {
        assert.ok(
          css.includes(`${selector}{`) || css.includes(`${selector} {`) ||
            css.includes(`${selector},`),
          `${selector} is rendered by NodeSyncProgress but no rule for it survived into the ` +
            `built ${app} stylesheet. This is the .toast defect: markup with no CSS behind it.`,
        );
      });
    }

    for (const selector of TONES) {
      it(`gives ${selector} its own look in the built ${app} stylesheet`, () => {
        const flat = css.replace(/\s+/g, "");
        assert.ok(
          flat.includes(selector.replace(/\s+/g, "")),
          `${selector} decides whether a person reads "your node is fine" or "this is not ` +
            `Hacash mainnet", and it is undefined in the built ${app} stylesheet.`,
        );
      });
    }

    it(`respects prefers-reduced-motion in the built ${app} stylesheet`, () => {
      const flat = css.replace(/\s+/g, "");
      assert.ok(
        flat.includes("@media(prefers-reduced-motion:reduce)"),
        `the built ${app} stylesheet has no prefers-reduced-motion block`,
      );
      // Every such block, not the first one. The desktop sheet already had one
      // for something else entirely, and stopping at it would have passed this
      // test while the sync bar still slid for somebody who asked it not to.
      const blocks: string[] = [];
      for (
        let at = flat.indexOf("@media(prefers-reduced-motion:reduce)");
        at !== -1;
        at = flat.indexOf("@media(prefers-reduced-motion:reduce)", at + 1)
      ) {
        blocks.push(flat.slice(at, flat.indexOf("}}", at) + 2));
      }
      assert.ok(
        blocks.some((block) => block.includes(".node-sync-fill")),
        `the built ${app} stylesheet does not quiet .node-sync-fill under reduced motion. ` +
          "An animation nobody asked for is not information.",
      );
    });

    /**
     * The rule the whole design turns on. A spinner is a thing that moves while
     * nothing is known, and there must be no way to produce one here: no
     * keyframes in the sync block, and no rotation on any of its parts.
     */
    it(`ships no looping animation on the ${app} sync surface`, () => {
      const flat = css.replace(/\s+/g, "");
      const at = flat.indexOf(".node-sync-fill{");
      assert.notEqual(at, -1, `.node-sync-fill has no rule in the built ${app} stylesheet`);
      const body = flat.slice(at, flat.indexOf("}", at));
      assert.ok(
        !body.includes("animation:"),
        `.node-sync-fill carries an animation in the built ${app} stylesheet. It must move only ` +
          "when the width it transitions to has actually changed, so that motion always means " +
          "a number moved.",
      );
      assert.ok(
        !flat.includes(".node-sync-track--indeterminate"),
        "an indeterminate variant of the track exists. There is no honest indeterminate " +
          "state here: a node catching up and a node on a private chain of its own both climb.",
      );
    });
  }
});

import assert from "node:assert/strict";
import test from "node:test";

import { evaluateAudit, parseLockedPackages } from "./check-rust-advisories.mjs";

const NOW = new Date("2026-08-14T12:00:00Z");
const warning = {
  advisory: { id: "RUSTSEC-2099-0001" },
  package: { name: "example", version: "1.2.3" },
};
const policy = {
  schemaVersion: 1,
  reviewBy: "2026-09-30",
  allowedWarnings: [
    {
      advisory: "RUSTSEC-2099-0001",
      package: "example",
      version: "1.2.3",
      kind: "unmaintained",
      reason: "fixture",
      releaseBlockers: ["linux-desktop-mainnet"],
    },
  ],
};

function report(overrides = {}) {
  return {
    vulnerabilities: { count: 0, list: [] },
    warnings: { unmaintained: [warning] },
    ...overrides,
  };
}

test("accepts only an exact reviewed warning", () => {
  assert.deepEqual(evaluateAudit(report(), policy, { now: NOW }).errors, []);
});

test("rejects vulnerabilities even when warnings match", () => {
  const errors = evaluateAudit(report({
    vulnerabilities: { count: 1, list: [{ advisory: { id: "RUSTSEC-2099-9999" } }] },
    warnings: { unmaintained: [warning] },
  }), policy, { now: NOW }).errors;
  assert.match(errors.join("\n"), /RUSTSEC-2099-9999/);
});

test("rejects unknown and changed warnings", () => {
  const changed = structuredClone(warning);
  changed.package.version = "1.2.4";
  const errors = evaluateAudit(report({ warnings: { unmaintained: [changed] } }), policy, { now: NOW }).errors;
  assert.match(errors.join("\n"), /unreviewed warning/);
  assert.match(errors.join("\n"), /stale policy entry/);
});

test("rejects stale policy entries when a warning is removed", () => {
  const errors = evaluateAudit(report({ warnings: {} }), policy, { now: NOW }).errors;
  assert.match(errors.join("\n"), /stale policy entry/);
});

test("blocks only the explicitly listed release target", () => {
  assert.equal(evaluateAudit(report(), policy, { now: NOW, releaseTarget: "windows-mainnet" }).errors.length, 0);
  assert.match(
    evaluateAudit(report(), policy, { now: NOW, releaseTarget: "linux-desktop-mainnet" }).errors.join("\n"),
    /blocks linux-desktop-mainnet/,
  );
});

test("expires the review instead of allowing warnings forever", () => {
  const errors = evaluateAudit(report(), policy, { now: new Date("2026-10-01T00:00:00Z") }).errors;
  assert.match(errors.join("\n"), /review expired/);
});

test("requires an exact immutable source for a reviewed patched dependency", () => {
  const pinnedPolicy = {
    ...policy,
    requiredPinnedPackages: [{
      package: "glib",
      version: "0.18.5",
      source: "git+https://example.invalid/glib?rev=abc#abc",
      reason: "fixture",
    }],
  };
  const lockText = `[[package]]\nname = "glib"\nversion = "0.18.5"\nsource = "git+https://example.invalid/glib?rev=abc#abc"\n`;
  assert.equal(evaluateAudit(report(), pinnedPolicy, { now: NOW, lockText }).errors.length, 0);

  const errors = evaluateAudit(report(), pinnedPolicy, {
    now: NOW,
    lockText: lockText.replace("#abc", "#changed"),
  }).errors;
  assert.match(errors.join("\n"), /required pinned package glib@0.18.5/);
});

test("parses source-less and sourced Cargo.lock packages", () => {
  assert.deepEqual(parseLockedPackages(`[[package]]\nname = "local"\nversion = "1.0.0"\n\n[[package]]\nname = "remote"\nversion = "2.0.0"\nsource = "registry+example"\n`), [
    { name: "local", version: "1.0.0", source: undefined },
    { name: "remote", version: "2.0.0", source: "registry+example" },
  ]);
});

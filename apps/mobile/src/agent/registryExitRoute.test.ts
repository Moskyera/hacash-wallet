import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import {
  DESKTOP_EXIT_CONTROL_LABEL,
  REGISTRY_EXIT_COST,
  REGISTRY_EXIT_LEASE,
  REGISTRY_EXIT_PHONE_CANNOT,
  REGISTRY_EXIT_REASSURANCE,
  REGISTRY_EXIT_ROUTE,
  REGISTRY_EXIT_TITLE,
} from "./registryExitRoute";

const read = (path: string) =>
  readFileSync(new URL(path, import.meta.url), "utf8");

/** The companion screen with its comments removed. */
const security = read("./CompanionSecurity.tsx")
  .replace(/\/\*[\s\S]*?\*\//g, " ")
  .replace(/^[ \t]*\/\/.*$/gm, " ");

describe("the phone names the desktop exit control exactly", () => {
  it("uses a label the desktop control table really carries", () => {
    // Two false instructions in this codebase caused a permanent,
    // unrecoverable device revocation. Both were a sentence naming a control
    // that did not exist. This is the same shape, across two apps.
    const controls = read("../../../desktop/src/agent/desktopControls.ts");
    expect(controls).toContain(
      `start_exit_without_provider: "${DESKTOP_EXIT_CONTROL_LABEL}"`,
    );
    expect(REGISTRY_EXIT_ROUTE).toContain(DESKTOP_EXIT_CONTROL_LABEL);
  });

  it("names the page that control is actually rendered on", () => {
    const admin = read("../../../desktop/src/agent/AgentAdminPages.tsx");
    const security = admin.slice(admin.indexOf("function SecurityPage("));
    expect(security).toContain("DESKTOP_CONTROLS.start_exit_without_provider");
    expect(REGISTRY_EXIT_ROUTE).toContain("Security");
  });
});

describe("the phone tells the truth about what it can and cannot do", () => {
  it("never implies this handset can start an exit", () => {
    expect(REGISTRY_EXIT_PHONE_CANNOT).toContain("cannot start it");
    for (const copy of [
      REGISTRY_EXIT_REASSURANCE,
      REGISTRY_EXIT_COST,
      REGISTRY_EXIT_LEASE,
      REGISTRY_EXIT_PHONE_CANNOT,
      REGISTRY_EXIT_ROUTE,
    ]) {
      expect(copy).not.toMatch(/tap|press this|approve the exit here/i);
    }
  });

  it("says the provider does not hold the money, before anything else", () => {
    expect(REGISTRY_EXIT_REASSURANCE).toContain("not held by your provider");
    expect(REGISTRY_EXIT_REASSURANCE).toContain("the chain, not the provider");
  });

  it("states the wait and the fee rather than only the reassurance", () => {
    expect(REGISTRY_EXIT_COST).toContain("objection window");
    expect(REGISTRY_EXIT_COST).toContain("three ordinary network fees");
    expect(REGISTRY_EXIT_COST).toContain(
      "spent whether or not your provider ever comes back",
    );
  });

  it("carries the one clock that destroys the money, without overstating it", () => {
    // The clock is real and it is the only one here that ends in money gone.
    expect(REGISTRY_EXIT_LEASE).toContain("gone for good");
    expect(REGISTRY_EXIT_LEASE).toContain("Anyone at all can pay to extend it");
    // But it does not fire when the first half runs out. The contract buys
    // every channel key a recovery buffer at funding, so an expired record goes
    // dormant and anyone can restore it. Saying "gone" at the first deadline
    // was wrong by about six times, on the one screen a person reads when they
    // already believe their money is lost.
    expect(REGISTRY_EXIT_LEASE).toContain("does not vanish straight away");
    expect(REGISTRY_EXIT_LEASE).toContain("Only if both of those run out");
  });
});

describe("it is rendered on the phone, not merely written", () => {
  it("appears on the companion Security screen", () => {
    expect(security).toContain("{REGISTRY_EXIT_TITLE}");
    for (const token of [
      "REGISTRY_EXIT_REASSURANCE",
      "REGISTRY_EXIT_COST",
      "REGISTRY_EXIT_LEASE",
      "REGISTRY_EXIT_PHONE_CANNOT",
      "REGISTRY_EXIT_ROUTE",
    ]) {
      expect(security, `${token} is written but never rendered`).toContain(
        `{${token}}`,
      );
    }
    expect(REGISTRY_EXIT_TITLE.length).toBeGreaterThan(10);
  });

  it("is not folded away behind a disclosure", () => {
    // The lease is the one thing here that has a deadline, and a summary an
    // owner never opens is the same as not saying it.
    const index = security.indexOf("{REGISTRY_EXIT_LEASE}");
    expect(index).toBeGreaterThan(0);
    const before = security.slice(0, index);
    expect(
      before.split("<details").length - before.split("</details>").length,
    ).toBe(0);
  });

  it("is shown in every build, including the read-only companion", () => {
    // A read-only build is exactly the build an owner is most likely to be
    // holding, and it is the build with nothing else on this subject at all.
    const block = security.slice(
      security.indexOf("{REGISTRY_EXIT_TITLE}") - 600,
      security.indexOf("{REGISTRY_EXIT_TITLE}"),
    );
    expect(block).not.toContain("pilotEnabled");
    expect(block).not.toContain("stored?.configured");
  });
});

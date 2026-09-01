import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import {
  DESKTOP_EXIT_CONTROL_LABEL,
  DESKTOP_FUND_CONTROL_LABEL,
  DESKTOP_OPEN_SECTION,
  REGISTRY_EXIT_COST,
  REGISTRY_EXIT_LEASE,
  REGISTRY_EXIT_NO_WATCHER,
  REGISTRY_EXIT_PHONE_CANNOT,
  REGISTRY_EXIT_REASSURANCE,
  REGISTRY_EXIT_ROUTE,
  REGISTRY_EXIT_TITLE,
  REGISTRY_OPEN_PHONE_CANNOT,
  REGISTRY_OPEN_ROUTE,
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

describe("the phone says it can never open a channel either", () => {
  it("names the desktop control that sends a deposit, exactly", () => {
    // Same shape as the exit label above: a sentence naming a control that
    // does not exist is what caused a permanent, unrecoverable revocation
    // twice in this codebase, and the desktop's own table is the authority.
    const controls = read("../../../desktop/src/agent/desktopControls.ts");
    expect(controls).toContain(
      `fund_provider_channel: "${DESKTOP_FUND_CONTROL_LABEL}"`,
    );
    expect(REGISTRY_OPEN_ROUTE).toContain(DESKTOP_FUND_CONTROL_LABEL);
  });

  it("names a section the desktop really renders", () => {
    const admin = read("../../../desktop/src/agent/AgentAdminPages.tsx");
    expect(admin).toContain(DESKTOP_OPEN_SECTION);
    expect(REGISTRY_OPEN_ROUTE).toContain(DESKTOP_OPEN_SECTION);
  });

  it("says never, and says why, rather than promising a later build", () => {
    expect(REGISTRY_OPEN_PHONE_CANNOT).toContain("never will");
    expect(REGISTRY_OPEN_PHONE_CANNOT).toContain(
      "approval identity, not a Hacash key",
    );
    // Both signatures a channel needs, not just the obvious one.
    expect(REGISTRY_OPEN_PHONE_CANNOT).toContain("locks up a deposit");
    expect(REGISTRY_OPEN_PHONE_CANNOT).toContain("refund receipt");
    expect(REGISTRY_OPEN_PHONE_CANNOT).not.toMatch(/yet|soon|future release/i);
  });

  it("says a provider that will not sign costs nothing", () => {
    expect(REGISTRY_OPEN_ROUTE).toContain("no channel opens and nothing is spent");
  });

  it("is rendered on the companion Security screen, not merely written", () => {
    for (const token of ["REGISTRY_OPEN_PHONE_CANNOT", "REGISTRY_OPEN_ROUTE"]) {
      expect(security, `${token} is written but never rendered`).toContain(
        `{${token}}`,
      );
    }
  });
});

describe("the phone tells the truth about what it can and cannot do", () => {
  it("never implies this handset can start an exit", () => {
    expect(REGISTRY_EXIT_PHONE_CANNOT).toContain("cannot start it");
    for (const copy of [
      REGISTRY_EXIT_REASSURANCE,
      REGISTRY_EXIT_COST,
      REGISTRY_EXIT_LEASE,
      REGISTRY_EXIT_NO_WATCHER,
      REGISTRY_EXIT_PHONE_CANNOT,
      REGISTRY_EXIT_ROUTE,
      REGISTRY_OPEN_PHONE_CANNOT,
      REGISTRY_OPEN_ROUTE,
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

  /**
   * A settlement can start without the owner, and the phone says so.
   *
   * The direction matters as much as the fact. An earlier draft said a stale
   * receipt takes the difference from a sleeping owner; on the shipped
   * one-directional rail it pays them MORE, and the wallet declines to answer
   * it for exactly that reason. These assertions pin the exposure that is real
   * and forbid the reversal returning.
   */
  it("says a settlement can start without the owner, in the direction the rail runs", () => {
    expect(REGISTRY_EXIT_NO_WATCHER).toContain(
      "start a settlement without you",
    );
    expect(REGISTRY_EXIT_NO_WATCHER).toContain("while you are asleep");
    // The direction, which is why this constant was rewritten.
    expect(REGISTRY_EXIT_NO_WATCHER).toContain(
      "cannot pay you less than your newest receipt",
    );
    expect(REGISTRY_EXIT_NO_WATCHER).toContain("owes you more");
    expect(REGISTRY_EXIT_NO_WATCHER).toContain("would hand money back");
    // Undefended, said outright. Not "no watchtower configured", which reads
    // as a setting somebody could change from this screen.
    expect(REGISTRY_EXIT_NO_WATCHER).toContain("nothing watches for it");
    // The exposure that is real: the ending does not happen by itself.
    expect(REGISTRY_EXIT_NO_WATCHER).toContain("waits in the contract");
    expect(REGISTRY_EXIT_NO_WATCHER).toContain("only the desktop can press");
    // And the reason an owner cannot fix it by finding somebody they trust:
    // there is no way to get the receipt out of either app.
    expect(REGISTRY_EXIT_NO_WATCHER).toContain(
      "hand your receipt to anyone else",
    );
    // The reversal must not come back. "gone for good" belongs to the lease.
    expect(REGISTRY_EXIT_NO_WATCHER).not.toMatch(
      /gone for good|the difference is gone/i,
    );
    // No promise of a build that is not scheduled.
    expect(REGISTRY_EXIT_NO_WATCHER).not.toMatch(/yet|soon|future release/i);
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
    // Same for the unwatched window: it is the other way the money goes
    // rather than waits, so it is held to the same standard.
    for (const token of ["{REGISTRY_EXIT_LEASE}", "{REGISTRY_EXIT_NO_WATCHER}"]) {
      const index = security.indexOf(token);
      expect(index, `${token} is never rendered`).toBeGreaterThan(0);
      const before = security.slice(0, index);
      expect(
        before.split("<details").length - before.split("</details>").length,
      ).toBe(0);
    }
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

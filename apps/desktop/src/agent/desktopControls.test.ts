import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import {
  DESKTOP_CONTROLS,
  DESKTOP_CONTROL_IDS,
  DESKTOP_CONTROL_LABEL_TOKENS,
  RETIRED_DESKTOP_INSTRUCTIONS,
  desktopControlLabels,
} from "./desktopControls";
import {
  DESKTOP_IRREVERSIBLE_ACTIONS,
  irreversibleControlLabel,
  irreversibleWarningFor,
} from "./irreversibleActions";

const readRaw = (name: string) =>
  readFileSync(new URL(`./${name}`, import.meta.url), "utf8");

/**
 * The source with its comments removed.
 *
 * A comment explaining that a false instruction was removed must not itself
 * count as that instruction coming back, and a label that appears only in a
 * comment must not count as rendered.
 */
const read = (name: string) =>
  readRaw(name)
    .replace(/\/\*[\s\S]*?\*\//g, " ")
    .replace(/^[ \t]*\/\/.*$/gm, " ");

/** JSX wraps prose across lines, so compare on collapsed whitespace. */
const flatten = (source: string) => source.replace(/\s+/g, " ");

const VIEWS = [
  "AgentWalletApp.tsx",
  "MobileCompanionPanel.tsx",
  "AgentAdminPages.tsx",
] as const;

const COPY = [
  "access.ts",
  "companionPairingFeedback.ts",
  "companionWaitingView.ts",
  "desktopControls.ts",
  "irreversibleActions.ts",
  "overviewLayout.ts",
  "strandedWitness.ts",
] as const;

const viewSource = VIEWS.map(read).join("\n");
const allSource = [...VIEWS, ...COPY].map(read).join("\n");
/**
 * Everything an owner can be shown, minus the table that lists the retired
 * strings so they can be tested for.
 */
const instructionSource = [...VIEWS, ...COPY]
  .filter((name) => name !== "desktopControls.ts")
  .map(read)
  .join("\n");

describe("every named control is actually rendered", () => {
  it.each(DESKTOP_CONTROL_IDS)("renders %s", (id) => {
    const label = DESKTOP_CONTROLS[id];
    const token = DESKTOP_CONTROL_LABEL_TOKENS[id];
    const rendered =
      viewSource.includes(label) ||
      viewSource.includes(`DESKTOP_CONTROLS.${id}`) ||
      (token !== undefined && viewSource.includes(token));
    expect(rendered, `${label} is named but never rendered`).toBe(true);
  });

  it("keeps every label distinct, so no instruction is ambiguous", () => {
    const labels = desktopControlLabels();
    expect(new Set(labels).size).toBe(labels.length);
  });
});

describe("retired instructions never come back", () => {
  // Two false instructions in this codebase caused a permanent, unrecoverable
  // device revocation. Each of these named a control that did not exist, or an
  // action the control never performed.
  it.each(RETIRED_DESKTOP_INSTRUCTIONS)("never says %s again", (instruction) => {
    // Flattened: JSX wraps a sentence across lines, and a wrapped lie is still
    // a lie.
    expect(flatten(instructionSource)).not.toContain(flatten(instruction));
  });

  it("keeps the connector label honest about calling stop", () => {
    // The button reads "Clear the failed connector" and its handler is onStop.
    expect(viewSource).toContain("DESKTOP_CONTROLS.clear_failed_connector");
    expect(viewSource).not.toContain("Restart the AI agent connector");
  });

  it("offers a real route wherever another Agent Wallet owns something", () => {
    // The old copy said "Open that wallet to manage it" and the unlocked UI has
    // no wallet picker at all. Locking returns to the unlock screen, which has.
    const switches = viewSource.split("DESKTOP_CONTROLS.lock_and_switch_wallet");
    expect(switches.length - 1).toBeGreaterThanOrEqual(2);
  });
});

describe("irreversible actions warn before they are taken", () => {
  it.each(DESKTOP_IRREVERSIBLE_ACTIONS)(
    "warns before $id",
    (entry) => {
      expect(desktopControlLabels()).toContain(irreversibleControlLabel(entry));
      expect(entry.warning.length).toBeGreaterThan(40);
      expect(entry.warning.toLowerCase()).toMatch(
        /permanent|cannot|final|recalled/,
      );
      // The warning must be in the shipped sources, not only in this table.
      expect(allSource).toContain(entry.warning);
    },
  );

  it("renders every irreversible warning in at least one view", () => {
    for (const entry of DESKTOP_IRREVERSIBLE_ACTIONS) {
      const rendered = VIEWS.some((view) =>
        read(view).includes(`{${entry.renderedAs}}`),
      );
      expect(rendered, `${entry.id} warning is never rendered`).toBe(true);
    }
  });

  it("keeps every irreversible warning out of a collapsed disclosure", () => {
    // A <details> around a before-the-fact warning is the same failure as no
    // warning at all, so no warning may sit inside a disclosure block.
    for (const entry of DESKTOP_IRREVERSIBLE_ACTIONS) {
      for (const view of VIEWS) {
        const source = read(view);
        for (const needle of [entry.warning, `{${entry.renderedAs}}`]) {
          let index = source.indexOf(needle);
          while (index !== -1) {
            const before = source.slice(0, index);
            const opened = before.split("<details").length - 1;
            const closed = before.split("</details>").length - 1;
            expect(
              opened,
              `${entry.id} warning is inside a <details> in ${view}`,
            ).toBe(closed);
            index = source.indexOf(needle, index + 1);
          }
        }
      }
    }
  });

  it("requires a second press wherever the table says so", () => {
    for (const entry of DESKTOP_IRREVERSIBLE_ACTIONS) {
      if (!entry.confirmLabel) continue;
      expect(viewSource).toContain(entry.confirmLabel);
    }
  });

  it("finds the warning that belongs to a control", () => {
    expect(irreversibleWarningFor("revoke_agent")).toContain("permanent");
    expect(irreversibleWarningFor("disable_all_agent_payments")).toContain(
      "cannot reverse a transaction that has already been submitted",
    );
    // Reversible controls carry no irreversibility claim.
    expect(irreversibleWarningFor("refresh")).toBe("");
    expect(irreversibleWarningFor("turn_on_phone_connection")).toBe("");
  });
});

describe("the phone panel keeps both phone controls reachable", () => {
  const panel = read("MobileCompanionPanel.tsx");

  it("offers pairing whether the connection is on or off", () => {
    // The whole pairing UI used to live in the `else` of `status?.enabled`, so
    // pairing a second phone, or re-pairing after a revoke, was impossible.
    const branch = panel.split("{linkOn || listenerFailed ? (")[1] ?? "";
    expect(branch).toContain("COMPANION_STOP_LINK_ACTION");
    // The pairing control sits outside that branch entirely.
    const afterBranch = panel.split("{!offer && (")[1] ?? "";
    expect(afterBranch).toContain("COMPANION_PAIR_ACTION");
    expect(panel).not.toContain("status?.enabled ? (");
  });

  it("hides, rather than disables, a control that cannot work in a state", () => {
    // No authorized phone means the desktop refuses to start the listener, so
    // the control is not shown and a sentence says why.
    expect(panel).toContain("!linkOn && !listenerFailed && !offer && hasAuthorizedDevice");
    expect(panel).toContain("!linkOn && !listenerFailed && !offer && statusLoaded && !hasAuthorizedDevice");
    expect(panel).toContain("is not shown because no phone is");
  });

  it("offers only the control that can succeed while the listener is dead", () => {
    // The slot is still held, so CompanionSupervisor::start refuses with
    // "stop the active mobile companion before starting another". Turning it
    // on cannot succeed; releasing it can, and the sentence names both presses
    // in the order that works.
    expect(panel).toContain("{listenerFailed && !offer && (");
    expect(panel).toContain("{PHONE_LISTENER_FAILED_ROUTE}");
    // The turn-on branch is withheld in that state rather than left to fail.
    expect(panel).not.toContain("{!linkOn && !offer && hasAuthorizedDevice && (");
  });
});


/* -------------------------------------------------------------------------- */
/* Reachability of the reads a state cannot leave without                      */
/* -------------------------------------------------------------------------- */

const APP = read("AgentWalletApp.tsx");
const PANEL_SOURCE = read("MobileCompanionPanel.tsx");
const ADMIN = read("AgentAdminPages.tsx");
const ROTATION = read("WitnessRotationPanel.tsx");

/** How deep inside <details> a given index sits. 0 means always visible. */
function disclosureDepth(source: string, index: number): number {
  const before = source.slice(0, index);
  return (
    before.split("<details").length - before.split("</details>").length
  );
}

describe("Refresh re-reads everything the Overview reports", () => {
  it("is the only thing the page head and the strip call", () => {
    // Refresh read only agent_wallet_overview, so the connector phase and the
    // phone status were never re-read. A connector stuck on "starting" sat
    // beside "wait for it to finish, then try again" with nothing that asked
    // again, and both panels kept reporting listeners an emergency stop had
    // already torn down.
    expect(APP).toContain("onRefresh={refreshAll}");
    expect(APP).not.toContain("onRefresh={refreshOverview}");
  });

  it("re-reads the runtime and the phone panel, not only the overview", () => {
    const body = APP.slice(
      APP.indexOf("const refreshAll = useCallback("),
      APP.indexOf("useEffect(() => {", APP.indexOf("const refreshAll")),
    );
    expect(body).toContain("refreshOverview()");
    expect(body).toContain("refreshRuntime()");
    expect(body).toContain("setCompanionRefreshToken");
    // And the panel really does re-read when that token changes.
    expect(PANEL_SOURCE).toContain("}, [refresh, refreshToken]);");
  });

  it("puts the same three reads on the fifteen-second poll", () => {
    const poll = APP.slice(
      APP.indexOf("const timer = window.setInterval("),
      APP.indexOf("}, 15_000);"),
    );
    expect(poll).toContain("refreshAll()");
  });

  it("names Refresh as the way out of a connector mid-transition", () => {
    // Both controls are unavailable while the phase is starting or stopping,
    // so the only way to leave the state is to observe it again.
    const wait = APP.slice(
      APP.indexOf("is unavailable while it is"),
      APP.indexOf("is unavailable while it is") + 400,
    );
    expect(wait).toContain("DESKTOP_CONTROLS.refresh");
    expect(wait).not.toContain("try again");
  });
});

describe("an emergency stop reports what it actually stopped", () => {
  it("re-reads the listeners it tore down", () => {
    const handler = APP.slice(
      APP.indexOf("onEmergencyStop={() =>"),
      APP.indexOf("onEnable={() =>"),
    );
    expect(handler).toContain("await refreshAll();");
    expect(handler).not.toContain("await refreshOverview();");
    expect(handler).toContain("setPairingActivation(null)");
  });

  it("warns that both listeners stop, before the press and never folded away", () => {
    const index = APP.indexOf("{EMERGENCY_STOP_STOPS_LISTENERS}");
    expect(index).toBeGreaterThan(0);
    expect(disclosureDepth(APP, index)).toBe(0);
    // Beside the control that engages the stop, not the one that clears it.
    const branch = APP.slice(
      APP.indexOf('{stopControl.action === "disable" && ('),
      index + 40,
    );
    expect(branch.length).toBeLessThan(400);
  });
});

describe("every control that cancels pending payment requests says so first", () => {
  it("warns beside Enable locally on Overview", () => {
    const index = APP.indexOf("{CLEAR_STOP_CANCELS_PENDING_REQUESTS}");
    expect(index).toBeGreaterThan(0);
    expect(disclosureDepth(APP, index)).toBe(0);
    // Rendered only in the branch that offers the clearing control.
    const branch = APP.slice(
      APP.indexOf('{stopControl.action === "enable" && ('),
      index + 40,
    );
    expect(branch.length).toBeLessThan(400);
  });

  it("widens the policy-save sentence to the scope Rust actually uses", () => {
    // update_agent_policy cancels with scope None: every agent on the wallet,
    // and payment requests rather than only sessions.
    const review = flatten(
      ADMIN.slice(
        ADMIN.indexOf("Apply policy epoch"),
        ADMIN.indexOf("Save policy and disconnect sessions"),
      ),
    );
    expect(review).toContain("on every agent on this wallet");
    expect(review).toContain("waiting for your decision");
    expect(disclosureDepth(ADMIN, ADMIN.indexOf("on every agent on this wallet"))).toBe(0);
  });

  it("warns before Approve read-only admits a new local agent", () => {
    // record_pairing_approval cancels every OTHER agent's pending requests
    // before it records the new one.
    const block = flatten(
      APP.slice(
        APP.indexOf("Initial approval is read-only"),
        APP.indexOf("Approve read-only"),
      ),
    );
    expect(block).toContain("on every other agent on this wallet");
    expect(disclosureDepth(APP, APP.indexOf("on every other agent on this wallet"))).toBe(0);
  });
});

describe("mainnet readiness is fail-closed and owner-readable", () => {
  it("renders the core blockers and keeps the Agent Wallet fee at zero", () => {
    expect(APP).toContain("overview.mainnet_readiness.blockers.map");
    expect(APP).toContain("The authenticated hacash-agent-pay/1 transport is read-only");
    expect(APP).toContain("An independent security audit is still required");
    expect(APP).toContain("Agent Wallet fee: 0 HAC");
  });
});

describe("the backup boundary is explained before a passphrase is chosen", () => {
  it("puts the warning above the field, outside any disclosure", () => {
    const warning = APP.indexOf("HPAY cannot recover this passphrase");
    const field = APP.indexOf("Agent Wallet passphrase");
    expect(warning).toBeGreaterThan(0);
    expect(warning).toBeLessThan(field);
    expect(disclosureDepth(APP, warning)).toBe(0);
  });
});

describe("a read-only policy names the route out and its cost", () => {
  it("names revoking, and states that revoking is permanent", () => {
    // Every field is disabled and validateDraft refuses any mode but
    // desktop_manual, so Review policy change can never enable. The only route
    // is revoke and pair again, and the screen never named it.
    const branch = flatten(
      ADMIN.slice(
        ADMIN.indexOf("unsupportedApprovalMode ? ("),
        ADMIN.indexOf("Desktop approval is the only production-ready choice"),
      ),
    );
    expect(branch).toContain("Nothing on this screen can change that mode");
    expect(branch).toContain("{REVOKE_AGENT_WARNING}");
    expect(disclosureDepth(ADMIN, ADMIN.indexOf("Nothing on this screen can change that mode"))).toBe(0);
  });
});

describe("a rotation past the point of no cancel admits it", () => {
  it("asks the core which controls are live instead of guessing from the phase", () => {
    // The backend refuses a cancel past CandidatePairedRestricted, and also
    // refuses it on a re-targeted rotation, which sits back in
    // awaiting_candidate_pairing with the old phone already revoked. A phase
    // list cannot express that, so the panel asks.
    const cancelList = flatten(
      ROTATION.slice(
        ROTATION.indexOf("{rotationActive && controls.cancellable ? ("),
        ROTATION.indexOf("Cancel before authority transition"),
      ),
    );
    expect(cancelList).toContain("controls.cancellable");
    expect(ROTATION).toContain("agentWalletApi.witnessRotationControls");
    expect(ROTATION).not.toContain('"awaiting_completion_anchor",');
  });

  it("does not fall silent when it cannot ask", () => {
    // Every control on this panel is gated on that one call. A failed answer
    // must stay fail-closed, but an empty panel is indistinguishable from "this
    // state has no way out" - which is the exact failure this panel exists to
    // end. It says so, and offers a retry.
    expect(ROTATION).toContain("setControlsUnknown(true)");
    const notice = flatten(
      ROTATION.slice(
        ROTATION.indexOf("{rotationActive && controlsUnknown ? ("),
        ROTATION.indexOf("Check again"),
      ),
    );
    expect(notice).toContain("could not check which rotation controls");
    expect(notice).toContain("Nothing has changed and nothing is lost");
    expect(notice).toContain('role="alert"');
    expect(ROTATION).toContain("setControlsReloadKey((value) => value + 1)");
    expect(ROTATION).toContain("controlsReloadKey]");
  });

  it("says so, and says what can still finish it", () => {
    const block = flatten(
      ROTATION.slice(
        ROTATION.indexOf('{phase === "awaiting_completion_anchor" ? ('),
      ),
    );
    expect(block).toContain("can no longer be cancelled from this desktop");
    expect(block).toContain("COMPANION_PHONE_ROTATION_ACTION");
    // And it must not recommend the one permanent action that removes the
    // device that can still finish it.
    expect(block).toContain("Do not revoke anything");
  });

  it("offers the only escape when that phone is gone, and states its cost first", () => {
    // Dead end 1. Until this control existed, awaiting_completion_anchor had no
    // exit at all: the cancel is refused twice over, the start form is hidden
    // while a rotation is active, and every agent payment stays refused. The
    // wallet was stopped for good on a handset that will never come back.
    expect(ROTATION).toContain("{controls.retargetable ? (");
    expect(ROTATION).toContain("? ROTATION_RETARGET_WARNING");
    expect(ROTATION).toContain(": ROTATION_RETARGET_PAIRING_WARNING}");
    expect(ROTATION).toContain("{ROTATION_RETARGET_ACTION}");
    // A typed confirmation, in words that are not the ones any other control
    // uses.
    expect(ROTATION).toContain(
      'export const ROTATION_RETARGET_CONFIRMATION = "USE A DIFFERENT PHONE"',
    );
    expect(ROTATION).toContain(
      "retargetText !== ROTATION_RETARGET_CONFIRMATION",
    );
    // The cost is stated before the press, in the open, and it names exactly
    // what is discarded and exactly what is not.
    const warning = ROTATION.indexOf("? ROTATION_RETARGET_WARNING");
    const button = ROTATION.indexOf("{ROTATION_RETARGET_ACTION}");
    expect(warning).toBeGreaterThan(0);
    expect(warning).toBeLessThan(button);
    expect(disclosureDepth(ROTATION, warning)).toBe(0);
    const text = flatten(ROTATION.slice(ROTATION.indexOf("ROTATION_RETARGET_WARNING =")));
    expect(text).toContain("cannot be undone");
    expect(text).toContain("can never serve this wallet again");
    expect(text).toContain("No money moves");
  });

  it("does not claim a cost that was not paid at the pairing phases", () => {
    // retarget_preconditions also offers the escape at rotation_ticket_issued
    // and candidate_paired_restricted once the old phone is revoked, because
    // the cancel is refused there for good and the ticket cannot be re-issued.
    // No baseline was accepted and no witness epoch was consumed at those
    // phases, so the expensive warning would be false - and a false warning
    // talks an owner out of the only control they have.
    const cheap = flatten(
      ROTATION.slice(ROTATION.indexOf("ROTATION_RETARGET_PAIRING_WARNING =")),
    );
    expect(cheap).toContain("cannot be undone");
    expect(cheap).toContain("no witness epoch was used up");
    expect(cheap).toContain("No money moves");
    expect(cheap).not.toContain("can never serve this wallet again");
    // The expensive one is shown only where it is true.
    expect(ROTATION).toMatch(
      /phase === "awaiting_completion_anchor"\s+\? ROTATION_RETARGET_WARNING/,
    );
  });

  it("quotes the phone's real labels rather than inventing one", () => {
    expect(ROTATION).not.toContain("Continue witness rotation");
    expect(ROTATION).toContain(
      'const COMPANION_PHONE_ROTATION_ACTION = "Check and continue rotation"',
    );
  });
});

describe("Copy address never fails in silence", () => {
  it("reports both the missing clipboard and the rejected write", () => {
    const handler = APP.slice(
      APP.indexOf("const clipboard = navigator.clipboard;"),
      APP.indexOf("{DESKTOP_CONTROLS.copy_address}"),
    );
    expect(handler).toContain("if (!clipboard) {");
    expect(handler).toContain("onError(");
    expect(handler).not.toContain(".catch(() => undefined)");
    // The optional chain short-circuited the whole expression, so the press
    // produced nothing at all when navigator.clipboard was absent.
    expect(APP).not.toContain("navigator.clipboard\n        ?.writeText");
  });

  it("keeps a second route to the address that needs no clipboard", () => {
    expect(APP).toContain('<p className="agent-exact-address">{overview.address}</p>');
  });
});

describe("an unread phone status is never reported as an empty one", () => {
  it("does not claim the read succeeded", () => {
    const effect = PANEL_SOURCE.slice(
      PANEL_SOURCE.indexOf("void refresh().catch((reason) => {"),
      PANEL_SOURCE.indexOf("}, [refresh, refreshToken]);"),
    );
    expect(effect).toContain("setLocalError(");
    // statusLoaded stays false, so phoneLinkState answers "unknown" rather
    // than "off" and Overview stops offering Pair a phone as the primary.
    expect(effect).not.toContain("setStatusLoaded(true)");
  });

  it("gates the empty-device claim on the read having happened", () => {
    expect(PANEL_SOURCE).toContain("statusLoaded ? (");
    const claim = PANEL_SOURCE.indexOf("No phone is authorized yet.");
    const gate = PANEL_SOURCE.indexOf("statusLoaded ? (");
    expect(gate).toBeLessThan(claim);
  });
});

describe("the setup retry is rendered from the fact every sentence names", () => {
  it("renders on the stripped address, not on the raw endpoint", () => {
    // phoneAddressReady, the strip handler and both sentences are all derived
    // from bindAddress; only the button was derived from endpoint, so an
    // endpoint holding just "hpay-lan://" produced two instructions pointing
    // at a button that was not rendered.
    expect(PANEL_SOURCE).toContain("const canRetryAutomaticSetup = !busy && !bindAddress && !offer;");
    expect(PANEL_SOURCE).toContain("{!bindAddress && !offer ? (");
    expect(PANEL_SOURCE).not.toContain("{!endpoint && !offer ? (");
  });

  it("stays reachable once an address has been found", () => {
    // The button used to disappear for good after the first success, so an
    // owner whose private Wi-Fi address changed could never re-detect it.
    const advanced = PANEL_SOURCE.slice(
      PANEL_SOURCE.indexOf("<summary>Advanced connection settings</summary>"),
    );
    expect(advanced).toContain("{DESKTOP_CONTROLS.retry_automatic_setup}");
    expect(advanced).toContain("onClick={retryAutomaticSetup}");
  });
});

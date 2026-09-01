/// THE SCREEN MUST NEVER SHOW A PASS WHILE A FATAL ITEM FAILED OR WAS SKIPPED.
///
/// The core computes the same verdict, and this side deliberately recomputes it
/// from the items rather than reading `report.verdict`. The header is the thing
/// a person acts on, and it must not be able to go green because one field said
/// so. So the rule is tested here as it renders, not only as it is computed.
///
/// The second half of this file is the copy. A green preflight means the
/// infrastructure answered correctly, read-only, at one instant. Every one of
/// the four things it must not be read as claiming is asserted to be on the
/// screen, because a caveat in a comment protects nobody.

import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";
import {
  NativeRailPreflightCard,
  PreflightResult,
  preflightShowsPass,
  type NativeRailPreflightView,
  type PreflightCheckSeverity,
  type PreflightCheckStatus,
  type PreflightCheckView,
} from "@hacash/wallet-ui";

function check(
  id: string,
  severity: PreflightCheckSeverity,
  status: PreflightCheckStatus,
): PreflightCheckView {
  return { id, title: `check ${id}`, severity, status, observed: `observed ${id}`, reason: null };
}

/**
 * A report whose `verdict` field says "pass" no matter what the items say.
 *
 * Deliberately dishonest, because that is exactly the case the screen has to
 * survive: a stale or wrong verdict field must not be able to paint the header
 * green over a failed fatal item.
 */
function report(checks: PreflightCheckView[]): NativeRailPreflightView {
  return {
    schema: "hpay-native-rail-mainnet-preflight/1",
    generated_unix: 1_800_000_000,
    node_url: "https://node.example",
    hub_url: "https://hub.example",
    owner_address: "1AVRuFXNFi3rdMrPH4hdqSgFrEBnWisWaS",
    hub_address: "1LFPqztfKhamVuzzV5WV6pHfykktGD5pMW",
    channel_deposit_hac: "1",
    payment_hac: "0.1",
    verdict: "pass",
    fatal_failed: 0,
    fatal_skipped: 0,
    warnings: 0,
    validity_seconds: 330,
    checks,
    declared_caps: {
      max_payment_hac: "1",
      max_channel_funding_hac: "10",
      max_aggregate_tvl_hac: "100",
      aggregate_tvl_within_limit: true,
    },
    cannot_be_checked: [
      {
        id: "allowlist_membership",
        title: "Whether this address is on the Hub's list",
        detail: "The Hub publishes only that a list exists, never who is on it.",
      },
      {
        id: "hub_will_countersign",
        title: "Whether the Hub will actually countersign your voucher",
        detail: "Nothing in Hacash can compel a second signature.",
      },
      {
        id: "pass_expires",
        title: "A pass expires in about five and a half minutes",
        detail: "It is re-read and re-judged at the signing boundary.",
      },
    ],
  };
}

const ALL_STATUSES: PreflightCheckStatus[] = ["pass", "fail", "skip"];

describe("the never-show-PASS rule", () => {
  it("shows READY only when every fatal item passed", () => {
    const green = report([
      check("a", "fatal", "pass"),
      check("b", "fatal", "pass"),
      check("c", "warning", "fail"),
    ]);
    expect(preflightShowsPass(green.checks)).toBe(true);
    expect(renderToStaticMarkup(<PreflightResult report={green} />)).toContain("READY");
  });

  it("never shows READY while a fatal item failed, even when the verdict field says pass", () => {
    const red = report([check("a", "fatal", "pass"), check("b", "fatal", "fail")]);
    expect(red.verdict).toBe("pass");
    expect(preflightShowsPass(red.checks)).toBe(false);
    const html = renderToStaticMarkup(<PreflightResult report={red} />);
    expect(html).toContain("NOT READY");
    expect(html).toContain("Do not put money in yet");
    expect(html).not.toContain(">READY<");
  });

  /// A skipped check is not a passed check.
  it("never shows READY while a fatal item was skipped", () => {
    const skipped = report([check("a", "fatal", "pass"), check("b", "fatal", "skip")]);
    expect(preflightShowsPass(skipped.checks)).toBe(false);
    const html = renderToStaticMarkup(<PreflightResult report={skipped} />);
    expect(html).toContain("NOT READY");
    // And it says so in words, rather than leaving a person to wonder why an
    // all-green-looking list did not come back green.
    expect(html).toContain("could not be run is shown as failed");
    expect(html).toContain("FATAL, NOT CHECKED");
  });

  it("holds for every combination of one fatal and one warning item", () => {
    for (const fatal of ALL_STATUSES) {
      for (const warning of ALL_STATUSES) {
        const checks = [check("fatal", "fatal", fatal), check("warn", "warning", warning)];
        expect(preflightShowsPass(checks)).toBe(fatal === "pass");
      }
    }
  });

  it("a failed warning alone never denies the pass", () => {
    expect(
      preflightShowsPass([check("a", "fatal", "pass"), check("b", "warning", "fail")]),
    ).toBe(true);
  });

  it("a report with no fatal items is not a pass", () => {
    expect(preflightShowsPass([])).toBe(false);
    expect(preflightShowsPass([check("w", "warning", "pass")])).toBe(false);
  });

  it("holds at every position in a long green run", () => {
    for (let bad = 0; bad < 10; bad += 1) {
      for (const status of ["fail", "skip"] as PreflightCheckStatus[]) {
        const checks = Array.from({ length: 10 }, (_, index) =>
          check(`i${index}`, "fatal", index === bad ? status : "pass"),
        );
        expect(preflightShowsPass(checks)).toBe(false);
      }
    }
  });
});

describe("the copy does not overclaim", () => {
  const html = renderToStaticMarkup(
    <PreflightResult report={report([check("a", "fatal", "pass")])} />,
  );

  it("says green means read-only, right now, and nothing more", () => {
    expect(html).toContain("read-only requests");
    expect(html).toContain("does not mean your money is safe");
    expect(html).toContain("does not make");
    expect(html).toContain("trustless");
  });

  it("says the Hub can still refuse the voucher afterwards", () => {
    expect(html).toContain("refuse to countersign your voucher");
  });

  it("says a green answer expires in about five minutes", () => {
    expect(html).toContain("goes stale in about 5 minutes");
    expect(html).toContain("330 seconds");
  });

  it("puts what cannot be checked on the screen, not in a comment", () => {
    expect(html).toContain("What this check cannot tell you");
    // The apostrophe arrives HTML-escaped, which is the renderer doing its job.
    expect(html).toContain("Whether this address is on the Hub&#x27;s list");
    expect(html).toContain("compel a second signature");
  });
});

/**
 * A green header means the node told the truth about the chain. It does not
 * mean the node can hand your signed transaction to a miner. That difference
 * is the whole reason this block exists, and a warning that only shows up in
 * the list under a READY banner is a warning nobody reads.
 */
describe("a node nobody can reach", () => {
  function reachCheck(
    status: PreflightCheckStatus,
    observed: string,
    reason: string,
  ): PreflightCheckView {
    return {
      id: "node_can_be_reached",
      title: "Other nodes can reach your node, so it can pass your payment on",
      severity: "warning",
      status,
      observed,
      reason,
    };
  }

  // The exact shape the core produces for the owner's live mainnet node.
  const leaf = reachCheck(
    "fail",
    "no other node has reached this one: every one of its 4 connections was opened by this node itself. In its own words: total 4, inbound 0, outbound 4, public 4, role \"leaf\"",
    "Your node downloads blocks, checks every one of them itself, and is telling you the truth about the chain. What it cannot do is be reached: nobody can connect to it, it relays for nobody, and nothing proves it can carry your signed channel open or your close voucher out to the miners.",
  );

  it("is on the screen under a green READY header, not buried in the list", () => {
    const green = report([check("a", "fatal", "pass"), leaf]);
    const html = renderToStaticMarkup(<PreflightResult report={green} />);
    expect(html).toContain("READY");
    expect(html).toContain(
      "Nothing can reach your node, so it may not be able to pass your payment on",
    );
    // Plain words about the consequence, above the fold, not a bare count.
    expect(html).toContain("relays for nobody");
    expect(html).toContain("no other node has reached this one");
    // And it says out loud that it is not a reason to distrust the green.
    expect(html).toContain("This does not stop you");
    expect(html).toContain("not that your signed");
  });

  it("says unknown when the node never answered the question", () => {
    const unknown = report([
      check("a", "fatal", "pass"),
      reachCheck(
        "skip",
        "this node's build does not report who has reached it",
        "Treat it as unknown rather than as fine.",
      ),
    ]);
    const html = renderToStaticMarkup(<PreflightResult report={unknown} />);
    expect(html).toContain(
      "Whether anything can reach your node is unknown, which is not the same as fine",
    );
    expect(html).toContain("Treat it as unknown rather than as fine");
    expect(html).not.toContain("Nothing can reach your node,");
  });

  it("stays quiet when another node has actually reached this one", () => {
    const reached = report([
      check("a", "fatal", "pass"),
      reachCheck(
        "pass",
        "3 other node(s) have reached this one and it accepted them",
        "Another node reached yours and was accepted.",
      ),
    ]);
    const html = renderToStaticMarkup(<PreflightResult report={reached} />);
    expect(html).not.toContain("Nothing can reach your node,");
    expect(html).not.toContain("is unknown, which is not the same as fine");
    expect(html).toContain("3 other node(s) have reached this one");
  });

  it("never blocks the verdict, whichever way it went", () => {
    for (const status of ALL_STATUSES) {
      const checks = [check("a", "fatal", "pass"), reachCheck(status, "o", "r")];
      expect(preflightShowsPass(checks)).toBe(true);
    }
  });

  it("is shown once, not twice", () => {
    const html = renderToStaticMarkup(
      <PreflightResult report={report([check("a", "fatal", "pass"), leaf])} />,
    );
    expect(html.split("no other node has reached this one").length - 1).toBe(1);
  });
});

describe("the card", () => {
  it("offers the check and renders nothing else until it has been run", () => {
    const html = renderToStaticMarkup(
      <NativeRailPreflightCard report={null} running={false} onRun={vi.fn()} />,
    );
    expect(html).toContain("Run the check");
    // The claim about scope belongs beside the button, before anybody presses
    // it: this is the native rail, not the 2000 HAC registry contract.
    expect(html).toContain("signs nothing");
    expect(html).toContain("native ChannelPay rail");
    expect(html).toContain("2000 HAC");
    expect(html).not.toContain("READY");
  });
});

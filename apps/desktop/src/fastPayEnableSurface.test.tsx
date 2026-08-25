/// THE FAST PAY SCREEN MUST SAY WHY ENABLE IS REFUSING, AND MUST NOT LIE ABOUT
/// WHETHER FAST PAY IS ON.
///
/// Two defects are pinned here.
///
/// 1. `WalletStatus.fast_pay_state` is produced by `fast_pay_status_sync`, two
///    lines that answer "checking" for any wallet with a Hub URL and
///    "no_provider" for one without. It contacts nothing, so it can never say
///    "ready" and never say "needs_channel". This screen read it for the ON/OFF
///    pill and for the headline, so the pill said OFF on a working channel and
///    the headline said "Checking Fast Pay provider" forever.
///    `crates/wallet-core/tests/owner_enable_fast_pay_repro.rs` proves the core
///    half; this proves the screen no longer depends on it.
///
/// 2. The Enable button was disabled when no provider address was saved and when
///    the signing transport was ineligible, and the whole card vanished when the
///    Fast Pay evaluation did not say setup was possible. A greyed control
///    carries no reason and a missing control carries less. Both conditions now
///    render as named refusals beside a button that is still pressable, and the
///    core still refuses for real.

import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import FastPayScreen from "./screens/FastPayScreen";
import { fastPayEnableRefusals } from "@hacash/wallet-ui";

type FastPayProps = Parameters<typeof FastPayScreen>[0];

function settings(overrides: Record<string, unknown> = {}) {
  return {
    node_url: "http://127.0.0.1:8080",
    network_mode: "mainnet",
    l2_hub_url: "http://127.0.0.1:8790",
    hub_right_address: "1LFPqztfKhamVuzzV5WV6pHfykktGD5pMW",
    trusted_mainnet_fast_pay_pilot: true,
    privacy: {},
    send: {},
    ...overrides,
  } as unknown as FastPayProps["settings"];
}

/**
 * A wallet whose channel is open and working, described the way the core
 * actually describes it: the async evaluation says `ready`, and the synchronous
 * status field says `checking`, because that is the only thing it can say.
 */
function readyWallet(): Partial<FastPayProps> {
  return {
    settings: settings(),
    status: {
      locked: false,
      watch_only: false,
      address: "1AVRuFXNFi3rdMrPH4hdqSgFrEBnWisWaS",
      fast_pay_state: "checking",
      fast_pay_message: "Checking provider settlement and routing capabilities.",
      channel_id: "aa".repeat(16),
    } as unknown as FastPayProps["status"],
    fastPayDetail: {
      state: "ready",
      message: "Sends settle in seconds with no Fast Pay fee.",
      provider_name: "your provider",
      hub_url: null,
      can_enable: false,
      default_deposit_mei: 10,
    },
    fastPayReady: true,
  };
}

function render(overrides: Partial<FastPayProps> = {}): string {
  const props: FastPayProps = {
    status: null,
    settings: settings(),
    fastPayDetail: null,
    channelInfo: null,
    hubHealth: undefined,
    billsCount: 0,
    fastPayReady: false,
    fastPayNeedsSetup: false,
    hideAddresses: false,
    busy: false,
    setBusy: () => undefined,
    onNavigate: () => undefined,
    onEnableFastPay: async () => null,
    onApplyHub: async () => undefined,
    onSaveL2Settings: () => undefined,
    onHubHealth: () => undefined,
    onPreviewChannel: () => undefined,
    onOpenChannel: () => undefined,
    onCloseChannel: () => undefined,
    onRefresh: async () => undefined,
    onNotify: () => undefined,
    clearMessages: () => undefined,
    ...overrides,
  };
  return renderToStaticMarkup(<FastPayScreen {...props} />);
}

/** The markup of the Enable button, so a control elsewhere cannot answer for it. */
function enableButton(markup: string): string {
  const end = markup.indexOf("Enable Fast Pay</button>");
  expect(end, "the Enable Fast Pay button must be on the screen").toBeGreaterThan(-1);
  const start = markup.lastIndexOf("<button", end);
  return markup.slice(start, end);
}

describe("the state this screen shows", () => {
  it("reads the measured Fast Pay state, not the placeholder in WalletStatus", () => {
    const markup = render(readyWallet());
    expect(markup).toContain("Fast Pay is ON");
    // The word the placeholder would have produced.
    expect(markup).not.toContain("Checking Fast Pay provider");
    expect(markup).toContain("payments go via Fast Pay (instant)");
  });

  it("says the route is not known yet rather than claiming on-chain", () => {
    // fastPayDetail null: the evaluation has not answered.
    const markup = render();
    expect(markup).toContain("not known yet");
    expect(markup).not.toContain("payments go on-chain (standard, few minutes)");
  });

  it("names the provider, the provider address and the node without a terminal", () => {
    const markup = render();
    expect(markup).toContain("http://127.0.0.1:8790");
    expect(markup).toContain("1LFPqztfKhamVuzzV5WV6pHfykktGD5pMW");
    expect(markup).toContain("http://127.0.0.1:8080");
  });
});

describe("the Enable control", () => {
  it("is offered even when the Fast Pay evaluation does not say setup is possible", () => {
    // provider_incompatible with can_enable false: the state in which the whole
    // card, the deposit field and the button used to disappear.
    const markup = render({
      fastPayDetail: {
        state: "provider_incompatible",
        message: "Fast Pay is not available on this provider: something specific",
        provider_name: null,
        hub_url: null,
        can_enable: false,
        default_deposit_mei: 10,
      },
    });
    expect(markup).toContain("Turn Fast Pay ON");
    expect(markup).toContain("Enable Fast Pay</button>");
  });

  it("is never disabled for a missing provider address; it says so instead", () => {
    const markup = render({ settings: settings({ hub_right_address: "" }) });
    expect(enableButton(markup)).not.toContain("disabled");
    expect(markup).toContain("No provider address is saved");
    expect(markup).toContain("no_provider_address");
  });

  it("is never disabled for an ineligible signing transport; it says so instead", () => {
    const markup = render({
      settings: settings({ node_url: "http://node.example.com" }),
    });
    expect(enableButton(markup)).not.toContain("disabled");
    expect(markup).toContain("This node cannot sign on mainnet");
    expect(markup).toContain("signing_transport_ineligible");
    // And it quotes the node it judged, so the person can see what to change.
    expect(markup).toContain("http://node.example.com");
  });

  it("names withheld mainnet consent, which nothing on this screen used to name", () => {
    const markup = render({
      settings: settings({ trusted_mainnet_fast_pay_pilot: false }),
    });
    expect(markup).toContain("mainnet_consent_withheld");
  });

  it("does not claim readiness when nothing is stopping it", () => {
    const markup = render({
      // A preflight has not run, so the Hub's channel cap is unread. Unknown is
      // reported as unknown.
      settings: settings(),
    });
    expect(markup).toContain("channel_cap_unknown");
  });
});

describe("fastPayEnableRefusals", () => {
  const base = {
    settingsLoaded: true,
    watchOnly: false,
    locked: false,
    networkMode: "mainnet",
    nodeUrl: "http://127.0.0.1:8080",
    hubAddress: "1LFPqztfKhamVuzzV5WV6pHfykktGD5pMW",
    consentGranted: true,
    depositHac: "0.2",
    declaredChannelCapHac: "0.2",
    signingTransportEligible: true,
    signingTransportNotice: "notice",
  };

  it("is empty for the owner's exact configuration", () => {
    expect(fastPayEnableRefusals(base)).toEqual([]);
  });

  it("names a deposit over the Hub's own declared cap, with both numbers", () => {
    // 10 is what the deposit field holds before the Hub's recommendation
    // arrives, and it is fifty times this Hub's cap.
    const refusals = fastPayEnableRefusals({ ...base, depositHac: "10" });
    expect(refusals.map((r) => r.id)).toEqual(["deposit_over_declared_cap"]);
    expect(refusals[0].detail).toContain("10 HAC");
    expect(refusals[0].detail).toContain("0.2 HAC");
  });

  it("reports an unread cap as unread rather than as satisfied", () => {
    const refusals = fastPayEnableRefusals({ ...base, declaredChannelCapHac: null });
    expect(refusals.map((r) => r.id)).toEqual(["channel_cap_unknown"]);
  });

  it("names every applicable condition at once, not one at a time", () => {
    const refusals = fastPayEnableRefusals({
      ...base,
      hubAddress: "",
      consentGranted: false,
      signingTransportEligible: false,
      depositHac: "abc",
    });
    expect(refusals.map((r) => r.id)).toEqual([
      "no_provider_address",
      "signing_transport_ineligible",
      "mainnet_consent_withheld",
      "deposit_not_a_number",
    ]);
  });

  it("does not ask for mainnet consent off mainnet", () => {
    const refusals = fastPayEnableRefusals({
      ...base,
      networkMode: "testnet",
      consentGranted: false,
    });
    expect(refusals).toEqual([]);
  });
});

/**
 * The regression guard for the whole class.
 *
 * `status.fast_pay_state` is a placeholder the core cannot populate with
 * "ready" or "needs_channel". Comparing it against either value is always
 * false, and TypeScript cannot catch it because both sides are strings from
 * the same union. So the source itself is held to the rule.
 */
describe("nothing compares the placeholder against a value it cannot hold", () => {
  it("has no `fast_pay_state === \"ready\"` or `=== \"needs_channel\"` in either app", async () => {
    const { readFileSync, readdirSync, statSync } = await import("node:fs");
    const { join } = await import("node:path");

    const offenders: string[] = [];
    const walk = (dir: string) => {
      for (const entry of readdirSync(dir)) {
        const full = join(dir, entry);
        if (statSync(full).isDirectory()) {
          walk(full);
          continue;
        }
        if (!/\.tsx?$/.test(entry) || entry.includes(".test.")) continue;
        // The preview mock is allowed to hold any value: it is a fixture that
        // stands in for the core, not a reader of it.
        if (full.includes("ipcMock")) continue;
        const source = readFileSync(full, "utf8");
        for (const line of source.split("\n")) {
          if (
            /fast_pay_state\s*===\s*"(ready|needs_channel)"/.test(line) ||
            /"(ready|needs_channel)"\s*===\s*[\w.?]*fast_pay_state/.test(line)
          ) {
            offenders.push(`${full}: ${line.trim()}`);
          }
        }
      }
    };
    walk(join(process.cwd(), "src"));
    walk(join(process.cwd(), "..", "mobile", "src"));
    expect(offenders).toEqual([]);
  });
});

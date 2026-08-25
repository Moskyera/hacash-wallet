// @vitest-environment jsdom
/**
 * CAN A PERSON READ THIS SCREEN WITHOUT A TERMINAL?
 *
 * The owner was stuck on the Fast Pay screen. It should say, without a terminal,
 * four things in this order of importance:
 *
 *   1. what is the next thing I do, and can I do it right now
 *   2. if not, exactly what is stopping me, in words, not an identifier
 *   3. what does MY Hub allow, its own declared caps, not this build's ceilings
 *   4. is my node actually reachable, which the preflight already knows
 *
 * The screen had the raw material for all four and asked a person to infer every
 * one of them. These tests mount it and read the words back.
 *
 * NOTHING HERE IS A GATE. Every assertion is about what is SAID. The Enable
 * button stays pressable throughout and the core still refuses on its own
 * account.
 */
import { beforeEach, describe, expect, it, vi } from "vitest";
import { mountComponent, typeInto } from "./domHarness";
import FastPayScreen from "./screens/FastPayScreen";

/**
 * The screen fetches its own preflight, so the test serves one rather than
 * injecting it through a prop. That keeps the production component free of
 * test-only inputs, and it proves the thing the screen relies on: that the
 * read-only check runs by itself on arrival, without being asked.
 */
const nativeRailPreflight = vi.fn();
const channelInfo = vi.fn();

vi.mock("./api", () => ({
  api: {
    nativeRailPreflight: (...args: unknown[]) => nativeRailPreflight(...args),
    channelInfo: (...args: unknown[]) => channelInfo(...args),
    discoverHubs: async () => ({ online_count: 0, hubs: [] }),
    hubDeclaration: async () => ({ reachable: false }),
    fastPayInbox: async () => [],
    listBills: async () => [],
  },
}));

vi.mock("@tauri-apps/plugin-shell", () => ({ open: async () => undefined }));

type FastPayProps = Parameters<typeof FastPayScreen>[0];
type Mounted = ReturnType<typeof mountComponent>;

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

/** The owner's real Hub caps, as their /v1/readiness/mainnet publishes them. */
function preflight(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    schema: "hpay-native-rail-preflight/1",
    generated_unix: 1787665702,
    node_url: "http://127.0.0.1:8080",
    hub_url: "http://127.0.0.1:8790",
    owner_address: "1AVRuFXNFi3rdMrPH4hdqSgFrEBnWisWaS",
    hub_address: "1LFPqztfKhamVuzzV5WV6pHfykktGD5pMW",
    channel_deposit_hac: "0.2",
    payment_hac: "0.01",
    verdict: "pass",
    fatal_failed: 0,
    fatal_skipped: 0,
    warnings: 0,
    validity_seconds: 60,
    checks: [
      {
        id: "node_can_be_reached",
        title: "Your node answers",
        severity: "fatal",
        status: "pass",
        observed: "height 776386",
        reason: null,
      },
    ],
    declared_caps: {
      // 0.1 HAC per payment, 0.2 HAC per channel. The Hub's own numbers.
      max_payment_hac: "0.1",
      max_channel_funding_hac: "0.2",
      max_aggregate_tvl_hac: "0.2",
      aggregate_tvl_within_limit: true,
    },
    cannot_be_checked: [],
    ...overrides,
  };
}

function baseProps(overrides: Partial<FastPayProps> = {}): FastPayProps {
  return {
    status: {
      locked: false,
      watch_only: false,
      address: "1AVRuFXNFi3rdMrPH4hdqSgFrEBnWisWaS",
      fast_pay_state: "checking",
      fast_pay_message: "Checking provider settlement and routing capabilities.",
      channel_id: null,
    } as unknown as FastPayProps["status"],
    settings: settings(),
    fastPayDetail: {
      state: "needs_channel",
      message: "Your provider is ready. Open a channel to turn Fast Pay on.",
      provider_name: "your provider",
      hub_url: "http://127.0.0.1:8790",
      can_enable: true,
      default_deposit_mei: 0.2,
    },
    channelInfo: null,
    hubHealth: undefined,
    billsCount: 0,
    fastPayReady: false,
    fastPayNeedsSetup: true,
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
  } as FastPayProps;
}

/**
 * Mount the screen and let its own preflight land.
 *
 * The auto-run sits behind a 400ms timer, so typing in the deposit field does
 * not fire a request per keystroke. The timers are faked and advanced past it.
 *
 * A `null` report means the request never resolves, which is the honest shape of
 * "nobody has checked yet".
 */
async function screen(
  overrides: Partial<FastPayProps> = {},
  report: Record<string, unknown> | null = null,
): Promise<Mounted> {
  nativeRailPreflight.mockReset();
  if (report) {
    nativeRailPreflight.mockResolvedValue(report);
  } else {
    nativeRailPreflight.mockImplementation(() => new Promise(() => {}));
  }
  const view = mountComponent(<FastPayScreen {...baseProps(overrides)} />);
  await vi.advanceTimersByTimeAsync(500);
  return view;
}

/** The words a person reads, with runs of whitespace collapsed. */
function words(view: Mounted): string {
  return (view.container.textContent ?? "").replace(/\s+/g, " ");
}

beforeEach(() => {
  vi.useFakeTimers();
  channelInfo.mockReset().mockResolvedValue(null);
});

describe("1. what is the next thing I do, and can I do it right now", () => {
  it("names a next step at all", async () => {
    const view = await screen();
    expect(words(view)).toMatch(/Your next step|What is stopping you/);
    view.unmount();
  });

  it("tells a wallet with nothing in the way to press Enable", async () => {
    const view = await screen({}, preflight());
    const text = words(view);
    expect(text).toContain("Your next step");
    expect(text).toContain("Enable Fast Pay");
    view.unmount();
  });

  it("switches the label to the blocked wording when something is in the way", async () => {
    const view = await screen({ settings: settings({ hub_right_address: "" }) }, preflight());
    const text = words(view);
    expect(text).toContain("What is stopping you");
    expect(text).not.toContain("Your next step");
    view.unmount();
  });
});

describe("2. exactly what is stopping me, in words, not an identifier", () => {
  it("says the sentence, not just the id, when no provider address is saved", async () => {
    const view = await screen({ settings: settings({ hub_right_address: "" }) }, preflight());
    const text = words(view);
    expect(text).toContain("No provider address is saved");
    // The instruction a person can act on, not `no_provider_address` alone.
    expect(text).toContain("Use this hub");
    view.unmount();
  });

  it("names withheld mainnet consent in words", async () => {
    const view = await screen(
      { settings: settings({ trusted_mainnet_fast_pay_pilot: false }) },
      preflight(),
    );
    expect(words(view)).toContain("bounded mainnet pilot has not been accepted");
    view.unmount();
  });

  it("names an emptied deposit field instead of leaving the button silent", async () => {
    // `type="number"` will not hold "abc" - the browser and jsdom both blank it -
    // so the state a person can actually reach by deleting the amount is the
    // empty string. That used to produce a bare `return` and no sentence.
    const view = await screen({}, preflight());
    const deposit = view.container.querySelector<HTMLInputElement>('input[type="number"]');
    expect(deposit).not.toBeNull();
    typeInto(deposit!, "");
    const text = words(view);
    expect(text).toContain("The channel deposit is not a usable amount");
    expect(text).toContain("Enter a positive number of HAC");
    // And the button is still pressable, so the refusal is a sentence and not a
    // grey rectangle.
    expect(view.button("Enable Fast Pay")?.disabled).toBe(false);
    view.unmount();
  });

  it("says how many other things are still queued", async () => {
    const view = await screen(
      {
        settings: settings({
          hub_right_address: "",
          trusted_mainnet_fast_pay_pilot: false,
        }),
      },
      preflight(),
    );
    expect(words(view)).toMatch(/other thing.? still need/);
    view.unmount();
  });

  it("keeps the Enable button pressable rather than greying it", async () => {
    // A greyed button carries no reason. This repository has shipped that before.
    const view = await screen({ settings: settings({ hub_right_address: "" }) }, preflight());
    const enable = view.button("Enable Fast Pay");
    expect(enable).toBeDefined();
    expect(enable?.disabled).toBe(false);
    view.unmount();
  });
});

describe("3. what does MY Hub allow, its own declared caps", () => {
  it("prints the Hub's own declared caps, not this build's ceilings", async () => {
    const view = await screen({}, preflight());
    const text = words(view);
    // 0.2 HAC per channel and 0.1 HAC per payment are what the owner's Hub
    // declares. The build's hard ceilings are different numbers entirely.
    expect(text).toContain("0.2");
    expect(text).toContain("0.1");
    view.unmount();
  });

  it("refuses a deposit over the Hub's declared cap, quoting both numbers", async () => {
    const view = await screen({}, preflight());
    const deposit = view.container.querySelector<HTMLInputElement>('input[type="number"]');
    typeInto(deposit!, "5");
    const text = words(view);
    expect(text).toContain("larger than this Hub will accept");
    expect(text).toContain("5 HAC");
    expect(text).toContain("0.2 HAC");
    view.unmount();
  });

  it("says the cap is unknown rather than fine when nobody has read it", async () => {
    const view = await screen();
    const text = words(view);
    expect(text).toContain("has not been read yet");
    expect(text).toContain("Unknown is not the same as fine");
    view.unmount();
  });
});

describe("4. is my node actually reachable", () => {
  it("says nobody has checked, when nobody has", async () => {
    const view = await screen();
    expect(words(view)).toContain("Nobody has checked whether your node answers yet");
    view.unmount();
  });

  it("promotes an unreachable node above every other cause", async () => {
    const unreachable = preflight({
      checks: [
        {
          id: "node_can_be_reached",
          title: "Your node answers",
          severity: "fatal",
          status: "fail",
          observed: "connection refused",
          reason: "connection refused",
        },
      ],
    });
    const view = await screen(
      { settings: settings({ trusted_mainnet_fast_pay_pilot: false }) },
      unreachable,
    );
    const text = words(view);
    expect(text).toContain("Your node is not answering");
    // Consent is also unmet, and it must NOT be the headline: a node nobody can
    // reach makes every other step pointless.
    expect(text.indexOf("Your node is not answering")).toBeLessThan(
      text.indexOf("bounded mainnet pilot has not been accepted"),
    );
    view.unmount();
  });

  it("does not call a node broken when the check was skipped", async () => {
    const skipped = preflight({
      checks: [
        {
          id: "node_can_be_reached",
          title: "Your node answers",
          severity: "fatal",
          status: "skip",
          observed: "not attempted",
          reason: "not attempted",
        },
      ],
    });
    const view = await screen({}, skipped);
    expect(words(view)).not.toContain("Your node is not answering");
    view.unmount();
  });
});

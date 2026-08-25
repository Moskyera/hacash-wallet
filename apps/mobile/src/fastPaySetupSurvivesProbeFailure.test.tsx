// @vitest-environment jsdom
/**
 * THE WHOLE SETUP SURFACE DISAPPEARED WHEN THE CHANNEL COULD NOT BE READ.
 *
 * The deposit fields, the read-only preflight that names what is wrong with the
 * node and the Hub, and the two buttons that actually open the channel all sat
 * inside one guard:
 *
 *     {channelProbe.status === "ready" && !channel && ( ... )}
 *
 * `loadChannel` sets the probe to `failed` when `api.channelInfo()` rejects, and
 * leaves it `loading` if the call never returns. In either case that entire card
 * was removed from the page - while the "Enable" button above it, driven only by
 * `fastPay`, stayed on screen.
 *
 * So at the exact moment the wallet could not read the channel, a person was
 * still offered the control that commits money and denied every surface that
 * could explain a refusal. All that was left was a "Retry channel check" button.
 *
 * The gates do not move. The core still refuses whatever it refused. What
 * changes is that the explanation stays on the page.
 */
import { beforeEach, describe, expect, it, vi } from "vitest";
import { mountComponent } from "./domHarness";
import FastPayChannelScreen from "./screens/FastPayChannelScreen";

const channelInfo = vi.fn();
const nativeRailPreflight = vi.fn();

vi.mock("./api", () => ({
  api: {
    channelInfo: (...a: unknown[]) => channelInfo(...a),
    nativeRailPreflight: (...a: unknown[]) => nativeRailPreflight(...a),
    discoverHubs: async () => ({ online_count: 0, hubs: [] }),
    hubDeclaration: async () => ({ reachable: false }),
    listBills: async () => [],
    fastPayInbox: async () => [],
  },
}));

type Props = Parameters<typeof FastPayChannelScreen>[0];

function props(overrides: Partial<Props> = {}): Props {
  return {
    fastPay: {
      state: "needs_channel",
      message: "Your provider is ready. Open a channel to turn Fast Pay on.",
      provider_name: "your provider",
      hub_url: "http://127.0.0.1:8790",
      can_enable: true,
      default_deposit_mei: 0.2,
    },
    settings: {
      node_url: "http://127.0.0.1:8080",
      network_mode: "mainnet",
      l2_hub_url: "http://127.0.0.1:8790",
      hub_right_address: "1LFPqztfKhamVuzzV5WV6pHfykktGD5pMW",
      trusted_mainnet_fast_pay_pilot: true,
    },
    hubUrl: "http://127.0.0.1:8790",
    hubAddress: "1LFPqztfKhamVuzzV5WV6pHfykktGD5pMW",
    userAddress: "1AVRuFXNFi3rdMrPH4hdqSgFrEBnWisWaS",
    hideAddresses: false,
    watchOnly: false,
    busy: false,
    setBusy: () => undefined,
    onRefresh: async () => undefined,
    onApplyHub: async () => undefined,
    onToast: () => undefined,
    ...overrides,
  } as unknown as Props;
}

async function mount() {
  const view = mountComponent(<FastPayChannelScreen {...props()} />);
  await vi.advanceTimersByTimeAsync(600);
  return view;
}

function words(view: ReturnType<typeof mountComponent>): string {
  return (view.container.textContent ?? "").replace(/\s+/g, " ");
}

beforeEach(() => {
  vi.useFakeTimers();
  nativeRailPreflight.mockReset().mockImplementation(() => new Promise(() => {}));
});

describe("the setup surface survives a channel probe that failed", () => {
  it("still shows the deposit field when the channel read was refused", async () => {
    channelInfo.mockRejectedValue(new Error("node unreachable"));
    const view = await mount();
    expect(words(view)).toContain("Your deposit");
    view.unmount();
  });

  it("still shows the setup heading when the channel read was refused", async () => {
    channelInfo.mockRejectedValue(new Error("node unreachable"));
    const view = await mount();
    expect(words(view)).toContain("Setup");
    view.unmount();
  });

  it("still shows the infrastructure check, which is what explains the failure", async () => {
    channelInfo.mockRejectedValue(new Error("node unreachable"));
    const view = await mount();
    // The preflight card is the only surface that reports node reachability and
    // the Hub's declared caps. It vanished exactly when it was needed.
    expect(words(view).toLowerCase()).toMatch(/check|preflight/);
    view.unmount();
  });

  it("keeps the channel failure named, and offers the retry", async () => {
    channelInfo.mockRejectedValue(new Error("node unreachable"));
    const view = await mount();
    const text = words(view);
    expect(text).toContain("node unreachable");
    expect(view.button("Retry channel check")).toBeDefined();
    view.unmount();
  });

  it("says the channel state is unknown rather than implying it is absent", async () => {
    // "no channel" and "could not read whether there is a channel" are different
    // facts, and only one of them means it is safe to open one.
    channelInfo.mockRejectedValue(new Error("node unreachable"));
    const view = await mount();
    expect(words(view).toLowerCase()).toContain("could not be read");
    view.unmount();
  });

  it("says a channel read still in flight is unfinished, not failed", async () => {
    // The card is offered for `loading` as well as `failed`, and the two are not
    // the same fact. A first render that has not heard back yet must not print
    // "could not be read": that is a failure announced during ordinary success,
    // which is the wrong-cause reporting this whole card exists to stop.
    channelInfo.mockImplementation(() => new Promise(() => {}));
    const view = await mount();
    const text = words(view).toLowerCase();
    expect(text).toContain("your deposit");
    expect(text).toContain("still being read");
    expect(text).not.toContain("could not be read");
    view.unmount();
  });

  it("shows the setup surface normally when there is simply no channel", async () => {
    channelInfo.mockResolvedValue(null);
    const view = await mount();
    const text = words(view);
    expect(text).toContain("Your deposit");
    // And it does NOT carry the unknown-state caveat in the normal case.
    expect(text.toLowerCase()).not.toContain("could not be read");
    view.unmount();
  });

  it("does not offer setup when a channel already exists", async () => {
    channelInfo.mockResolvedValue({
      id: "ab".repeat(16),
      left: { address: "1AVRuFXNFi3rdMrPH4hdqSgFrEBnWisWaS", hacash: "0.2", satoshi: 0 },
      right: { address: "1LFPqztfKhamVuzzV5WV6pHfykktGD5pMW", hacash: "0", satoshi: 0 },
    });
    const view = await mount();
    expect(words(view)).toContain("Active channel");
    view.unmount();
  });
});

// @vitest-environment jsdom
/**
 * THE HUB'S OWN REFUSAL, ON A PHONE.
 *
 * `FastPayStatus.message` is the field that carries the reason a provider was
 * refused. `provider_incompatible_because` (crates/wallet-core/src/fast_pay.rs:152)
 * exists purely to put the Hub's own words in it, and the comment above it says
 * why: the generic sentence is "simply false" when a mainnet readiness gate
 * refused, because the same Hub was publishing `settlement_ready: true`,
 * `cross_channel_ready: true` and a zero fee at that moment. What it lacked was
 * the mainnet guarantees. Telling somebody a wrong cause is worse than a vague
 * one - they go and change the provider, which fixes nothing.
 *
 * The mobile screen never rendered `message`. It rendered
 * `fastPayStatusLine(fastPay.state, ...)`, a hardcoded sentence switched off the
 * state enum, and for `provider_incompatible` that sentence is exactly the false
 * one: "Provider cannot create safe, fee-free routed settlements."
 *
 * Desktop already gets this right (FastPayScreen.tsx renders
 * `fastPayDetail?.message ?? ...`). This is the phone catching up.
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

/**
 * The exact shape the core produces for a Hub that answers healthily and is
 * then refused by a mainnet readiness gate. This is the owner's situation.
 */
const REFUSAL =
  "Fast Pay is not available on this provider: Fast Pay provider does not match " +
  "the explicitly selected mainnet settlement policy; new funding is blocked: your " +
  'wallet is set to trustless settlement only (the mainnet pilot consent box is not ' +
  'ticked), and the provider publishes profile "mainnet-bounded-pilot"';

function props(overrides: Partial<Props> = {}): Props {
  return {
    fastPay: {
      state: "provider_incompatible",
      message: REFUSAL,
      provider_name: null,
      hub_url: null,
      can_enable: false,
      default_deposit_mei: 0.2,
    },
    settings: {
      node_url: "http://127.0.0.1:8080",
      network_mode: "mainnet",
      l2_hub_url: "http://127.0.0.1:8790",
      hub_right_address: "1LFPqztfKhamVuzzV5WV6pHfykktGD5pMW",
      trusted_mainnet_fast_pay_pilot: false,
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

function words(view: ReturnType<typeof mountComponent>): string {
  return (view.container.textContent ?? "").replace(/\s+/g, " ");
}

beforeEach(() => {
  channelInfo.mockReset().mockResolvedValue(null);
  nativeRailPreflight.mockReset().mockImplementation(() => new Promise(() => {}));
});

describe("the phone prints the Hub's reason, not a generic guess", () => {
  it("renders the message the core put in FastPayStatus", () => {
    const view = mountComponent(<FastPayChannelScreen {...props()} />);
    expect(words(view)).toContain("does not match the explicitly selected mainnet");
    view.unmount();
  });

  it("does not print the false generic cause when a real reason exists", () => {
    // This is the sentence that sends a person off to replace a working Hub.
    const view = mountComponent(<FastPayChannelScreen {...props()} />);
    expect(words(view)).not.toContain(
      "Provider cannot create safe, fee-free routed settlements",
    );
    view.unmount();
  });

  it("still says something useful when the core supplied no message", () => {
    const view = mountComponent(
      <FastPayChannelScreen
        {...props({
          fastPay: {
            state: "needs_channel",
            message: "",
            provider_name: null,
            hub_url: null,
            can_enable: true,
            default_deposit_mei: 0.2,
          } as unknown as Props["fastPay"],
        })}
      />,
    );
    // Falls back to the state line rather than rendering an empty paragraph.
    expect(words(view)).toMatch(/Deposit .* HAC once to turn on/);
    view.unmount();
  });

  it("keeps the Enable control on screen for a refusing provider", () => {
    // `can_enable` is false here. The control must still be there, with the
    // reason beside it, rather than vanishing and leaving nothing to press.
    const view = mountComponent(<FastPayChannelScreen {...props()} />);
    expect(view.button("Enable")).toBeDefined();
    view.unmount();
  });
});

// @vitest-environment jsdom
/**
 * THE SAME SCREEN IN YOUR HAND.
 *
 * The Fast Pay screens were reordered into three bands: "can I act right now"
 * first and carrying the control, "what am I about to agree to" second, and the
 * evidence folded behind `<details>` third. If only the desktop got the first
 * band, the two screens would be further apart than before the change and a
 * person would have to relearn the screen when they picked up their phone. The
 * phone had never had a next-step block at all.
 *
 * So these assert the shape on mobile, and they assert the rule that keeps the
 * change honest: folding is allowed, removing is not.
 *
 * NOTHING HERE IS A GATE. The Enable button stays pressable in every case, and
 * `prepare_channel_open`, the signing boundary and the Hub each refuse on their
 * own account.
 */
import { beforeEach, describe, expect, it, vi } from "vitest";
import { mountComponent } from "./domHarness";
import FastPayChannelScreen from "./screens/FastPayChannelScreen";
import {
  FAST_PAY_MAINNET_CEILINGS,
  FAST_PAY_MAINNET_CHANNEL_REFUSED,
  FAST_PAY_MAINNET_CONSENT,
} from "@hacash/wallet-ui";

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
      provider_name: "HPAY Fast Pay Hub",
      hub_url: "http://127.0.0.1:8790",
      can_enable: true,
      default_deposit_mei: 0.2,
    },
    settings: {
      node_url: "http://127.0.0.1:8080",
      network_mode: "mainnet",
      l2_hub_url: "http://127.0.0.1:8790",
      hub_right_address: "18bV2fjWhpQpmGRLifS8PDmzA6ATRJwVgq",
      trusted_mainnet_fast_pay_pilot: true,
    },
    hubUrl: "http://127.0.0.1:8790",
    hubAddress: "18bV2fjWhpQpmGRLifS8PDmzA6ATRJwVgq",
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

/** Everything in the document, folded or not. */
function allText(root: HTMLElement): string {
  return (root.textContent ?? "").replace(/\s+/g, " ");
}

/** What a person meets: the same document with every `<details>` removed. */
function metText(root: HTMLElement): string {
  const clone = root.cloneNode(true) as HTMLElement;
  clone.querySelectorAll("details").forEach((node) => node.remove());
  return (clone.textContent ?? "").replace(/\s+/g, " ");
}

beforeEach(() => {
  channelInfo.mockReset().mockResolvedValue(null);
  nativeRailPreflight.mockReset().mockImplementation(() => new Promise(() => {}));
});

describe("the phone answers can-I-act-now first", () => {
  it("has a next-step block at all, which it never had before", () => {
    const view = mountComponent(<FastPayChannelScreen {...props()} />);
    const band = view.container.querySelector(".fp-next-step");
    expect(band).not.toBeNull();
    expect(band?.textContent).toMatch(/Your next step|What is stopping you/);
    view.unmount();
  });

  it("puts that block before any folded section", () => {
    const view = mountComponent(<FastPayChannelScreen {...props()} />);
    const nodes = Array.from(view.container.querySelectorAll(".fp-next-step, details"));
    expect(nodes.length).toBeGreaterThan(1);
    expect(nodes[0].className).toContain("fp-next-step");
    view.unmount();
  });

  it("keeps the Enable button in that block, pressable, and out of every fold", () => {
    const view = mountComponent(<FastPayChannelScreen {...props()} />);
    const enable = view.button("Enable");
    expect(enable).toBeDefined();
    expect(enable?.disabled).toBe(false);
    expect(enable?.closest("details")).toBeNull();
    expect(enable?.closest(".fp-next-step")).not.toBeNull();
    view.unmount();
  });

  it("names the blocking cause in the band when consent is withheld", () => {
    const view = mountComponent(
      <FastPayChannelScreen
        {...props({
          settings: {
            node_url: "http://127.0.0.1:8080",
            network_mode: "mainnet",
            l2_hub_url: "http://127.0.0.1:8790",
            hub_right_address: "18bV2fjWhpQpmGRLifS8PDmzA6ATRJwVgq",
            trusted_mainnet_fast_pay_pilot: false,
          } as unknown as Props["settings"],
        })}
      />,
    );
    const band = view.container.querySelector(".fp-next-step");
    expect(band?.textContent).toContain("What is stopping you");
    expect(band?.textContent).toContain("bounded mainnet pilot has not been accepted");
    view.unmount();
  });

  it("says the deposit the button will actually send", () => {
    // The field under Setup feeds the preview and open path; Enable sends the
    // provider's recommendation. Saying which is which beside the button is the
    // honest half of leaving that behaviour alone.
    const view = mountComponent(<FastPayChannelScreen {...props()} />);
    const band = view.container.querySelector(".fp-next-step");
    expect(band?.textContent).toContain("Enable deposits 0.2 HAC");
    view.unmount();
  });
});

describe("the phone never folds what you are agreeing to", () => {
  it("renders the consent sentence and the ceilings without opening anything", () => {
    const view = mountComponent(<FastPayChannelScreen {...props()} />);
    const met = metText(view.container);
    expect(met).toContain(FAST_PAY_MAINNET_CONSENT);
    expect(met).toContain(FAST_PAY_MAINNET_CEILINGS);
    expect(met).toContain("can only be closed if the Hub co-signs");
    view.unmount();
  });

  it("says the channel will be refused, above the box that used to open it", () => {
    // Same rule as the desktop screen: the plain fact about the way out is met
    // BEFORE the money moves. wallet-core refuses at prepare and is the
    // authority; this sentence only has to arrive first, and it must not wait
    // on the preflight having reached a Hub, because the fact does not.
    const view = mountComponent(<FastPayChannelScreen {...props()} />);
    const met = metText(view.container);
    expect(met).toContain(FAST_PAY_MAINNET_CHANNEL_REFUSED);
    expect(met).toContain("Agent Wallet");
    expect(met.indexOf("will not open a mainnet Fast Pay channel")).toBeLessThan(
      met.indexOf("I will not put in more than I can afford to lose"),
    );
    view.unmount();
  });

  it("never tells a phone to take a voucher no build on it can take", () => {
    // The Agent Wallet is absent from the phone by target gate, so this
    // instruction was doubly wrong here. It came from the shared blocker
    // sentence and is gone from both apps at once.
    const view = mountComponent(<FastPayChannelScreen {...props()} />);
    expect(metText(view.container)).not.toMatch(/take a close voucher before you pay/i);
    view.unmount();
  });

  it("shows the counterparty by URL and on-chain address", () => {
    const view = mountComponent(<FastPayChannelScreen {...props()} />);
    const met = metText(view.container);
    expect(met).toContain("http://127.0.0.1:8790");
    expect(met).toContain("18bV2fjWhpQpmGRLifS8PDmzA6ATRJwVgq");
    view.unmount();
  });

  it("says which route a payment takes right now", () => {
    const view = mountComponent(<FastPayChannelScreen {...props()} />);
    expect(metText(view.container)).toContain("payments go on-chain");
    view.unmount();
  });

  it("names whose failure the consent text describes for a self-hosted Hub", () => {
    const view = mountComponent(<FastPayChannelScreen {...props()} />);
    expect(metText(view.container)).toContain(
      "you are the counterparty to your own channel",
    );
    view.unmount();
  });

  it("still prints the Hub's own refusal rather than a generic guess", () => {
    const view = mountComponent(
      <FastPayChannelScreen
        {...props({
          fastPay: {
            state: "provider_incompatible",
            message: "Fast Pay is not available on this provider: the Hub said so",
            provider_name: null,
            hub_url: null,
            can_enable: false,
            default_deposit_mei: 0.2,
          } as unknown as Props["fastPay"],
        })}
      />,
    );
    expect(metText(view.container)).toContain("the Hub said so");
    view.unmount();
  });
});

describe("the phone folds the evidence without losing it", () => {
  it("keeps every enable refusal in the document, behind a counted summary", () => {
    const view = mountComponent(
      <FastPayChannelScreen
        {...props({
          hubAddress: "",
          settings: {
            node_url: "http://127.0.0.1:8080",
            network_mode: "mainnet",
            l2_hub_url: "http://127.0.0.1:8790",
            hub_right_address: "",
            trusted_mainnet_fast_pay_pilot: false,
          } as unknown as Props["settings"],
        })}
      />,
    );
    const all = allText(view.container);
    expect(all).toContain("no_provider_address");
    expect(all).toContain("mainnet_consent_withheld");
    // No provider address, withheld consent, and an unread per-channel cap,
    // because nobody has run the check on this phone yet.
    expect(all).toContain("channel_cap_unknown");
    const fold = Array.from(view.container.querySelectorAll("details")).find((node) =>
      (node.querySelector("summary")?.textContent ?? "").includes(
        "Everything stopping Enable",
      ),
    );
    expect(fold, "the refusal queue must have a fold of its own").toBeDefined();
    // The count in the summary is the length of the list underneath it. Asserted
    // against the rendered list rather than against a number typed here, so the
    // day a fourth refusal appears this still holds or fails loudly.
    const listed = fold?.querySelectorAll("li").length ?? 0;
    expect(listed).toBe(3);
    expect(fold?.querySelector("summary")?.textContent).toContain(
      `${listed} things are stopping Enable right now`,
    );
    view.unmount();
  });

  it("keeps the hub-sourcing paragraphs present, with an honest summary", () => {
    const view = mountComponent(<FastPayChannelScreen {...props()} />);
    const all = allText(view.container);
    expect(all).toContain("There is no public Fast Pay provider and no directory");
    expect(all).toContain("Bounded pilot Hubs admit named addresses only");
    const summaries = Array.from(view.container.querySelectorAll("summary")).map((n) =>
      (n.textContent ?? "").replace(/\s+/g, " "),
    );
    const hubs = summaries.find((line) => line.includes("Where hubs come from"));
    // The summary carries the content rather than hiding it.
    expect(hubs).toContain("no public hub and no directory");
    expect(hubs).toContain("moves this risk to you rather than removing it");
    view.unmount();
  });

  it("keeps what the check does in the document before anyone runs it", () => {
    const view = mountComponent(<FastPayChannelScreen {...props()} />);
    expect(allText(view.container)).toContain("signs nothing");
    expect(allText(view.container)).toContain("2000 HAC");
    view.unmount();
  });
});

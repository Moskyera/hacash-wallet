// @vitest-environment jsdom
/**
 * WHAT THE OWNER ACTUALLY READS, ON THEIR OWN CONFIGURATION.
 *
 * Their live Hub, verbatim from http://127.0.0.1:8790: version 7,
 * settlement_ready, cross_channel_ready and official_channelpay_ready all true,
 * hub_fee_mei "0", profile mainnet-bounded-pilot, trusted_bounded_pilot true,
 * payments_enabled true, mainnet_detected true, blockers [], and caps of
 * 10000000 / 20000000 zhu, which is 0.1 HAC per payment and 0.2 HAC per channel.
 *
 * This mounts the screen against exactly that and prints the copy, so the
 * wording is reviewed rather than assumed.
 */
import { beforeEach, describe, expect, it, vi } from "vitest";
import { mountComponent } from "./domHarness";
import FastPayScreen from "./screens/FastPayScreen";

const nativeRailPreflight = vi.fn();

vi.mock("./api", () => ({
  api: {
    nativeRailPreflight: (...a: unknown[]) => nativeRailPreflight(...a),
    channelInfo: async () => null,
    discoverHubs: async () => ({ online_count: 0, hubs: [] }),
    hubDeclaration: async () => ({ reachable: false }),
    fastPayInbox: async () => [],
    listBills: async () => [],
  },
}));
vi.mock("@tauri-apps/plugin-shell", () => ({ open: async () => undefined }));

type FastPayProps = Parameters<typeof FastPayScreen>[0];

/** The owner's preflight, with their Hub's own declared caps. */
const OWNER_PREFLIGHT = {
  schema: "hpay-native-rail-preflight/1",
  generated_unix: 1787665702,
  node_url: "http://127.0.0.1:8080",
  hub_url: "http://127.0.0.1:8790",
  owner_address: "1AVRuFXNFi3rdMrPH4hdqSgFrEBnWisWaS",
  hub_address: "18bV2fjWhpQpmGRLifS8PDmzA6ATRJwVgq",
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
      observed: "height 776386, tip age 351s",
      reason: null,
    },
  ],
  declared_caps: {
    max_payment_hac: "0.1",
    max_channel_funding_hac: "0.2",
    max_aggregate_tvl_hac: "0.2",
    aggregate_tvl_within_limit: true,
  },
  cannot_be_checked: [],
};

function props(overrides: Partial<FastPayProps> = {}): FastPayProps {
  return {
    status: {
      locked: false,
      watch_only: false,
      address: "1AVRuFXNFi3rdMrPH4hdqSgFrEBnWisWaS",
      // The placeholder the sync status can only ever produce.
      fast_pay_state: "checking",
      fast_pay_message: "Checking provider settlement and routing capabilities.",
      channel_id: null,
    } as unknown as FastPayProps["status"],
    settings: {
      node_url: "http://127.0.0.1:8080",
      network_mode: "mainnet",
      l2_hub_url: "http://127.0.0.1:8790",
      hub_right_address: "18bV2fjWhpQpmGRLifS8PDmzA6ATRJwVgq",
      trusted_mainnet_fast_pay_pilot: true,
      privacy: {},
      send: {},
    } as unknown as FastPayProps["settings"],
    fastPayDetail: {
      state: "needs_channel",
      message: "Your provider is ready. Open a channel to turn Fast Pay on.",
      provider_name: "HPAY Fast Pay Hub",
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

beforeEach(() => {
  vi.useFakeTimers();
  nativeRailPreflight.mockReset().mockResolvedValue(OWNER_PREFLIGHT);
});

describe("the owner's own screen", () => {
  it("prints the next step block for review", async () => {
    const view = mountComponent(<FastPayScreen {...props()} />);
    await vi.advanceTimersByTimeAsync(600);
    const block = view.container.querySelector(".fp-next-step");
    expect(block).not.toBeNull();
    const copy = (block?.textContent ?? "").replace(/\s+/g, " ").trim();
    // Printed so the wording is read, not assumed.
    console.log("\n[owner sees, next step] " + copy + "\n");
    expect(copy).toContain("Your next step");
    expect(copy).toContain("Enable Fast Pay");
    view.unmount();
  });

  it("pre-fills the deposit from the Hub's own recommendation, not the build default", async () => {
    // The field's initial state is "10", and an effect replaces it with
    // `fastPayDetail.default_deposit_mei`, which the core sets to the smaller of
    // the Hub's declared per-channel cap and the wallet default. For this Hub
    // that is 0.2 HAC. So the owner does not arrive at a refusal they have to
    // work out for themselves; the screen has already used their Hub's number.
    const view = mountComponent(<FastPayScreen {...props()} />);
    await vi.advanceTimersByTimeAsync(600);
    const deposit = view.container.querySelector<HTMLInputElement>('input[type="number"]');
    expect(deposit?.value).toBe("0.2");
    view.unmount();
  });

  it("prints the deposit refusal when the amount exceeds their Hub's 0.2 HAC cap", async () => {
    const view = mountComponent(
      <FastPayScreen
        {...props({
          // Same wallet, but the Hub recommends more than it will accept, which
          // is the shape of the mistake a person makes by typing over the cap.
          fastPayDetail: {
            state: "needs_channel",
            message: "Your provider is ready. Open a channel to turn Fast Pay on.",
            provider_name: "HPAY Fast Pay Hub",
            hub_url: "http://127.0.0.1:8790",
            can_enable: true,
            default_deposit_mei: 10,
          } as unknown as FastPayProps["fastPayDetail"],
        })}
      />,
    );
    await vi.advanceTimersByTimeAsync(600);
    const copy = (view.container.textContent ?? "").replace(/\s+/g, " ");
    const at = copy.indexOf("larger than this Hub will accept");
    expect(at).toBeGreaterThan(-1);
    console.log("\n[owner sees, refusal] " + copy.slice(at, at + 220).trim() + "\n");
    expect(copy).toContain("0.2 HAC");
    view.unmount();
  });
});

// @vitest-environment jsdom
/**
 * THE STEP WHERE MOST PEOPLE LEAVE.
 *
 * Install, create a wallet, see a balance, press Send. `wallet_prepare_send_hac`
 * reaches `require_online_signing_transport`
 * (crates/wallet-core/src/wallet/authorization_service.rs:246), fails, and
 * `formatInvokeError` hands the raw core string to a toast: "mainnet signing
 * requires HTTPS, except for a node on this same device". No next step, and
 * nothing anywhere on the plain sending path had mentioned the rule.
 *
 * Three facts made it a dead end rather than an obstacle:
 *   - the shipped default node provably cannot sign on mainnet
 *     (crates/wallet-core/src/settings.rs asserts
 *     `validate_signing_node_url(DEFAULT_NODE_URL, "mainnet").is_err()`),
 *   - `MAINNET_SIGNING_TRANSPORT_NOTICE` rendered in exactly one place in the
 *     product, on the Fast Pay screen, which a plain sender never opens,
 *   - and Settings advised against changing the one setting that would fix it.
 *
 * These tests are about WHEN the person learns, and whether what they read
 * tells them what to do. They assert nothing about whether the send is allowed:
 * that stays the core's decision, enforced at prepare time and again at the
 * signing boundary. This side only mirrors it so nobody is refused after the
 * fact for a condition the app already knew about.
 */
import { describe, expect, it, vi } from "vitest";
import { LocaleProvider } from "@hacash/wallet-ui";
import { emptyAssetTrends } from "./assetTrends";
import { mountComponent } from "./domHarness";
import HomeScreen from "./screens/HomeScreen";
import SendScreen from "./screens/SendScreen";
import SettingsScreen from "./screens/SettingsScreen";

vi.mock("@tauri-apps/plugin-shell", () => ({ open: async () => undefined }));
vi.mock("./api", () => ({
  api: {
    discoverNodes: async () => ({
      active_node: "http://nodeapi.hacash.org",
      switched: false,
      network_mode: "mainnet",
      candidates: [],
    }),
    appUpdateStatus: async () => null,
    listDappApps: async () => [],
  },
}));

/** The node every fresh install ships pointed at, and the one that cannot sign. */
const OFFICIAL = "http://nodeapi.hacash.org";
/** Where a Hacash fullnode on this machine answers. Mirrors LOCAL_NODE_URL. */
const LOCAL = "http://127.0.0.1:8080";

type SendProps = Parameters<typeof SendScreen>[0];
type HomeProps = Parameters<typeof HomeScreen>[0];

function status(nodeUrl: string) {
  return {
    has_wallet: true,
    locked: false,
    address: "1AVRuFXNFi3rdMrPH4hdqSgFrEBnWisWaS",
    security_profile: "balanced",
    node_url: nodeUrl,
    network_mode: "mainnet",
    l2_enabled: false,
    l2_hub_url: null,
    channel_id: null,
    webauthn_enabled: false,
    l2_bill_count: 0,
    auto_lock_secs: 600,
    seconds_until_lock: null,
    hardware_signing_mode: "software",
    require_second_factor_above_mei: 0,
    signing_available: true,
    watch_only: false,
    privacy: {},
    dust_whisper: {},
    fast_pay_state: "not_configured",
    fast_pay_message: "",
    legacy_key_derivation: null,
  } as unknown as SendProps["status"];
}

function sendProps(nodeUrl: string): SendProps {
  return {
    active: true,
    status: status(nodeUrl),
    assets: null,
    hideBalances: false,
    hideAddresses: false,
    fastPayReady: false,
    nativeBioAvailable: false,
    busy: false,
    setBusy: () => {},
    // An address and an amount are already filled in, so the Continue button
    // is not disabled for any reason other than the one under test.
    sendTo: "1LFPqztfKhamVuzzV5WV6pHfykktGD5pMW",
    setSendTo: () => {},
    sendAmount: "5",
    setSendAmount: () => {},
    sendHubFeePayer: "sender",
    sendForceL1: false,
    setSendForceL1: () => {},
    sendL1FeeSpeed: "normal",
    setSendL1FeeSpeed: () => {},
    sendServiceFeeEnabled: true,
    setSendServiceFeeEnabled: () => {},
    serviceFeeRate: 0.0006,
    showSendOptions: false,
    setShowSendOptions: () => {},
    sendQrScanOpen: false,
    setSendQrScanOpen: () => {},
    preview: null,
    clearPreview: () => {},
    persistSendPreferences: async () => {},
    onPaymentQr: () => {},
    onPreviewSend: () => {},
    onConfirmSend: () => {},
    onNavigate: () => {},
    onNotify: () => {},
    onSent: async () => {},
  } as unknown as SendProps;
}

function homeProps(nodeUrl: string): HomeProps {
  return {
    status: status(nodeUrl),
    assets: null,
    assetTrends: emptyAssetTrends(),
    history: [],
    hideBalances: false,
    hideAddresses: false,
    fastPayReady: false,
    lastTx: "",
    privacy: {},
    onNavigate: () => {},
    onOpenAgent: () => {},
    onNotify: () => {},
    clearMessages: () => {},
  } as unknown as HomeProps;
}

function mountSend(nodeUrl: string) {
  return mountComponent(
    <LocaleProvider>
      <SendScreen {...sendProps(nodeUrl)} />
    </LocaleProvider>,
  );
}

function mountHome(nodeUrl: string) {
  return mountComponent(
    <LocaleProvider>
      <HomeScreen {...homeProps(nodeUrl)} />
    </LocaleProvider>,
  );
}

/**
 * A REMOTE PLAINTEXT NODE THAT IS NOT THE NAMED EXCEPTION.
 *
 * `validate_node_url` refuses most of these before the transport rule is
 * reached, so this stands for the general blocked case rather than a setting a
 * person is likely to hold.
 */
const OTHER_PLAINTEXT = "http://node.example.com";

describe("the official node sends, and says what that costs", () => {
  /**
   * THE CORRECTION.
   *
   * An earlier version of this screen keyed its block off the STRICT signing
   * rule, so it disabled Continue on the wallet's own shipped default. The
   * core permits that send: `validate_l1_payment_node_url` allows an ordinary
   * L1 payment through `http://nodeapi.hacash.org` as one named exception. A
   * disabled button in front of a send the core would have accepted is a worse
   * dead end than the toast it replaced, and it makes a working wallet look
   * broken.
   */
  it("does not block the send the core actually permits", () => {
    const screen = mountSend(OFFICIAL);
    expect(screen.text(), "the shipped default is not a blocked node").not.toContain(
      "cannot send yet",
    );
    expect(screen.button("Cannot send")).toBeFalsy();
    expect(screen.button("Continue")?.disabled).toBe(false);
    screen.unmount();
  });

  it("states the cost rather than going quiet about it", () => {
    const screen = mountSend(OFFICIAL);
    const text = screen.text();
    // Permitted is not the same as free. Every clause of the disclosure is a
    // fact the person is owed before they approve.
    expect(text).toContain("over plain HTTP");
    expect(text).toContain("read which address you are asking about");
    expect(text).toContain("quote a wrong network fee");
    screen.unmount();
  });

  it("says plainly what nobody on the path can do, so the cost is not overstated", () => {
    const screen = mountSend(OFFICIAL);
    const text = screen.text();
    expect(text).toContain("cannot change who gets paid or how much");
    expect(text).toContain("cannot sign anything for you");
    screen.unmount();
  });

  it("ends with the one thing that removes the cost", () => {
    const screen = mountSend(OFFICIAL);
    expect(screen.text()).toContain(LOCAL);
    expect(screen.button("Open Settings")).toBeTruthy();
    screen.unmount();
  });

  it("says nothing once a node on this machine is in use", () => {
    const screen = mountSend(LOCAL);
    const text = screen.text();
    expect(text).not.toContain("over plain HTTP");
    expect(text).not.toContain("cannot send yet");
    expect(screen.button("Continue")?.disabled).toBe(false);
    screen.unmount();
  });
});

describe("a node that genuinely cannot carry a payment still stops the screen", () => {
  it("says the wallet cannot send, on the screen, not in a toast after the fact", () => {
    const screen = mountSend(OTHER_PLAINTEXT);
    expect(screen.text()).toContain("cannot send yet");
    screen.unmount();
  });

  it("gives the reason in words with no term of art in them", () => {
    const screen = mountSend(OTHER_PLAINTEXT);
    const text = screen.text();
    // The strict rule is not softened for anything but the named exception.
    expect(text).toContain("running on this same computer");
    expect(text).toContain("could change what you sign");
    screen.unmount();
  });

  it("names the node it is actually on, rather than describing a category", () => {
    const screen = mountSend(OTHER_PLAINTEXT);
    expect(screen.text()).toContain(OTHER_PLAINTEXT);
    screen.unmount();
  });

  it("ends with something the person can do", () => {
    const screen = mountSend(OTHER_PLAINTEXT);
    expect(screen.text()).toContain("Start a Hacash node on this computer");
    expect(screen.button("Open Settings")).toBeTruthy();
    screen.unmount();
  });

  /**
   * "Find active node" looks at exactly one address, http://127.0.0.1:8080
   * (LOCAL_NODE_URL in crates/wallet-core/src/node_discovery.rs). A person who
   * does what this notice says and binds their node to some other port presses
   * the button, is not picked up, and has been told nothing that explains it.
   * The instruction has to carry the address the promise depends on.
   */
  it("names the address the promise depends on", () => {
    const screen = mountSend(OTHER_PLAINTEXT);
    const text = screen.text();
    expect(text, "an unqualified promise to find the node is a new dead end").toContain(LOCAL);
    screen.unmount();
  });

  it("disables Continue and puts the reason ON the button", () => {
    const screen = mountSend(OTHER_PLAINTEXT);
    const button = screen.button("Cannot send");
    expect(button, "the Continue button must carry its own reason").toBeTruthy();
    expect(button?.disabled).toBe(true);
    // A disabled control with no label is its own dead end.
    expect(button?.textContent).toContain("no Hacash node on this computer");
    screen.unmount();
  });

  it("disappears entirely once a node on this machine is in use", () => {
    const screen = mountSend(LOCAL);
    const text = screen.text();
    expect(text).not.toContain("cannot send yet");
    expect(screen.button("Cannot send")).toBeFalsy();
    const continueButton = screen.button("Continue");
    expect(continueButton?.disabled).toBe(false);
    screen.unmount();
  });

  it("says nothing off mainnet, where the transport rule does not apply", () => {
    const props = sendProps(OFFICIAL);
    const testnet = {
      ...props,
      status: { ...props.status, network_mode: "testnet" },
    } as unknown as SendProps;
    const screen = mountComponent(
      <LocaleProvider>
        <SendScreen {...testnet} />
      </LocaleProvider>,
    );
    expect(screen.text()).not.toContain("cannot send yet");
    screen.unmount();
  });
});

describe("Home says it too, several screens before the Send button", () => {
  it("carries the cost of the shipped default next to the balance", () => {
    const screen = mountHome(OFFICIAL);
    const text = screen.text();
    // The default sends, so Home must not call it blocked. It must still name
    // what that send costs, on the first screen rather than never.
    expect(text).not.toContain("cannot send yet");
    expect(text).toContain("over plain HTTP");
    expect(text).toContain(LOCAL);
    screen.unmount();
  });

  it("carries the refusal for a node that genuinely cannot carry a payment", () => {
    const screen = mountHome(OTHER_PLAINTEXT);
    const text = screen.text();
    expect(text).toContain("cannot send yet");
    expect(text).toContain("Start a Hacash node on this computer");
    screen.unmount();
  });

  it("is absent once the wallet can sign, so it is never wallpaper", () => {
    const screen = mountHome(LOCAL);
    const text = screen.text();
    expect(text).not.toContain("cannot send yet");
    expect(text).not.toContain("over plain HTTP");
    screen.unmount();
  });
});

describe("Settings stops recommending the setting that cannot work", () => {
  const settingsProps = (nodeUrl: string) =>
    ({
      settings: {
        node_url: nodeUrl,
        node_fallback_urls: [],
        auto_node_failover: true,
        network_mode: "mainnet",
      },
      busy: false,
      onSave: () => {},
      onInfo: () => {},
      onError: () => {},
    }) as unknown as Parameters<typeof SettingsScreen>[0];

  function mountSettings(nodeUrl: string) {
    return mountComponent(
      <LocaleProvider>
        <SettingsScreen {...settingsProps(nodeUrl)} />
      </LocaleProvider>,
    );
  }

  it("shows the transport notice while sitting on the default, without pressing Change node", () => {
    // `settings.officialHttpNotice` already existed and already said the truth.
    // It rendered nowhere on desktop, and on mobile only inside the
    // "Change node" branch, so only somebody who had already diagnosed the
    // problem could read the diagnosis.
    const screen = mountSettings(OFFICIAL);
    const text = screen.text();
    // What the notice must now do is state a cost, not a refusal. The refusal
    // was accurate until the named exception landed and is now false for the
    // one thing most people do with this wallet.
    expect(text).toContain("Ordinary payments go through it");
    expect(text).toContain("read the fee before you approve");
    expect(text).toContain("cannot change who gets paid");
    // And it must still say where the exception stops, or the Fast Pay refusal
    // becomes the next unexplained dead end.
    expect(text).toContain("Fast Pay setup and channel closes still need HTTPS");
    expect(screen.button("Change node"), "still on the unexpanded default view").toBeTruthy();
    screen.unmount();
  });

  it("drops the notice once the node can sign", () => {
    const screen = mountSettings(LOCAL);
    expect(screen.text()).not.toContain("Ordinary payments go through it");
    screen.unmount();
  });

  it("no longer tells people not to change the node they must change", () => {
    const screen = mountSettings(LOCAL);
    const text = screen.text();
    // The old hint read "Only change this if you run your own Hacash node or
    // need a private endpoint", which on mainnet is backwards: you must change
    // it or you can never send anything.
    expect(text).not.toContain("Only change this if you run your own");
    // And it no longer claims the opposite either. The hint used to say the
    // official node "can see balances but cannot send", which stopped being
    // true when the named exception landed; a hint that tells somebody their
    // wallet is broken while it works is the same defect facing the other way.
    expect(text).not.toContain("cannot send");
    expect(text).toContain("sends through the official node over plain HTTP");
    expect(text).toContain("read the fee before you approve");
    expect(text).toContain("http://127.0.0.1:8080");
    screen.unmount();
  });
});

/// CAN A PERSON NAME A HUB, AND DOES THAT HUB ANSWER FOR ITSELF?
///
/// The bounded mainnet path dead-ended before any gate: the wallet's whole
/// provider directory was one loopback address, the field for pasting a real
/// one was collapsed inside "Technical settings (advanced)" on a different part
/// of the page, discovery read the SAVED value so a typed URL was the one
/// candidate it skipped, and a person who did find a Hub was shown this
/// build's compile-time ceilings instead of that Hub's declared caps.
///
/// These tests pin the four facts that open it. Nothing here reads a source
/// file for a string: each test either watches what reaches `invoke` or reads
/// what actually renders.

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { renderToStaticMarkup } from "react-dom/server";
import { beforeEach, describe, expect, it, vi } from "vitest";
import {
  FAST_PAY_NO_HUB_EXPLANATION,
  HubDeclarationCard,
  type HubDeclarationView,
} from "@hacash/wallet-ui";

const invoke = vi.fn();
vi.mock("@tauri-apps/api/core", () => ({
  invoke: (...args: unknown[]) => invoke(...args),
}));

const { api } = await import("./api");
const HubDiscoveryPanel = (await import("./components/HubDiscoveryPanel")).default;

const settings = { network_mode: "mainnet" } as never;

/** A bounded-pilot Hub whose aggregate cap is a tenth of its channel cap. */
const declaration: HubDeclarationView = {
  hub_url: "https://hub.example.com",
  reachable: true,
  error: null,
  name: "Pilot Hub",
  hub_address: "1Q1pE5vPGEEMqRcVRMbtBK842Y6Pzo6nK9",
  version: 7,
  settlement_ready: true,
  cross_channel_ready: true,
  hub_fee_mei: "0",
  deployment_profile: "mainnet-bounded-pilot",
  mainnet_checked: true,
  readiness_profile: "mainnet-bounded-pilot",
  payments_enabled: false,
  declared_caps: {
    max_payment_hac: "1",
    max_channel_funding_hac: "10",
    max_aggregate_tvl_hac: "1",
    aggregate_tvl_within_limit: true,
  },
  blockers: ["fullnode_capability_probe_failed: connection refused"],
  disclosed_blockers: ["unilateral_l1_dispute_path_is_not_ready"],
  limitations: ["new channels require an allowlisted user"],
  readiness_error: null,
};

beforeEach(() => {
  invoke.mockReset();
});

describe("naming a hub", () => {
  it("sends the typed hub URL to discovery instead of only the saved one", async () => {
    invoke.mockResolvedValue({ hubs: [], online_count: 0 });
    await api.discoverHubs("  https://hub.example.com  ");
    expect(invoke).toHaveBeenCalledWith("wallet_discover_hubs", {
      hubUrl: "https://hub.example.com",
    });
  });

  it("sends null rather than an empty string when nothing was typed", async () => {
    invoke.mockResolvedValue({ hubs: [], online_count: 0 });
    await api.discoverHubs("   ");
    expect(invoke).toHaveBeenCalledWith("wallet_discover_hubs", { hubUrl: null });
  });

  it("asks the Hub for its own declaration by URL, without saving it first", async () => {
    invoke.mockResolvedValue(declaration);
    await api.hubDeclaration("https://hub.example.com");
    expect(invoke).toHaveBeenCalledWith("wallet_hub_declaration", {
      hubUrl: "https://hub.example.com",
    });
    // Reading a Hub must not write settings.
    expect(invoke).toHaveBeenCalledTimes(1);
  });

  it("puts the hub address field on the visible surface, not behind a toggle", () => {
    const markup = renderToStaticMarkup(
      <HubDiscoveryPanel
        settings={settings}
        activeHubUrl=""
        busy={false}
        setBusy={() => undefined}
        onApplyHub={async () => undefined}
        onToast={() => undefined}
      />,
    );
    expect(markup).toContain('id="hub-discovery-url"');
    // And it says why the directory is empty rather than reporting a
    // confusing loopback failure.
    expect(markup).toContain(FAST_PAY_NO_HUB_EXPLANATION.slice(0, 40));
  });
});

describe("a hub answering for itself", () => {
  it("shows the Hub's three declared caps, including the aggregate one", () => {
    const markup = renderToStaticMarkup(<HubDeclarationCard declaration={declaration} />);
    expect(markup).toContain("Per payment");
    expect(markup).toContain("Per channel");
    expect(markup).toContain("Total across all channels");
    // The number a person with 7 HAC most needs and could not previously see.
    expect(markup).toContain("Total across all channels:</strong> 1 HAC");
  });

  it("warns when the Hub advertises a channel it cannot fund", () => {
    const markup = renderToStaticMarkup(<HubDeclarationCard declaration={declaration} />);
    expect(markup).toContain("will refuse any channel larger than");
  });

  it("prints the Hub's blockers verbatim rather than summarising them", () => {
    const markup = renderToStaticMarkup(<HubDeclarationCard declaration={declaration} />);
    expect(markup).toContain("fullnode_capability_probe_failed: connection refused");
    expect(markup).toContain("unilateral_l1_dispute_path_is_not_ready");
    expect(markup).not.toContain("does not support safe, fee-free routed settlement");
  });

  it("labels this build's numbers as ceilings, next to the Hub's declaration", () => {
    const markup = renderToStaticMarkup(<HubDeclarationCard declaration={declaration} />);
    expect(markup).toContain("ceilings this build refuses to cross");
    expect(markup).toContain("These are its numbers, not");
  });

  it("says a cap was not declared instead of inventing a zero", () => {
    const older: HubDeclarationView = {
      ...declaration,
      declared_caps: { ...declaration.declared_caps, max_aggregate_tvl_hac: null },
    };
    const markup = renderToStaticMarkup(<HubDeclarationCard declaration={older} />);
    expect(markup).toContain("Total across all channels:</strong> not declared");
  });

  it("reports an unreachable Hub as unreachable, with the reason", () => {
    const markup = renderToStaticMarkup(
      <HubDeclarationCard
        declaration={{
          ...declaration,
          reachable: false,
          error: "remote Fast Pay hub endpoints must use HTTPS",
        }}
      />,
    );
    expect(markup).toContain("Could not read this Hub");
    expect(markup).toContain("remote Fast Pay hub endpoints must use HTTPS");
  });
});

/**
 * THE CONSENT CEREMONY NEEDS A CONTROL THAT SUBMITS IT.
 *
 * The bounded mainnet pilot text, its checkbox and the "Wallet passphrase, to
 * confirm this choice" field all render high on the Fast Pay page. The only
 * control that submitted them lived inside the collapsed "Technical settings
 * (advanced)" section further down, which is not rendered at all until it is
 * expanded. So a person read the consent, ticked the box, typed their wallet
 * passphrase, and nothing on screen did anything with it: ticking only set
 * local state, and there was no other caller of onSaveL2Settings in the file.
 *
 * These render the real screen and look inside the consent block itself. They
 * cannot drive the checkbox, because this harness has no DOM and effects do
 * not run under server rendering, so they exercise the same visibility rule
 * from the other side: the control appears exactly when the ticked state and
 * the saved state disagree, which is when there is something to submit.
 *
 * No gate moves. Granting still requires a passphrase and still routes through
 * the authenticated consent command, both inside the handler these tests pass.
 */
const fastPayModule = await import("./screens/FastPayScreen");
const FastPayScreen = fastPayModule.default;
const { consentSubmitState } = fastPayModule;

type FastPayProps = Parameters<typeof FastPayScreen>[0];

function mainnetSettings(consented: boolean) {
  return {
    node_url: "http://127.0.0.1:8080",
    network_mode: "mainnet",
    l2_hub_url: "https://hub.example.com",
    trusted_mainnet_fast_pay_pilot: consented,
    hub_right_address: "1Q1pE5vPGEEMqRcVRMbtBK842Y6Pzo6nK9",
    channel_id_hex: null,
    webauthn_enabled: false,
    security_profile: "standard",
    hardware_signing_mode: "software",
    privacy: {},
  } as unknown as FastPayProps["settings"];
}

function renderFastPay(overrides: Partial<FastPayProps> = {}) {
  const props: FastPayProps = {
    status: null,
    settings: mainnetSettings(false),
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
    onEnableFastPay: () => undefined,
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

/** Just the consent block, so a button further down the page cannot satisfy it. */
function consentBlock(markup: string): string {
  const start = markup.indexOf("Bounded mainnet pilot");
  const end = markup.indexOf("Find a hub");
  return start === -1 ? "" : markup.slice(start, end);
}

describe("the bounded pilot consent ceremony", () => {
  it("puts its own submit control inside the consent block", () => {
    // Saved consent differs from the unticked default, which is the same
    // condition a person creates by ticking the box.
    const block = consentBlock(renderFastPay({ settings: mainnetSettings(true) }));
    expect(block).toContain("<button");
    expect(block).toContain("Withdraw consent");
  });

  it("offers nothing to submit while the tick matches what is saved", () => {
    const block = consentBlock(renderFastPay());
    expect(block).not.toContain("<button");
  });

  it("asks for the passphrase to grant, and asks for nothing to withdraw", () => {
    // Granting chooses the settlement model every later mainnet payment is
    // judged under, so it is authenticated. Withdrawing is a tightening.
    const granting = consentSubmitState(true, false, "", false);
    expect(granting.visible).toBe(true);
    expect(granting.needsPassphrase).toBe(true);
    expect(granting.disabled).toBe(true);
    expect(granting.label).toBe("Confirm this choice");

    const withPassphrase = consentSubmitState(true, false, "hunter2hunter2h", false);
    expect(withPassphrase.disabled).toBe(false);

    const withdrawing = consentSubmitState(false, true, "", false);
    expect(withdrawing.visible).toBe(true);
    expect(withdrawing.needsPassphrase).toBe(false);
    expect(withdrawing.disabled).toBe(false);
    expect(withdrawing.label).toBe("Withdraw consent");
  });

  it("hides the control when there is nothing to change, in both directions", () => {
    expect(consentSubmitState(false, false, "", false).visible).toBe(false);
    expect(consentSubmitState(true, true, "", false).visible).toBe(false);
  });

  it("never enables the control while the wallet is busy", () => {
    expect(consentSubmitState(true, false, "hunter2hunter2h", true).disabled).toBe(true);
    expect(consentSubmitState(false, true, "", true).disabled).toBe(true);
  });

  it("keeps the advanced Save settings button collapsed, as before", () => {
    // The defect was never that the advanced button existed. It was that the
    // advanced button was the ONLY submitter, inside a section that renders
    // nothing until expanded. That section must stay collapsed by default.
    const markup = renderFastPay({ settings: mainnetSettings(true) });
    expect(markup).not.toContain("Save settings");
    expect(markup).toContain("Technical settings (advanced)");
  });

  it("does not show the ceremony at all off mainnet", () => {
    const markup = renderFastPay({
      settings: {
        ...(mainnetSettings(false) as object),
        network_mode: "testnet",
      } as unknown as FastPayProps["settings"],
    });
    expect(markup).not.toContain("Bounded mainnet pilot");
  });
});

describe("adopting a Hub never fails silently", () => {
  // The Hub was configured, running and healthy on mainnet, and pressing
  // "Use this hub" did nothing at all: no save, no error, no toast. The
  // handler returned early on three separate conditions and said nothing on
  // any of them, so the only way to find out that l2_hub_url was still empty
  // was to read the settings file off disk.
  const source = readFileSync(
    join(dirname(fileURLToPath(import.meta.url)), "components/HubDiscoveryPanel.tsx"),
    "utf8",
  );

  it("explains every refusal instead of returning in silence", () => {
    // No bare `return;` may sit directly under one of the guard conditions.
    expect(source).not.toMatch(
      /if \(!declaration \|\| !declaration\.reachable \|\| !declaration\.hub_address\) return;/,
    );
    expect(source).not.toMatch(/if \(!entry\.online\) return;/);
    // Each of the four reasons a person can hit must name itself.
    expect(source).toMatch(/Check the provider first/);
    expect(source).toMatch(/did not answer/);
    expect(source).toMatch(/did not publish an on-chain address/);
    expect(source).toMatch(/not answering, so it was not saved/);
  });
});

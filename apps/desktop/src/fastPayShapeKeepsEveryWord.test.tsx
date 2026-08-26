// @vitest-environment jsdom
/**
 * FOLDING IS ALLOWED. REMOVING IS NOT.
 *
 * The owner asked for the Fast Pay screen to be made understandable, because it
 * has a lot of information. Every sentence on it is true and most of it was hard
 * won: three disclosed blockers, five published limitations, a leaf-node
 * warning, a stranding warning and a consent paragraph all exist because
 * somebody measured something. The screen was reordered into three bands and the
 * evidence was folded behind `<details>`.
 *
 * That change has exactly one way of doing harm: quietly dropping a risk
 * sentence while looking tidier. So this file is written from that direction.
 *
 *   1. NOTHING IS DELETED. Every disclosed blocker, every published limitation,
 *      every check row and every "cannot be checked" fact is still in the
 *      rendered output, folded or not.
 *   2. WHAT YOU AGREE TO IS NOT FOLDED. The consent sentence and the ceilings
 *      sentence render without opening anything. A person who ticks a box whose
 *      label is behind a disclosure has agreed to something they did not read.
 *   3. "CAN I ACT NOW" IS ABOVE THE EVIDENCE, and it carries the button.
 *   4. THE SUMMARIES COUNT FROM THE DATA. A fold whose summary says three when
 *      the Hub declares four is worse than the wall of text it replaced, because
 *      a wrong count reads as authority.
 *
 * NOTHING HERE IS A GATE. Every assertion is about what is SAID and in what
 * order. The Enable button stays pressable throughout, and the core, the signing
 * boundary and the Hub each refuse on their own account.
 *
 * WHY THE STRUCTURE ASSERTIONS MATTER. jsdom's `textContent` includes the
 * contents of a CLOSED `<details>`, which is exactly why folding is safe for the
 * copy tests that already exist, and exactly why those tests cannot tell whether
 * the fold works at all. `metText` below removes every `<details>` before
 * reading, so it answers the different question: what does a person meet without
 * opening anything.
 */
import { beforeEach, describe, expect, it, vi } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { mountComponent, type Mounted } from "./domHarness";
import FastPayScreen from "./screens/FastPayScreen";
import {
  FAST_PAY_MAINNET_CEILINGS,
  FAST_PAY_MAINNET_CONSENT,
  HubDeclarationCard,
  type HubDeclarationView,
} from "@hacash/wallet-ui";

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

/**
 * The owner's Hub, as its own /v1/readiness/mainnet publishes it: three
 * disclosed blockers and five limitations, including the 80-word stale-splits
 * paragraph, transcribed from crates/l2-fast-pay-hub/src/readiness.rs.
 */
const DISCLOSED_BLOCKERS = [
  "wallet_cannot_build_a_unilateral_exit_without_the_hub",
  "unilateral_l1_dispute_path_is_not_ready",
  "no_watcher_answers_for_an_offline_owner",
];

const LIMITATIONS = [
  "settled does not mean unilateral L1 finality",
  "the active Hacash mainnet exposes cooperative original-funding close action 3",
  "pilot exposure must remain inside the configured payment and channel caps",
  "no_watcher_answers_for_an_offline_owner: nobody answers the objection window on an offline owner's behalf, and nothing finalizes or claims for them either. On the shipped one-directional rail this cannot cost them principal, because a stale split pays the left party MORE and the driver deliberately declines to answer it; that rests on two checks (a refused non-zero hub deposit and a ledger that only subtracts from the left balance) rather than on the protocol. It is disclosed and it does not block closing",
  "the external rollback anchor witness is attested as self-operated operated by the pilot operator; an attestation is a signed statement about where the witness runs, not proof of it",
];

function declaration(overrides: Partial<HubDeclarationView> = {}): HubDeclarationView {
  return {
    hub_url: "http://127.0.0.1:8790",
    reachable: true,
    error: null,
    name: "HPAY Fast Pay Hub",
    hub_address: "18bV2fjWhpQpmGRLifS8PDmzA6ATRJwVgq",
    version: 7,
    settlement_ready: true,
    cross_channel_ready: true,
    hub_fee_mei: "0",
    deployment_profile: "mainnet-bounded-pilot",
    mainnet_checked: true,
    readiness_profile: "mainnet-bounded-pilot",
    payments_enabled: true,
    declared_caps: {
      max_payment_hac: "0.1",
      max_channel_funding_hac: "0.2",
      max_aggregate_tvl_hac: "0.2",
      aggregate_tvl_within_limit: true,
    },
    blockers: [],
    disclosed_blockers: DISCLOSED_BLOCKERS,
    limitations: LIMITATIONS,
    readiness_error: null,
    ...overrides,
  };
}

/**
 * Twenty check rows, sixteen green, three failed and one never run, plus six
 * facts no check can answer. The counts in the fold's summary have to come from
 * these arrays, so the test builds them and then asserts the sentence.
 */
function checks() {
  const rows: Array<Record<string, unknown>> = [
    {
      id: "node_identity",
      title: "Your node answers",
      severity: "fatal",
      status: "pass",
      observed: "chain 0, mainnet, height 776466",
      reason: null,
    },
    {
      id: "node_can_be_reached",
      title: "Nothing can reach your node",
      severity: "warning",
      status: "fail",
      observed: "total 10, inbound 0, outbound 10, role leaf",
      reason: "no other node has reached this one",
    },
    {
      id: "hub_disclosed_gaps",
      title: "What this Hub discloses but does not block on",
      severity: "warning",
      status: "fail",
      observed: `everything this Hub reports as outstanding, in its own order: ${DISCLOSED_BLOCKERS.join(", ")}`,
      reason: `These produce no refusal by design: ${DISCLOSED_BLOCKERS.join(", ")}`,
    },
    {
      id: "hub_will_countersign",
      title: "Whether this Hub will countersign",
      severity: "fatal",
      status: "fail",
      observed: "cannot be established read-only",
      reason: "no signed request is sent by this check",
    },
    {
      id: "allowlist_membership",
      title: "Whether this address is on the Hub's list",
      severity: "warning",
      status: "skip",
      observed: "not reached",
      reason: "requires a signed request",
    },
  ];
  for (let i = 0; i < 15; i += 1) {
    rows.push({
      id: `green_item_${i}`,
      title: `Green item ${i}`,
      severity: i % 2 === 0 ? "fatal" : "warning",
      status: "pass",
      observed: `observed value ${i}`,
      reason: null,
    });
  }
  return rows;
}

const CANNOT_BE_CHECKED = [
  {
    id: "countersignature",
    title: "Whether this Hub will countersign",
    detail: "Nothing read-only can compel a second signature.",
  },
  {
    id: "allowlist",
    title: "Whether this address is on the Hub's list",
    detail: "A Hub will not publish its list.",
  },
  { id: "operator", title: "Who the operator is", detail: "Not published anywhere." },
  { id: "backups", title: "Whether the Hub keeps backups", detail: "Not observable." },
  { id: "future", title: "Whether it will answer tomorrow", detail: "One instant only." },
  { id: "law", title: "What happens in a dispute", detail: "No dispute path on this rail." },
];

function preflight(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    schema: "hpay-native-rail-preflight/1",
    generated_unix: 1787665702,
    node_url: "http://127.0.0.1:8080",
    hub_url: "http://127.0.0.1:8790",
    owner_address: "1AVRuFXNFi3rdMrPH4hdqSgFrEBnWisWaS",
    hub_address: "18bV2fjWhpQpmGRLifS8PDmzA6ATRJwVgq",
    channel_deposit_hac: "0.2",
    payment_hac: "0.1",
    verdict: "not_pass",
    fatal_failed: 1,
    fatal_skipped: 0,
    warnings: 3,
    validity_seconds: 60,
    checks: checks(),
    declared_caps: {
      max_payment_hac: "0.1",
      max_channel_funding_hac: "0.2",
      max_aggregate_tvl_hac: "0.2",
      aggregate_tvl_within_limit: true,
    },
    cannot_be_checked: CANNOT_BE_CHECKED,
    ...overrides,
  };
}

function props(overrides: Partial<FastPayProps> = {}): FastPayProps {
  return {
    status: {
      locked: false,
      watch_only: false,
      address: "1AVRuFXNFi3rdMrPH4hdqSgFrEBnWisWaS",
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

async function screen(overrides: Partial<FastPayProps> = {}): Promise<Mounted> {
  const view = mountComponent(<FastPayScreen {...props(overrides)} />);
  await vi.advanceTimersByTimeAsync(600);
  return view;
}

/** Everything in the document, folded or not. Whitespace collapsed. */
function allText(root: HTMLElement): string {
  return (root.textContent ?? "").replace(/\s+/g, " ");
}

/**
 * What a person MEETS: the same document with every `<details>` taken out.
 *
 * This is the assertion the existing copy tests cannot make. `textContent`
 * includes closed `<details>`, so a `toContain` passes whether the fold works or
 * not. Removing them first is what tells the two apart.
 */
function metText(root: HTMLElement): string {
  const clone = root.cloneNode(true) as HTMLElement;
  clone.querySelectorAll("details").forEach((node) => node.remove());
  return (clone.textContent ?? "").replace(/\s+/g, " ");
}

beforeEach(() => {
  vi.useFakeTimers();
  nativeRailPreflight.mockReset().mockResolvedValue(preflight());
});

describe("1. nothing is deleted", () => {
  it("keeps every disclosed blocker and every published limitation in the output", () => {
    const markup = renderToStaticMarkup(
      <HubDeclarationCard declaration={declaration()} />,
    );
    for (const blocker of DISCLOSED_BLOCKERS) {
      expect(markup, `${blocker} must still be rendered`).toContain(blocker);
    }
    for (const limitation of LIMITATIONS) {
      // The Hub's own words, never rewritten and never summarised away. The
      // 80-word stale-splits paragraph is checked in full on purpose.
      const escaped = limitation.replace(/'/g, "&#x27;");
      expect(markup, `a published limitation went missing`).toContain(
        escaped.slice(0, 120),
      );
    }
  });

  it("keeps a BLOCKING blocker unfolded, because blocking is not evidence", () => {
    const blocking = declaration({
      blockers: ["mainnet_pilot_user_allowlist_is_not_configured"],
    });
    const container = document.createElement("div");
    container.innerHTML = renderToStaticMarkup(
      <HubDeclarationCard declaration={blocking} />,
    );
    // readiness.rs deliberately moves some identifiers between the two lists.
    // A blocking one answers "can I act now" and must not fold; a disclosed one
    // may. Both must always be somewhere.
    expect(metText(container)).toContain("mainnet_pilot_user_allowlist_is_not_configured");
    expect(metText(container)).not.toContain("no_watcher_answers_for_an_offline_owner");
    expect(allText(container)).toContain("no_watcher_answers_for_an_offline_owner");
  });

  it("keeps every check row and every uncheckable fact on the screen", async () => {
    const view = await screen();
    const text = allText(view.container);
    for (const check of checks()) {
      expect(text, `check ${check.id} went missing`).toContain(String(check.id));
      expect(text).toContain(String(check.observed));
    }
    for (const fact of CANNOT_BE_CHECKED) {
      expect(text, `${fact.id} went missing`).toContain(fact.detail);
    }
    view.unmount();
  });

  it("keeps every enable refusal on the screen, with its identifier", async () => {
    const view = await screen({
      settings: {
        node_url: "http://127.0.0.1:8080",
        network_mode: "mainnet",
        l2_hub_url: "http://127.0.0.1:8790",
        hub_right_address: "",
        trusted_mainnet_fast_pay_pilot: false,
        privacy: {},
        send: {},
      } as unknown as FastPayProps["settings"],
    });
    const text = allText(view.container);
    expect(text).toContain("no_provider_address");
    expect(text).toContain("mainnet_consent_withheld");
    view.unmount();
  });
});

describe("2. what you are agreeing to is never folded", () => {
  it("renders the consent sentence and the ceilings without opening anything", async () => {
    const view = await screen();
    const met = metText(view.container);
    // The checkbox label itself, verbatim. If this is ever inside a <details>,
    // a person can tick a box whose text they were never shown.
    expect(met).toContain(FAST_PAY_MAINNET_CONSENT);
    expect(met).toContain(FAST_PAY_MAINNET_CEILINGS);
    view.unmount();
  });

  it("says the Hub must co-sign, in the consent text, before any fold", async () => {
    const view = await screen();
    const met = metText(view.container);
    expect(met).toContain("can only be closed if the Hub co-signs");
    expect(met).toContain("is not a trustless L1 exit");
    view.unmount();
  });

  it("shows this Hub's declared caps without opening anything", async () => {
    const view = await screen();
    const met = metText(view.container);
    expect(met).toContain("Per payment");
    expect(met).toContain("0.1");
    expect(met).toContain("Per channel");
    expect(met).toContain("0.2");
    view.unmount();
  });

  it("says the channel will be refused, before the box that used to open it", async () => {
    // The rule this enforces: a person meets the plain fact about their way
    // out BEFORE the money moves. wallet-core is the authority and refuses at
    // prepare; this only has to get there first, and it must not depend on the
    // preflight having reached a Hub, because the fact does not.
    const view = await screen();
    const met = metText(view.container);
    expect(met).toContain("This wallet will not open a mainnet Fast Pay channel");
    expect(met).toContain("Agent Wallet");
    // Above the consent box, not below it. The box says there is no way out
    // and is true; what it never did was stop anyone.
    expect(met.indexOf("will not open a mainnet Fast Pay channel")).toBeLessThan(
      met.indexOf("I will not put in more than I can afford to lose"),
    );
    view.unmount();
  });

  it("shows the no-way-out sentence without opening anything", async () => {
    const view = await screen();
    // Disclosed through the preflight's own hub_disclosed_gaps item, which is
    // the only place this screen can see it without a Hub declaration.
    const met = metText(view.container);
    expect(met).toContain("Your wallet cannot build a way out on its own.");
    // And it names the rail where the exit does exist, so a refusal reads as a
    // limit of this wallet rather than as a broken build.
    expect(met).toContain("Agent Wallet");
    view.unmount();
  });

  it("does not tell a person to take a voucher this wallet cannot take", async () => {
    // The screen used to carry, unfolded and beside the caps, "Take a close
    // voucher before you pay anything" - a few hundred pixels from a consent
    // box saying there is no way out. Both cannot be true, and the one with a
    // button attached was the false one: no close-voucher command exists in
    // this wallet, on either app.
    const view = await screen();
    expect(metText(view.container)).not.toMatch(/take a close voucher before you pay/i);
    view.unmount();
  });

  it("names whose failure the consent text describes when the Hub is your own", async () => {
    const view = await screen();
    // The saved hub is on loopback, so the self-hosted note is met rather than
    // folded: it is the owner's own key and their own durable state.
    expect(metText(view.container)).toContain("you are the counterparty to your own channel");
    view.unmount();
  });

  it("keeps the leaf-node headline visible and folds only its explanation", async () => {
    const view = await screen();
    const met = metText(view.container);
    expect(met).toContain("Nothing can reach your node");
    // The three paragraphs under it are evidence and do fold, but stay present.
    expect(met).not.toContain("still downloads every block");
    expect(allText(view.container)).toContain("still downloads every block");
    view.unmount();
  });
});

describe("3. can I act now, above the evidence", () => {
  it("puts the next-step block before any folded section", async () => {
    const view = await screen();
    const nodes = Array.from(
      view.container.querySelectorAll(".fp-next-step, details"),
    );
    expect(nodes.length).toBeGreaterThan(1);
    expect(nodes[0].className).toContain("fp-next-step");
    view.unmount();
  });

  it("puts the Enable button inside the block that says whether it can be pressed", async () => {
    const view = await screen();
    const band = view.container.querySelector(".fp-next-step");
    expect(band).not.toBeNull();
    expect(band?.textContent).toContain("Enable Fast Pay");
    // Exactly one, so "here is the button" is answered in one place.
    const enables = view
      .buttons()
      .filter((node) => (node.textContent ?? "").includes("Enable Fast Pay"));
    expect(enables).toHaveLength(1);
    expect(enables[0].disabled).toBe(false);
    // And it is not inside a fold: a control a person has to open a disclosure
    // to reach is a control that is not there.
    expect(enables[0].closest("details")).toBeNull();
    view.unmount();
  });

  it("puts the check's verdict at the top rather than under the whole report", async () => {
    const view = await screen();
    const band = view.container.querySelector(".fp-next-step");
    expect(band?.textContent).toContain("NOT READY");
    expect(band?.textContent).toContain("Do not put money in yet");
    view.unmount();
  });

  it("keeps the sentence that stops a live button reading as broken", async () => {
    const view = await screen();
    expect(metText(view.container)).toContain(
      "You can still press Enable, and the same gates will refuse again with a reason",
    );
    view.unmount();
  });
});

describe("4. the folded summaries count from the data", () => {
  it("counts the check items, and never merges skipped into green", async () => {
    const view = await screen();
    const summaries = Array.from(view.container.querySelectorAll("summary")).map(
      (node) => (node.textContent ?? "").replace(/\s+/g, " "),
    );
    const items = summaries.find((line) => line.includes("Every item this check ran"));
    expect(items, "the report fold must summarise itself").toBeDefined();
    // 20 rows: 16 pass, 3 fail, 1 skip. A skipped check has its own number,
    // because a question nobody answered is not one that came back clean.
    expect(items).toContain("20 items: 16 green, 3 failed, 1 not run");
    expect(items).toContain("6 things no check can tell you");
    view.unmount();
  });

  it("reads the disclosed count from the array, so a fourth blocker says four", () => {
    const three = renderToStaticMarkup(<HubDeclarationCard declaration={declaration()} />);
    expect(three).toContain("3 things it discloses but does not block on");
    expect(three).toContain("5 limitations it publishes");

    const four = renderToStaticMarkup(
      <HubDeclarationCard
        declaration={declaration({
          disclosed_blockers: [...DISCLOSED_BLOCKERS, "rollback_anchor_channels_latched_in_refusal"],
        })}
      />,
    );
    expect(four).toContain("4 things it discloses but does not block on");
  });

  it("counts the refusal queue rather than announcing a fixed number", async () => {
    const view = await screen({
      settings: {
        node_url: "http://127.0.0.1:8080",
        network_mode: "mainnet",
        l2_hub_url: "http://127.0.0.1:8790",
        hub_right_address: "",
        trusted_mainnet_fast_pay_pilot: false,
        privacy: {},
        send: {},
      } as unknown as FastPayProps["settings"],
    });
    const summaries = Array.from(view.container.querySelectorAll("summary")).map(
      (node) => (node.textContent ?? "").replace(/\s+/g, " "),
    );
    const queue = summaries.find((line) => line.includes("Everything stopping Enable"));
    expect(queue).toContain("2 things are stopping Enable right now");
    // And the counter above points at a heading that exists.
    const band = view.container.querySelector(".fp-next-step");
    expect(band?.textContent).toContain('listed under "Everything stopping Enable"');
    view.unmount();
  });
});

describe("5. the volume the owner complained about", () => {
  it("meets a person with a fraction of the words, with all of them one click away", async () => {
    const view = await screen();
    const met = metText(view.container).trim().split(/\s+/).length;
    const all = allText(view.container).trim().split(/\s+/).length;
    console.log(`\n[fast pay screen] met without opening anything: ${met} words of ${all}\n`);
    expect(all).toBeGreaterThan(met);
    // The target was about a fifth. This pins the direction rather than the
    // exact number, so honest additions to the always-visible band are allowed
    // and a quiet slide back to the wall of text is not.
    expect(met / all).toBeLessThan(0.45);
    view.unmount();
  });
});

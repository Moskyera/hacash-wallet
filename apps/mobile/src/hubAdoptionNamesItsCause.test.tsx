// @vitest-environment jsdom
/**
 * ADOPTING A PROVIDER WITH NO ADDRESS REPORTED SUCCESS AND LEFT THE WRONG PAIR.
 *
 * `probe_hub_entry` returns `online: true` with `hub_address: None` for a
 * healthy zero-fee Hub that publishes no address. The phone's list button was
 * gated on `entry.online` alone, so such a Hub could be adopted, and
 * `handleApplyHub` then wrote:
 *
 *     l2_hub_url:        entry.hub_url                                  // new
 *     hub_right_address: entry.hub_address ?? settings.hub_right_address // OLD
 *
 * The toast said "Using <name>", the row flipped to "In use", and the wallet was
 * left pointing at one provider's URL while still bound to a different
 * provider's on-chain address. A channel binds to an exact counterparty, so that
 * pair is not incomplete, it is wrong.
 *
 * The desktop copy of this panel was fixed for exactly this. The phone was not.
 *
 * NO GATE MOVES HERE. Every case below was already unusable as a provider. What
 * changes is that the refusal has a cause a person can read, and that the
 * mismatched pair can no longer be written at all.
 */
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { click, mountComponent, settle } from "./domHarness";
import HubDiscoveryPanel from "./components/HubDiscoveryPanel";

const discoverHubs = vi.fn();
const hubDeclaration = vi.fn();

vi.mock("./api", () => ({
  api: {
    discoverHubs: (...a: unknown[]) => discoverHubs(...a),
    hubDeclaration: (...a: unknown[]) => hubDeclaration(...a),
  },
}));

const ADDRESSLESS = {
  id: "custom",
  name: "Addressless Hub",
  hub_url: "http://127.0.0.1:9999",
  online: true,
  hub_address: null,
  hub_fee_mei: "0",
  error: null,
};

const WITH_ADDRESS = {
  ...ADDRESSLESS,
  name: "Proper Hub",
  hub_address: "1LFPqztfKhamVuzzV5WV6pHfykktGD5pMW",
};

type Props = Parameters<typeof HubDiscoveryPanel>[0];

function props(overrides: Partial<Props> = {}): Props {
  return {
    settings: {
      node_url: "http://127.0.0.1:8080",
      network_mode: "mainnet",
      l2_hub_url: "http://127.0.0.1:8790",
      hub_right_address: "18bV2fjWhpQpmGRLifS8PDmzA6ATRJwVgq",
    },
    activeHubUrl: "http://127.0.0.1:8790",
    busy: false,
    setBusy: () => undefined,
    onApplyHub: async () => undefined,
    onToast: () => undefined,
    ...overrides,
  } as unknown as Props;
}

beforeEach(() => {
  discoverHubs.mockReset();
  hubDeclaration.mockReset();
});

/** Scan, so the result list with its adopt button is on screen. */
async function scanFor(entry: unknown, overrides: Partial<Props> = {}) {
  discoverHubs.mockResolvedValue({ online_count: 1, hubs: [entry] });
  const view = mountComponent(<HubDiscoveryPanel {...props(overrides)} />);
  await settle();
  const scan = view
    .buttons()
    .find((b) => /scan/i.test(b.textContent ?? ""));
  expect(scan, "the scan control must exist").toBeDefined();
  click(scan!);
  await settle();
  return view;
}

/**
 * The handler's own text.
 *
 * Read from disk rather than through `import.meta.url`: this file runs under
 * jsdom, where `import.meta.url` is an http URL and `fileURLToPath` refuses it.
 */
function mobileAppSource(): string {
  return readFileSync(resolve(process.cwd(), "src/MobileApp.tsx"), "utf8");
}

function adoptButton(view: ReturnType<typeof mountComponent>) {
  return view.buttons().find((b) => /use this hub/i.test(b.textContent ?? ""));
}

describe("adopting a scanned provider", () => {
  it("refuses a Hub that publishes no address, and names why", async () => {
    const onToast = vi.fn();
    const onApplyHub = vi.fn(async () => undefined);
    const view = await scanFor(ADDRESSLESS, { onToast, onApplyHub });

    const use = adoptButton(view);
    // Not removed and not greyed. The control is offered and it refuses aloud.
    expect(use, "the adopt control must still be offered").toBeDefined();
    click(use!);
    await settle();

    expect(onApplyHub, "nothing may be saved").not.toHaveBeenCalled();
    const said = onToast.mock.calls.map((c) => String(c[0])).join(" ");
    expect(said).toContain("no on-chain address");
    expect(said).toContain("Addressless Hub");
    expect(onToast.mock.calls.some((c) => c[1] === "error")).toBe(true);
    expect(said, "it must not report success").not.toContain("Using Addressless Hub");
    view.unmount();
  });

  it("still adopts a Hub that does publish an address", async () => {
    // The refusal has to be about the missing address and nothing else.
    const onApplyHub = vi.fn(async () => undefined);
    const view = await scanFor(WITH_ADDRESS, { onApplyHub });
    click(adoptButton(view)!);
    await settle();
    expect(onApplyHub).toHaveBeenCalledTimes(1);
    view.unmount();
  });

  it("never keeps the previous provider's address beside a new provider's URL", () => {
    // Read from the handler itself: a component test cannot observe a settings
    // field that the fix stops writing at all.
    const text = mobileAppSource();
    expect(text).not.toContain(
      "hub_right_address: entry.hub_address ?? session.settings.hub_right_address",
    );
    expect(text).toContain("hub_right_address: entry.hub_address");
  });

  it("says why nothing happened when the wallet settings are not loaded", () => {
    // This was `if (!session.settings || !entry.online) return;` before
    // `setBusy`, so no toast, no spinner, no error: a press indistinguishable
    // from a dead button.
    const text = mobileAppSource();
    expect(text).not.toContain("if (!session.settings || !entry.online) return;");
    expect(text).toContain("are not loaded yet");
    expect(text).toContain("is not answering, so it was not saved");
  });
});

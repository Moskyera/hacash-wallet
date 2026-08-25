// @vitest-environment jsdom
/**
 * CAN A PERSON ACTUALLY PRESS THE CONTROL THAT ANSWERS "WHAT DOES MY HUB ALLOW"?
 *
 * "Check this hub" is the only control in the wallet that reads the configured
 * Hub's own /v1/health and /v1/readiness/mainnet and prints its declared caps
 * and blockers verbatim. On the Fast Pay screen it was greyed out on arrival
 * every single time, with a hub saved, for a reason nobody could see:
 *
 *   HubDiscoveryPanel:  const [draftUrl, setDraftUrl] = useState(activeHubUrl ?? "")
 *   FastPayScreen:      const [hubUrl, setHubUrl] = useState("")
 *                       useEffect(() => { setHubUrl(settings.l2_hub_url ?? "") }, [...])
 *
 * The parent's effect runs AFTER the child has mounted, so the child's
 * `useState` initializer captured the empty string, and a `useState` initializer
 * runs once. Nothing resynced it. The field rendered empty whatever was saved,
 * `disabled={... || !draftUrl.trim()}` held, and "Scan for hubs" passed the same
 * empty string to `discoverHubs`, skipping the saved hub - the exact defect this
 * panel's own doc comment claims to have fixed.
 *
 * These tests need a real mount, effects and a rerender, because the defect IS
 * the ordering. `renderToStaticMarkup` performs a single mount with final props,
 * which is the one ordering the app never has, so the suite could not see this.
 */
import { beforeEach, describe, expect, it, vi } from "vitest";
import { mountComponent, typeInto } from "../domHarness";
import HubDiscoveryPanel from "./HubDiscoveryPanel";
import type { WalletSettings } from "../api";

const discoverHubs = vi.fn();
const hubDeclaration = vi.fn();

vi.mock("../api", () => ({
  api: {
    discoverHubs: (...args: unknown[]) => discoverHubs(...args),
    hubDeclaration: (...args: unknown[]) => hubDeclaration(...args),
  },
}));

const SAVED_HUB = "http://127.0.0.1:8790";

const settings = {
  network_mode: "mainnet",
  l2_hub_url: SAVED_HUB,
  hub_right_address: "18bV2fjWhpQpmGRLifS8PDmzA6ATRJwVgq",
} as unknown as WalletSettings;

function panel(activeHubUrl: string, onApplyHub = vi.fn(), onToast = vi.fn()) {
  return (
    <HubDiscoveryPanel
      settings={settings}
      activeHubUrl={activeHubUrl}
      busy={false}
      setBusy={() => {}}
      onApplyHub={onApplyHub}
      onToast={onToast}
    />
  );
}

beforeEach(() => {
  discoverHubs.mockReset().mockResolvedValue({ online_count: 0, hubs: [] });
  hubDeclaration.mockReset();
});

describe('"Check this hub" is reachable when a hub is saved', () => {
  it("fills the hub field when the saved URL arrives after mount", () => {
    // The real ordering: the parent mounts this child before its own settings
    // effect has run, so `activeHubUrl` is "" at mount and the saved URL only
    // arrives on a later render.
    const view = mountComponent(panel(""));
    expect(view.input("#hub-discovery-url")?.value).toBe("");

    view.rerender(panel(SAVED_HUB));
    expect(view.input("#hub-discovery-url")?.value).toBe(SAVED_HUB);
    view.unmount();
  });

  it("un-greys the check button once the saved URL arrives", () => {
    const view = mountComponent(panel(""));
    view.rerender(panel(SAVED_HUB));
    const check = view.button("Check this hub");
    expect(check).toBeDefined();
    expect(check?.disabled).toBe(false);
    view.unmount();
  });

  it("scans the saved hub, not only the loopback preset", async () => {
    const view = mountComponent(panel(""));
    view.rerender(panel(SAVED_HUB));
    const scan = view.button("Scan for hubs");
    scan?.click();
    await Promise.resolve();
    // Passing "" here is what made discovery skip the one hub the person had
    // actually configured.
    expect(discoverHubs).toHaveBeenCalledWith(SAVED_HUB);
    view.unmount();
  });

  it("keeps what the person typed instead of overwriting it from settings", () => {
    // The sync must not fight the keyboard. Once somebody has typed, later
    // arrivals of `activeHubUrl` must not clobber the edit in progress.
    const view = mountComponent(panel(SAVED_HUB));
    const input = view.input("#hub-discovery-url");
    expect(input).not.toBeNull();
    typeInto(input!, "https://hub.example.com");
    expect(view.input("#hub-discovery-url")?.value).toBe("https://hub.example.com");

    view.rerender(panel(SAVED_HUB));
    expect(view.input("#hub-discovery-url")?.value).toBe("https://hub.example.com");
    view.unmount();
  });

  it("never greys the check button without a reason a person can read", () => {
    // This repository has shipped the greyed version before. If the field is
    // empty the button stays pressable and says what is missing.
    const onToast = vi.fn();
    const view = mountComponent(panel("", vi.fn(), onToast));
    const check = view.button("Check this hub");
    expect(check?.disabled).toBe(false);
    check?.click();
    expect(onToast).toHaveBeenCalledWith(
      expect.stringContaining("hub address"),
      "error",
    );
    view.unmount();
  });
});

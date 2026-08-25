// @vitest-environment jsdom
/**
 * A TAB THAT IS NOT A TAB, AND LOCKS THE WALLET.
 *
 * "Agent" is drawn as the fourth of five equal items in the bottom navigation,
 * beside Home, Send, Receive and More, with the same icon-over-label shape. It
 * reads as a view switch. The other four call `onChange` and swap a tab; this
 * one calls `openAgentCompanion`, which unmounts the Personal UI and then does
 * `await api.lock()` before creating the companion webview.
 *
 * So tapping what looks like a tab locked the wallet and forced a passphrase
 * re-entry to get back, with no confirmation and no warning anywhere on the
 * control. It is also not the Agent Wallet: mobile has no agent-wallet-admin
 * feature, so the destination is an approval companion that is useless without
 * an already-paired desktop.
 *
 * The control is not removed and not greyed. It asks first, and it says what it
 * is about to do.
 */
import { describe, expect, it, vi } from "vitest";
import { mountComponent, click } from "../domHarness";
import { LocaleProvider } from "../locale";
import BottomNav from "./BottomNav";

type Props = Parameters<typeof BottomNav>[0];

function nav(overrides: Partial<Props> = {}) {
  return (
    <LocaleProvider>
      <BottomNav
        {...({
          active: "home",
          onChange: () => undefined,
          watchOnly: false,
          ...overrides,
        } as Props)}
      />
    </LocaleProvider>
  );
}

function text(view: ReturnType<typeof mountComponent>): string {
  return (view.container.textContent ?? "").replace(/\s+/g, " ");
}

describe("the Agent tab asks before it locks the wallet", () => {
  it("does not lock on the first tap", () => {
    const onOpenAgent = vi.fn();
    const view = mountComponent(nav({ onOpenAgent }));
    const agent = view.buttons().find((b) => (b.textContent ?? "").includes("Agent"));
    expect(agent).toBeDefined();
    click(agent!);
    expect(
      onOpenAgent,
      "the first tap must not reach the handler that locks the wallet",
    ).not.toHaveBeenCalled();
    view.unmount();
  });

  it("says the wallet will lock, in words, before it does", () => {
    const view = mountComponent(nav({ onOpenAgent: vi.fn() }));
    click(view.buttons().find((b) => (b.textContent ?? "").includes("Agent"))!);
    const shown = text(view).toLowerCase();
    expect(shown).toContain("lock");
    expect(shown).toContain("passphrase");
    view.unmount();
  });

  it("goes through on the second, explicit press", () => {
    const onOpenAgent = vi.fn();
    const view = mountComponent(nav({ onOpenAgent }));
    click(view.buttons().find((b) => (b.textContent ?? "").includes("Agent"))!);
    const confirm = view
      .buttons()
      .find((b) => (b.textContent ?? "").toLowerCase().includes("lock and open"));
    expect(confirm).toBeDefined();
    click(confirm!);
    expect(onOpenAgent).toHaveBeenCalledTimes(1);
    view.unmount();
  });

  it("can be backed out of", () => {
    const onOpenAgent = vi.fn();
    const view = mountComponent(nav({ onOpenAgent }));
    click(view.buttons().find((b) => (b.textContent ?? "").includes("Agent"))!);
    const cancel = view
      .buttons()
      .find((b) => (b.textContent ?? "").toLowerCase().includes("stay"));
    expect(cancel).toBeDefined();
    click(cancel!);
    expect(onOpenAgent).not.toHaveBeenCalled();
    expect(text(view).toLowerCase()).not.toContain("passphrase");
    view.unmount();
  });

  it("leaves the other four tabs switching on one tap", () => {
    const onChange = vi.fn();
    const view = mountComponent(nav({ onChange, onOpenAgent: vi.fn() }));
    for (const label of ["Home", "Receive"]) {
      const tab = view.buttons().find((b) => (b.textContent ?? "").includes(label));
      if (tab) click(tab);
    }
    expect(onChange.mock.calls.length).toBeGreaterThan(0);
    view.unmount();
  });

  it("says the companion is useless without a paired desktop", () => {
    const view = mountComponent(nav({ onOpenAgent: vi.fn() }));
    click(view.buttons().find((b) => (b.textContent ?? "").includes("Agent"))!);
    expect(text(view).toLowerCase()).toContain("desktop");
    view.unmount();
  });
});

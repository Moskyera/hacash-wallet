// @vitest-environment jsdom
/**
 * A SETTING THAT FAILS TO SAVE AND SAYS NOTHING.
 *
 * Two handlers awaited an IPC call with no try/catch, and both were invoked as
 * `void handler(...)` from the control:
 *
 *   useWalletSession.persistPrivacy   - Hide balances, Hide addresses, Screen
 *                                       privacy shield, Store tx history, Pause
 *                                       auto-lock on HACD, Clipboard clear
 *   usePaymentFlow.persistSendPrefs   - "Force on-chain (L1)" and the L1
 *                                       fee-speed picker
 *
 * A rejected command therefore became an unhandled rejection: no toast, no
 * error, nothing. And because the checkbox state is derived from
 * `settings?.privacy ?? status?.privacy ?? DEFAULT_PRIVACY`, the box snapped
 * straight back with no reason on screen. The Pay tab is worse: it flips its own
 * local state first (`setSendForceL1(force); void onPersistSendPrefs(...)`), so
 * on failure the checkbox stays visibly ticked, the wallet keeps the old
 * setting, and the divergence only surfaces on the next launch.
 *
 * "Force on-chain (L1)" is exactly what somebody reaches for when Fast Pay will
 * not turn on, which is where the owner was.
 *
 * `persistDustWhisper`, twenty lines below `persistPrivacy`, DOES wrap its call
 * in try/catch, so this was an omission rather than a house style.
 */
import { beforeEach, describe, expect, it, vi } from "vitest";
import { act } from "react";
import { mountComponent } from "./domHarness";
import { useWalletSession } from "./hooks/useWalletSession";
import { usePaymentFlow } from "./hooks/usePaymentFlow";

const updatePrivacy = vi.fn();
const updateSettings = vi.fn();

vi.mock("./api", () => {
  const stub = () => vi.fn().mockResolvedValue(null);
  return {
    api: new Proxy(
      {
        updatePrivacy: (...a: unknown[]) => updatePrivacy(...a),
        updateSettings: (...a: unknown[]) => updateSettings(...a),
      } as Record<string, unknown>,
      {
        get(target, key: string) {
          if (!(key in target)) target[key] = stub();
          return target[key];
        },
      },
    ),
  };
});

/** Mount a hook and hand back its latest return value. */
function driveHook<T>(useHook: () => T): { current: () => T; unmount: () => void } {
  let latest: T;
  function Probe() {
    latest = useHook();
    return null;
  }
  const view = mountComponent(<Probe />);
  return { current: () => latest, unmount: view.unmount };
}

beforeEach(() => {
  updatePrivacy.mockReset();
  updateSettings.mockReset();
});

describe("a privacy toggle that cannot be saved says so", () => {
  it("reports the refusal instead of leaving an unhandled rejection", async () => {
    updatePrivacy.mockRejectedValue(new Error("vault is locked"));
    const toast = vi.fn();
    const hook = driveHook(() => useWalletSession(toast));

    await act(async () => {
      await hook.current().persistPrivacy({ hide_balances: true });
    });

    const errors = toast.mock.calls.filter((call) => call[1] === "error");
    expect(
      errors.length,
      "a failed privacy save must produce an error the person can read",
    ).toBeGreaterThan(0);
    expect(String(errors[0][0])).toContain("vault is locked");
    hook.unmount();
  });

  it("does not claim success when the save was refused", async () => {
    updatePrivacy.mockRejectedValue(new Error("vault is locked"));
    const toast = vi.fn();
    const hook = driveHook(() => useWalletSession(toast));

    await act(async () => {
      await hook.current().persistPrivacy({ hide_balances: true });
    });

    const successes = toast.mock.calls.filter((call) =>
      String(call[0]).includes("Privacy settings saved"),
    );
    expect(successes).toHaveLength(0);
    hook.unmount();
  });

  it("does not rethrow, since every call site is a bare void call", async () => {
    // `onPersistPrivacy: (p) => void session.persistPrivacy(p)` - a rejection
    // here has nowhere to go but the console.
    updatePrivacy.mockRejectedValue(new Error("nope"));
    const hook = driveHook(() => useWalletSession(vi.fn()));
    await expect(
      act(async () => {
        await hook.current().persistPrivacy({ hide_balances: true });
      }),
    ).resolves.not.toThrow();
    hook.unmount();
  });
});

describe('a send preference that cannot be saved says so', () => {
  it("reports the refusal when the wallet will not store it", async () => {
    updateSettings.mockRejectedValue(new Error("disk is full"));
    const toast = vi.fn();
    const hook = driveHook(() =>
      usePaymentFlow({
        settings: { send: {}, privacy: {} } as never,
        setSettings: () => undefined,
        status: null,
        showToast: toast,
        refresh: async () => undefined,
      } as never),
    );

    await act(async () => {
      await hook.current().persistSendPrefs("sender", true);
    });

    const errors = toast.mock.calls.filter((call) => call[1] === "error");
    expect(
      errors.length,
      'a failed "Force on-chain (L1)" save must produce an error the person can read',
    ).toBeGreaterThan(0);
    hook.unmount();
  });

  it("says something when the settings are not loaded yet", async () => {
    // `if (!settings) return;` was a bare return: the checkbox flipped, nothing
    // was stored, and nothing was said.
    const toast = vi.fn();
    const hook = driveHook(() =>
      usePaymentFlow({
        settings: null,
        setSettings: () => undefined,
        status: null,
        showToast: toast,
        refresh: async () => undefined,
      } as never),
    );

    await act(async () => {
      await hook.current().persistSendPrefs("sender", true);
    });

    expect(toast.mock.calls.length).toBeGreaterThan(0);
    hook.unmount();
  });
});

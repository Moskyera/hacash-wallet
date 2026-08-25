/**
 * A COPY BUTTON THAT FAILS AND SAYS NOTHING.
 *
 * `copyWithPrivacyClear` throws `new Error("Clipboard is unavailable")` when the
 * writer is missing, and otherwise lets `clipboard.writeText` reject. Every
 * caller awaited it and then toasted success with no try/catch, and every button
 * fired them as `onClick={() => void copyHacd()}`. A failed write therefore
 * produced an unhandled rejection: no success toast, no error toast, a button
 * that looks broken and says nothing.
 *
 * Six controls: "Copy address" twice on Receive, "Copy HACD receive code",
 * "Copy Hacash address for BTC", the payment-URI copy in MobileApp, and the
 * quantum address copy in QuantumScreen.
 *
 * `copyAndReport` is the one place that now owns the outcome, so a call site
 * cannot forget again.
 */
import { describe, expect, it, vi } from "vitest";
import { copyAndReport } from "./privacy";

describe("copyAndReport never leaves a press unanswered", () => {
  it("says the success message when the write lands", async () => {
    const toast = vi.fn();
    const clipboard = { writeText: vi.fn().mockResolvedValue(undefined) };
    const ok = await copyAndReport("1AVRuFXNFi3rd", 0, toast, "Address copied.", clipboard);
    expect(ok).toBe(true);
    expect(toast).toHaveBeenCalledWith("Address copied.", "success");
  });

  it("reports a rejected clipboard write instead of throwing into nowhere", async () => {
    const toast = vi.fn();
    const clipboard = {
      writeText: vi.fn().mockRejectedValue(new Error("permission denied")),
    };
    const ok = await copyAndReport("1AVRuFXNFi3rd", 0, toast, "Address copied.", clipboard);
    expect(ok).toBe(false);
    const [message, kind] = toast.mock.calls[0];
    expect(kind).toBe("error");
    expect(String(message)).toContain("permission denied");
    // And it must not also claim success.
    expect(toast).toHaveBeenCalledTimes(1);
  });

  it("reports a missing clipboard by name", async () => {
    const toast = vi.fn();
    const ok = await copyAndReport("x", 0, toast, "Copied.", null);
    expect(ok).toBe(false);
    expect(String(toast.mock.calls[0][0])).toContain("Clipboard is unavailable");
  });

  it("never rejects, because every call site is a bare void call", async () => {
    const clipboard = { writeText: vi.fn().mockRejectedValue(new Error("nope")) };
    await expect(
      copyAndReport("x", 0, vi.fn(), "Copied.", clipboard),
    ).resolves.toBe(false);
  });

  it("still arms the privacy clear on success", async () => {
    vi.useFakeTimers();
    const clipboard = { writeText: vi.fn().mockResolvedValue(undefined) };
    await copyAndReport("secret", 1, vi.fn(), "Copied.", clipboard);
    expect(clipboard.writeText).toHaveBeenCalledWith("secret");
    await vi.advanceTimersByTimeAsync(1100);
    // The clear writes an empty string over it.
    expect(clipboard.writeText).toHaveBeenLastCalledWith("");
    vi.useRealTimers();
  });
});

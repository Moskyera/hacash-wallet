import { afterEach, describe, expect, it, vi } from "vitest";
import { clearSensitiveClipboard, copyWithPrivacyClear } from "./privacy";

afterEach(() => {
  vi.useRealTimers();
});

describe("wallet-managed clipboard", () => {
  it("clears copied wallet data immediately when the app backgrounds", async () => {
    const writes: string[] = [];
    const clipboard = {
      writeText: vi.fn(async (value: string) => {
        writes.push(value);
      }),
    };

    await copyWithPrivacyClear("private-value", 0, clipboard);
    expect(await clearSensitiveClipboard(clipboard)).toBe(true);
    expect(writes).toEqual(["private-value", ""]);
    expect(await clearSensitiveClipboard(clipboard)).toBe(false);
  });

  it("does not let an old timer erase a newer clipboard value", async () => {
    vi.useFakeTimers();
    const writes: string[] = [];
    const clipboard = {
      writeText: vi.fn(async (value: string) => {
        writes.push(value);
      }),
    };

    await copyWithPrivacyClear("first", 1, clipboard);
    await copyWithPrivacyClear("second", 30, clipboard);
    await vi.advanceTimersByTimeAsync(1_000);
    expect(writes).toEqual(["first", "second"]);

    expect(await clearSensitiveClipboard(clipboard)).toBe(true);
    expect(writes).toEqual(["first", "second", ""]);
  });

  it("fails safely when clipboard clearing is unavailable", async () => {
    const clipboard = {
      writeText: vi
        .fn<(value: string) => Promise<void>>()
        .mockResolvedValueOnce()
        .mockRejectedValueOnce(new Error("clipboard unavailable")),
    };

    await copyWithPrivacyClear("private-value", 0, clipboard);
    await expect(clearSensitiveClipboard(clipboard)).resolves.toBe(false);
  });
});

import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import {
  NOT_SENT_TEXT,
  SENT_TEXT,
  deliveryLabel,
  sendReceipt,
} from "./messengerDelivery";

const read = (path: string) => readFileSync(new URL(path, import.meta.url), "utf8");

/** The messenger screen with its comments stripped, so only shipped code counts. */
const screen = read("./components/MessengerScreen.tsx")
  .replace(/\/\*[\s\S]*?\*\//g, " ")
  .replace(/^[ \t]*\/\/.*$/gm, " ");

describe("what the messenger may claim after send", () => {
  it("calls it sent only when a relay accepted it", () => {
    expect(sendReceipt({ delivered: true })).toEqual({ text: SENT_TEXT, kind: "success" });
    const failed = sendReceipt({ delivered: false });
    expect(failed.kind).toBe("error");
    expect(failed.text).toBe(NOT_SENT_TEXT);
    expect(failed.text).toMatch(/^Not sent\./);
    expect(failed.text.toLowerCase()).not.toMatch(/\bwas sent\b|\bdelivered\b|\breceived\b/);
    // The success line may not promise the recipient got it either. One relay
    // took custody of the envelope; that is the whole of what is known.
    expect(SENT_TEXT.toLowerCase()).not.toMatch(/\bdelivered\b|\breceived\b|\brecipient\b/);
  });

  it("treats a missing or flagless record as not sent", () => {
    expect(sendReceipt(undefined).text).toBe(NOT_SENT_TEXT);
    expect(sendReceipt(null).kind).toBe("error");
    expect(sendReceipt({} as { delivered: boolean }).text).toBe(NOT_SENT_TEXT);
    expect(sendReceipt({ delivered: "yes" } as unknown as { delivered: boolean }).kind).toBe(
      "error",
    );
  });

  it("never promises a retry the wallet does not perform", () => {
    // Nothing in the app re-sends an undelivered message, so the copy must not
    // say queued or pending or sending.
    expect(NOT_SENT_TEXT.toLowerCase()).not.toMatch(/queue|pending|will be sent|sending/);
  });

  it("labels outgoing bubbles by their real transport state, and incoming not at all", () => {
    expect(deliveryLabel({ direction: "out", delivered: true })).toEqual({
      text: "Sent to relay",
      delivered: true,
    });
    expect(deliveryLabel({ direction: "out", delivered: false })).toEqual({
      text: "Not sent",
      delivered: false,
    });
    // On an incoming message `delivered` is the read flag, not a transport fact.
    expect(deliveryLabel({ direction: "in", delivered: false })).toBeNull();
    expect(deliveryLabel({ direction: "in", delivered: true })).toBeNull();
  });
});

describe("what a refusal is allowed to say", () => {
  it("passes on the relay's own reason for refusing, when it gave one", () => {
    // "inbox full" and "no relay is reachable" are different problems, and only
    // one of them is worth waiting out. `messenger_send` used to throw the
    // relay's answer away, so both arrived here as the same line.
    const receipt = sendReceipt({ delivered: false, delivery_error: "inbox full" });
    expect(receipt.kind).toBe("error");
    expect(receipt.text).toMatch(/inbox full/i);
    expect(receipt.text).toContain(NOT_SENT_TEXT);
  });

  it("says nothing extra when the relay gave no reason", () => {
    expect(sendReceipt({ delivered: false, delivery_error: null }).text).toBe(NOT_SENT_TEXT);
    expect(sendReceipt(null).text).toBe(NOT_SENT_TEXT);
  });
});

describe("the screen reports what the command actually returned", () => {
  it("does not toast success for any call that merely did not throw", () => {
    // messenger_send returns Ok when the message was only written to local
    // history. A toast that fires on non-throw is a claim the code cannot make.
    expect(screen).not.toMatch(/onToast\(\s*"Message sent\./);
    const toasts = [...screen.matchAll(/onToast\(\s*"([^"]*)"\s*,\s*"success"/g)].map(
      (m) => m[1],
    );
    expect(toasts).toEqual([]);
  });

  it("routes the send result through the receipt helper", () => {
    expect(screen).toMatch(/import\s*\{[^}]*sendReceipt[^}]*\}\s*from\s*"\.\.\/messengerDelivery"/);
    // The returned message must be captured, not discarded.
    expect(screen).toMatch(/const\s+sent\s*=\s*await\s+messengerApi\.send\(/);
    expect(screen).toMatch(/sendReceipt\(\s*sent\s*\)/);
  });

  it("shows the delivery state on outgoing bubbles", () => {
    expect(screen).toMatch(/deliveryLabel\(/);
    expect(screen).toMatch(/\bm\.delivered\b|deliveryLabel\(m\)/);
  });
});

/**
 * WHERE THE URL COMES FROM, NOT JUST WHERE TO TYPE IT.
 *
 * Two fields on a fresh install want an address that nobody supplies:
 *
 *   - `DustWhisperSettings::default()` ships `relay_urls: Vec::new()`
 *     (crates/wallet-core/src/dust_whisper.rs:33).
 *   - The only Fast Pay preset is a loopback dev hub
 *     (crates/wallet-core/src/fast_pay.rs:24-29).
 *
 * Both are empty on purpose: there is no public relay and no public hub, and a
 * default pointing at a machine nobody runs would be worse than a blank box.
 * What the wallet used to leave out is that the box is blank because a person
 * has to run the thing, and that the person can be the owner. "Add at least one
 * relay URL to enable DUST Whisper" and "Set one on the Privacy screen" both
 * said where to type and neither said where a URL comes from.
 *
 * The relay is a real binary that ships in this repo, `dust-whisper-relay`
 * (crates/dust-whisper/Cargo.toml:36-38, source
 * crates/dust-whisper/src/bin/dust-whisper-relay.rs), and the hub has had an
 * operator guide the whole time. So these tests hold every place that asks for
 * one of the two URLs to name the guide for running one.
 */
import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { pollReport } from "./messengerPoll";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = join(HERE, "../../..");

function source(relative: string): string {
  return readFileSync(join(HERE, relative), "utf8");
}

/** Somebody has to run one, and it can be you. */
const RUN_ONE = /somebody has to run|run your own|run one yourself/i;
const RELAY_GUIDE = /docs\/RUNNING-A-RELAY\.md/;
const HUB_GUIDE = /docs\/HUB-OPERATOR\.md/;

describe("the relay field says where a relay comes from", () => {
  it("names the guide on the screen that asks for the URL", () => {
    const privacy = source("screens/PrivacyScreen.tsx");
    expect(privacy).toMatch(RELAY_GUIDE);
    expect(privacy).toMatch(RUN_ONE);
  });

  it("names the guide in the messenger empty state", () => {
    const messages = source("screens/MessagesScreen.tsx");
    expect(messages).toMatch(RELAY_GUIDE);
    expect(messages).toMatch(RUN_ONE);
  });

  it("names the guide in the refusal to enable DUST Whisper without one", () => {
    const hook = source("hooks/useDesktopWallet.ts");
    expect(hook).toMatch(/Add at least one relay URL/);
    expect(hook).toMatch(RELAY_GUIDE);
  });

  it("names the guide when an inbox check had no relay to check", () => {
    const report = pollReport({
      added: 0,
      relays_tried: 0,
      relays_answered: 0,
      relays_refused: 0,
      rejected_envelopes: 0,
      undecryptable: 0,
      store_full: false,
    });
    expect(report.kind).toBe("error");
    expect(report.text).toMatch(RELAY_GUIDE);
    expect(report.text).toMatch(RUN_ONE);
    // Still the thing it was already right about: no relay tried is not an
    // empty mailbox.
    expect(report.text).not.toMatch(/nothing new/i);
  });
});

describe("the hub field says where a hub comes from", () => {
  it("names the operator guide beside the discovery button", () => {
    const panel = source("components/HubDiscoveryPanel.tsx");
    expect(panel).toMatch(HUB_GUIDE);
    expect(panel).toMatch(RUN_ONE);
  });

  it("names the operator guide beside the Hub API URL box", () => {
    const fastPay = source("screens/FastPayScreen.tsx");
    expect(fastPay).toMatch(/Hub API URL/);
    expect(fastPay).toMatch(HUB_GUIDE);
  });
});

describe("the guides the wallet points at", () => {
  it("has the hub operator guide on disk", () => {
    expect(existsSync(join(REPO, "docs/HUB-OPERATOR.md"))).toBe(true);
  });

  it("has the relay operator guide on disk", () => {
    // Held back on the first pass, because a test for a file another change
    // owned would have failed on whichever of the two landed first. Both are
    // here now, and every relay sentence above is a pointer at this one.
    expect(existsSync(join(REPO, "docs/RUNNING-A-RELAY.md"))).toBe(true);
  });
});

describe("the relay operator sees the whole transaction, and the wallet says so", () => {
  /**
   * The relay decrypts a submitted transaction before forwarding it
   * (`decrypt_payload`, crates/dust-whisper/src/relay.rs:94, posted in clear to
   * the node at :109-121). docs/RUNNING-A-RELAY.md section 6.5 tells the
   * operator that in as many words. The screen where somebody pastes a
   * stranger's relay URL said only that a remote relay "can hide your IP from
   * the full node", which is the half of the trade that sounds good.
   */
  it("says the encryption ends at the relay on the screen that turns it on", () => {
    const privacy = source("screens/PrivacyScreen.tsx");
    expect(privacy).toMatch(/encryption ends at the relay/i);
    expect(privacy).toMatch(/sees the whole transaction/i);
  });
});

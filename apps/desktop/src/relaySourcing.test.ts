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

/**
 * SECTION 0 IS A WALKTHROUGH, SO ITS GAPS ARE WHERE A PERSON STOPS.
 *
 * Three of them were real, and each one stopped somebody at the exact step it
 * was missing from:
 *
 *  - step 1's very first save fails outright if something already holds 8787,
 *    and section 0 never said so or pointed at section 4, which has a whole
 *    subsection for it;
 *  - step 4 told the second person to "put the address in their relay URL box"
 *    without saying to remove the loopback line the box came with, having just
 *    trained the reader in step 1 to leave exactly that line alone;
 *  - step 2 listed what widening costs without listing the one that stops the
 *    thing working.
 */
describe("the walkthrough for two people with nothing else deployed", () => {
  const guide = readFileSync(join(REPO, "docs/RUNNING-A-RELAY.md"), "utf8");
  const sectionZero = guide.slice(
    guide.indexOf("## 0. Two people"),
    guide.indexOf("## 1. What you are running"),
  );

  it("is a real section, read from the file rather than assumed", () => {
    expect(sectionZero.length).toBeGreaterThan(2000);
  });

  it("says the first save can fail on a port, in the step where it can", () => {
    expect(sectionZero).toMatch(/port is already in use/i);
    expect(sectionZero).toMatch(/before-anything-the-port-the-wallet-may-already-be-using/);
    // And the subsection it points at is really there to be pointed at.
    expect(guide).toMatch(/### Before anything: the port the wallet may already be using/);
  });

  it("tells the second person to move or remove the line already in the box", () => {
    expect(sectionZero).toMatch(/has to go \*\*above\s+it, or replace it\*\*/i);
    expect(sectionZero).toMatch(/delete the loopback line/i);
  });

  it("states the sending asymmetry the way it actually fails", () => {
    // Sending stops at the first relay that accepts; polling tries all of them.
    // Describing it as "the order of both lists" is not the same hazard and is
    // not what costs somebody an afternoon.
    expect(sectionZero).toMatch(/stops at the first relay in the\s+list that\s+accepts/i);
    expect(sectionZero).toMatch(/tries every relay in\s+the\s+list/i);
    expect(sectionZero).toMatch(/never written to you|no reason to suspect|live two way thread/i);
  });

  it("says the socket opening is not the relay opening, and what a stranger gets", () => {
    expect(sectionZero).toMatch(/The socket stops being yours alone. The relay does\s+not/i);
    expect(sectionZero).toMatch(/denies by\s+default/i);
    expect(sectionZero).toMatch(/cannot post a\s+message/i);
    expect(sectionZero).toMatch(/is not in the key\s+directory/i);
    // And that neither the refusal nor the acceptance is an answer. The
    // refusal was symmetric all along; the acceptance was not, which is how a
    // passer-by used to read the host list out of the challenge route.
    expect(sectionZero).toMatch(/never heard of/i);
    expect(sectionZero).toMatch(/or one that is on your\s+list/i);
    expect(sectionZero).toMatch(/cannot work out who you\s+are relaying for/i);
    expect(sectionZero).toMatch(/acceptances are the same shape as the\s+refusals/i);
  });

  it("names the limit it does not close: the people on the list", () => {
    expect(sectionZero).toMatch(/The people on the list are a different\s+matter/i);
    expect(sectionZero).toMatch(/not a secret from the people on\s+it/i);
  });

  it("says an empty list is nobody, which is the state an upgrade lands in", () => {
    expect(sectionZero).toMatch(/An empty list is nobody, not\s+everybody/i);
    expect(sectionZero).toMatch(/a safe relay and not yet a useful\s+one/i);
    // The upgrade direction is stated rather than left to be discovered.
    expect(sectionZero).toMatch(/narrows a\s+relay rather than widening one/i);
  });

  it("says the flood is closed because a stranger cannot post at all", () => {
    expect(sectionZero).toMatch(/a stranger cannot\s+fill it/i);
    expect(sectionZero).toMatch(/keys cost nothing/i);
    expect(sectionZero).toMatch(/seven days/i);
  });

  it("says the transaction door is separate and stays shut", () => {
    expect(sectionZero).toMatch(/Transactions are a different\s+door/i);
    expect(sectionZero).toMatch(/only when it was submitted from\s+this computer/i);
    expect(sectionZero).toMatch(/SubmitAccess::ThisMachineOnly/);
    // The credential, and why it is a secret rather than an IP address: the
    // very next section tells the operator to install a reverse proxy, behind
    // which every caller in the world arrives as 127.0.0.1.
    expect(sectionZero).toMatch(/READ THIS RELAY.S OWN KEY\s+FILE/i);
    expect(sectionZero).toMatch(/reverse proxy/i);
  });

  it("states the metadata a host does hold, without softening it or overclaiming", () => {
    expect(sectionZero).toMatch(/metadata of the people you\s+listed/i);
    expect(sectionZero).toMatch(/both addresses, when, and how\s+big/i);
    expect(sectionZero).toMatch(/no list removes it/i);
    expect(sectionZero).toMatch(/which both of them already know/i);
  });

  it("has the step that closes it, and names the setting behind it", () => {
    expect(sectionZero).toMatch(/### Step 2b: say who this relay is for/);
    expect(sectionZero).toMatch(/relay_allowlist/);
    expect(sectionZero).toMatch(/Your own address is already on\s+it/i);
    expect(sectionZero).toMatch(/Removing somebody takes effect at\s+once/i);
    // And it does not oversell it.
    expect(sectionZero).toMatch(/changes nothing on the loopback\s+bind/i);
  });
});

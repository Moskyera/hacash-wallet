/**
 * A GUIDE THAT SAYS "TURN IT ON AND SHARE THE ADDRESS" IS LYING.
 *
 * The wallet can host the relay two people need, and once it says so, the next
 * thing a person does is give somebody the address. That is where this feature
 * can quietly become dishonest, in three specific ways:
 *
 *   - offering an address for a socket bound to loopback, which nobody can
 *     reach;
 *   - implying that binding wider is what makes a relay reachable, when the
 *     router and the firewall have not been touched;
 *   - never mentioning carrier grade NAT, where none of it works and no amount
 *     of trying will change that.
 *
 * These tests hold the copy to all three, and they hold the widen control to
 * stating what it costs before it is used rather than after.
 */
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import type { RelayEndpoint } from "./api";
import {
  PLAIN_HTTP_LIMIT,
  ALLOWLIST_EXPLANATION,
  SHARE_INSTRUCTION,
  WIDEN_CONSEQUENCES,
  acceptedByNote,
  bindLabel,
  firstAcceptWarning,
  reachabilityConditions,
  relayReach,
  TRANSACTION_DOOR,
  widenConsequences,
} from "./relayReach";

const HERE = dirname(fileURLToPath(import.meta.url));

function source(relative: string): string {
  return readFileSync(join(HERE, relative), "utf8");
}

const LOOPBACK: RelayEndpoint = {
  hosting: true,
  serving: true,
  listen_addr: "127.0.0.1:8787",
  bind: "loopback",
  loopback_only: true,
  port: 8787,
  own_url: "http://127.0.0.1:8787",
  lan_addr: null,
  lan_url: null,
  idle_reason: null,
  allowlist: [],
  own_address: "1Owner",
  served_addresses: ["1Owner"],
  serves_nobody: false,
  transaction_reach:
    "Transactions are not relayed for anybody else. This relay forwards a transaction to your fullnode only when it was submitted from this computer.",
  relay_urls: ["http://127.0.0.1:8787"],
};

const WIDE: RelayEndpoint = {
  hosting: true,
  serving: true,
  listen_addr: "0.0.0.0:8787",
  bind: "all_interfaces",
  loopback_only: false,
  port: 8787,
  own_url: "http://127.0.0.1:8787",
  lan_addr: "192.168.1.24",
  lan_url: "http://192.168.1.24:8787",
  allowlist: [],
  own_address: "1Owner",
  served_addresses: ["1Owner"],
  serves_nobody: false,
  transaction_reach:
    "Transactions are not relayed for anybody else. This relay forwards a transaction to your fullnode only when it was submitted from this computer.",
  relay_urls: ["http://127.0.0.1:8787"],
  idle_reason: null,
};

describe("a relay on loopback", () => {
  it("says the address it is on", () => {
    expect(relayReach(LOOPBACK)?.headline).toContain("127.0.0.1:8787");
  });

  it("says in words that no other machine can reach it", () => {
    const reach = relayReach(LOOPBACK)?.reach ?? "";
    expect(reach).toMatch(/this computer and nothing else/i);
    expect(reach).toMatch(/no other machine can reach it/i);
    // Not "you may need to configure something". The person you want to
    // message cannot reach this, full stop.
    expect(reach).toMatch(/person you are trying to message/i);
  });

  it("offers no address to share, because there is not one", () => {
    expect(relayReach(LOOPBACK)?.share).toBeNull();
  });

  /**
   * Defensive on purpose. `wallet_relay_endpoint` only fills `lan_url` when
   * the socket is actually wide, but the screen must not hand out a network
   * address for a loopback listener even if it is somehow given one.
   */
  it("still offers nothing when handed a network address for a loopback socket", () => {
    const confused: RelayEndpoint = {
      ...LOOPBACK,
      lan_addr: "192.168.1.24",
      lan_url: "http://192.168.1.24:8787",
    };
    expect(relayReach(confused)?.share).toBeNull();
  });
});

describe("a relay bound to every interface", () => {
  it("says what the socket is, and that reaching it is not the same as using it", () => {
    const reach = relayReach(WIDE);
    expect(reach?.headline).toContain("0.0.0.0:8787");
    expect(reach?.headline).toMatch(/every network this computer is on/i);
    // The socket is open to the network and the relay is not. Saying only the
    // first would frighten somebody out of a safe arrangement; saying only the
    // second would hide that the port is exposed. Both.
    expect(reach?.reach).toMatch(/anybody on your network can open a connection/i);
    expect(reach?.reach).toMatch(/carries mail for your address only/i);
    expect(reach?.reach).toMatch(/cannot post a message/i);
  });

  it("names the other people it serves once there are any", () => {
    const shared = relayReach({
      ...WIDE,
      served_addresses: ["1Owner", "1Friend"],
    });
    expect(shared?.reach).toMatch(/only for the 2 addresses/i);
    expect(shared?.reach).toMatch(/yours and 1 other/i);
    expect(shared?.reach).toMatch(/everybody else is refused on every route/i);
  });

  /**
   * A wide socket serving nobody is a real state and it is the one an upgrade
   * lands in: `relay_allowlist` is empty and no wallet is loaded, so
   * `served_addresses` is empty. The screen must not describe that as working.
   */
  it("says a relay that serves nobody serves nobody, including the person reading", () => {
    const empty = relayReach({ ...WIDE, served_addresses: [], serves_nobody: true });
    expect(empty?.reach).toMatch(/carries mail for no address at all/i);
    expect(empty?.reach).toMatch(/including you/i);
  });

  it("offers the address a person would actually paste", () => {
    expect(relayReach(WIDE)?.share).toBe("http://192.168.1.24:8787");
  });

  it("names the three cases, in the order that saves an evening", () => {
    const conditions = relayReach(WIDE)?.conditions ?? [];
    const joined = conditions.join(" ");
    expect(joined).toMatch(/same network as this computer/i);
    expect(joined).toMatch(/port forwarded/i);
    expect(joined).toMatch(/firewall/i);
    expect(joined).toMatch(/carrier grade NAT/i);
    expect(joined).toMatch(/cannot be made to work at all/i);
    const sameNetwork = conditions.findIndex((c) => /same network/i.test(c));
    const internet = conditions.findIndex((c) => /port forwarded/i.test(c));
    const cgnat = conditions.findIndex((c) => /carrier grade NAT/i.test(c));
    expect(sameNetwork).toBeLessThan(internet);
    expect(internet).toBeLessThan(cgnat);
  });

  it("says the shared address can stop working on its own", () => {
    expect(relayReach(WIDE)?.conditions.join(" ")).toMatch(/can change/i);
  });

  it("promises nothing", () => {
    const all = [relayReach(WIDE)?.reach ?? "", ...(relayReach(WIDE)?.conditions ?? [])].join(" ");
    expect(all).not.toMatch(/will be able to (?:reach|connect)/i);
    expect(all).not.toMatch(/anyone can now connect/i);
  });

  it("still names the conditions when no network address was found", () => {
    const noRoute: RelayEndpoint = { ...WIDE, lan_addr: null, lan_url: null };
    expect(relayReach(noRoute)?.share).toBeNull();
    expect(relayReach(noRoute)?.conditions.join(" ")).toMatch(/carrier grade NAT/i);
    expect(reachabilityConditions(noRoute)[0]).toContain("the address above");
  });
});

describe("a wallet that is not hosting", () => {
  it("repeats the reason the wallet gave rather than inventing one", () => {
    const idle: RelayEndpoint = {
      hosting: false,
      serving: false,
      listen_addr: null,
      bind: "loopback",
      loopback_only: true,
      port: 8787,
      own_url: "http://127.0.0.1:8787",
      lan_addr: null,
      lan_url: null,
      idle_reason: "Auto-start is off, so this wallet is not hosting a relay.",
      allowlist: [],
  own_address: "1Owner",
  served_addresses: ["1Owner"],
  serves_nobody: false,
  transaction_reach:
    "Transactions are not relayed for anybody else. This relay forwards a transaction to your fullnode only when it was submitted from this computer.",
      relay_urls: ["http://127.0.0.1:8787"],
    };
    expect(relayReach(idle)?.headline).toBe(
      "Auto-start is off, so this wallet is not hosting a relay.",
    );
    expect(relayReach(idle)?.share).toBeNull();
  });

  it("says nothing at all before the wallet has answered", () => {
    expect(relayReach(null)).toBeNull();
    expect(bindLabel(null)).toBe("unknown");
  });

  it("does not claim a socket is bound when the wallet is set to host but nothing is listening", () => {
    const stalled: RelayEndpoint = {
      ...LOOPBACK,
      serving: false,
      listen_addr: null,
    };
    expect(relayReach(stalled)?.headline).toMatch(/nothing is listening/i);
    expect(relayReach(stalled)?.share).toBeNull();
  });
});

describe("the choice to widen the bind", () => {
  /**
   * `WIDEN_CONSEQUENCES` is the nobody-listed case, which is the default, and
   * the default has to read as the safe-but-not-working state it is.
   */
  it("states what it costs, starting from the default, which serves nobody", () => {
    const joined = WIDEN_CONSEQUENCES.join(" ");
    expect(joined).toMatch(/carry mail for nobody/i);
    expect(joined).toMatch(/including yours/i);
    expect(joined).toMatch(/plain HTTP/i);
    expect(joined).toMatch(/docs\/RUNNING-A-RELAY\.md/);
  });

  /**
   * The state a person is actually in when they press the control: their own
   * address is served whether or not they typed it, so the box has to be
   * described from `served_addresses` and not from the text area.
   */
  it("states what it costs once somebody is listed, and what the host then holds", () => {
    const joined = widenConsequences(["1Owner", "1Friend"]).join(" ");
    expect(joined).toMatch(/only for the 2 addresses listed below/i);
    expect(joined).toMatch(/the first of them is your own/i);
    expect(joined).toMatch(/1 other address is listed/i);
    expect(joined).toMatch(/everybody else who reaches this port is refused on every route/i);
    // The limit that is inherent and must not be engineered away in the copy.
    expect(joined).toMatch(/you will hold the metadata of the people you listed/i);
    expect(joined).toMatch(/both addresses, when it was sent, and how big it was/i);
    expect(joined).toMatch(/not the contents/i);
    expect(joined).toMatch(/no list removes it/i);
    // And it must not overclaim past that.
    expect(joined).toMatch(/those two people talk to each other, which both of them already know/i);
  });

  /**
   * A host who opened a message relay must not discover later that they also
   * opened a transaction submitter for their network. The rule is
   * `SubmitAccess::LoopbackOnly`; this is the sentence that quotes it.
   */
  it("says the transaction door is a different door and stays shut", () => {
    for (const list of [[], ["1Owner"], ["1Owner", "1Friend"]]) {
      const joined = widenConsequences(list).join(" ") + " " + TRANSACTION_DOOR;
      expect(joined).toMatch(/transactions/i);
      expect(joined).toMatch(/only when it was submitted from this computer/i);
    }
    expect(TRANSACTION_DOOR).toMatch(/refused before their payload is read|refused before its payload is read/i);
    expect(reachabilityConditions(WIDE).join(" ")).toMatch(
      /only when it was submitted from this computer/i,
    );
  });

  it("is a control the person operates, never a default and never automatic", () => {
    const privacy = source("screens/PrivacyScreen.tsx");
    // The consequences are rendered beside the control, not after the save,
    // and they are computed from the allowlist the person is looking at rather
    // than from a constant that cannot know about it.
    // Computed from what the relay will serve after the save, which is the
    // owner plus the additions, and not from the text box on its own.
    expect(privacy).toMatch(/widenConsequences\(servedDraft\)/);
    expect(privacy).toMatch(/own_address/);
    expect(privacy).toMatch(/relay_bind/);
    // Nothing in the shipped defaults asks for a wide socket.
    expect(source("privacy.ts")).toMatch(/relay_bind:\s*"loopback"/);
  });

  it("tells the two people that one relay has to be the same relay", () => {
    expect(SHARE_INSTRUCTION).toMatch(/no federation/i);
    expect(SHARE_INSTRUCTION).toMatch(/same relay/i);
  });

  /**
   * `validate_relay_url` (crates/dust-whisper/src/client.rs) refuses a relay
   * URL that is neither loopback nor HTTPS, and only on the transaction path.
   * A person handed a plain http address gets a working messenger and a
   * broadcast that quietly went somewhere else, so the screen that hands the
   * address over is where that is said.
   */
  it("says a plain http address carries messages and not transactions", () => {
    expect(PLAIN_HTTP_LIMIT).toMatch(/not be used to broadcast transactions/i);
    expect(PLAIN_HTTP_LIMIT).toMatch(/straight to the node/i);
    expect(PLAIN_HTTP_LIMIT).toMatch(/HTTPS/);
    for (const file of ["screens/PrivacyScreen.tsx", "screens/MessagesScreen.tsx"]) {
      expect(source(file)).toMatch(/PLAIN_HTTP_LIMIT/);
    }
  });
});

describe("the screens carry it", () => {
  it("shows the address on the messenger, where a person is trying to reach somebody", () => {
    const messages = source("screens/MessagesScreen.tsx");
    expect(messages).toMatch(/relayReach|RelayEndpoint/);
  });

  it("puts the whole decision where the relay settings are saved", () => {
    const privacy = source("screens/PrivacyScreen.tsx");
    expect(privacy).toMatch(/relayReach/);
    expect(privacy).toMatch(/RUNNING-A-RELAY\.md/);
  });
});

/**
 * WHAT AN OPEN RELAY COSTS THAT IS NOT ABOUT WHAT SOMEBODY LEARNS.
 *
 * The widen list used to end by claiming to be the whole of the choice. It was
 * not. Every item on it was about what an outsider can SEE, and none of it said
 * an outsider can stop the relay working. Keys are free, so a stranger on that
 * network can fill the store with signed mail addressed to inboxes of their own
 * until the relay refuses everybody, including the friend it was widened for.
 */
describe("what widening actually costs", () => {
  /**
   * The flood and the directory oracle were the two costs of an OPEN relay,
   * and both were things a stranger could do because a stranger could use the
   * relay at all. Default deny removes the precondition, so the copy no longer
   * warns about them; what it must do instead is say, plainly, that a stranger
   * cannot do anything - and it must be checkable that the code makes that so,
   * which is `messenger_relay_allowlist.rs`, not this file.
   */
  it("says a stranger gets nothing rather than warning about what a stranger could do", () => {
    const joined = widenConsequences(["1Owner", "1Friend"]).join(" ");
    expect(joined).toMatch(/cannot post/i);
    expect(joined).toMatch(/cannot be posted to/i);
    expect(joined).toMatch(/cannot get a mailbox challenge/i);
    expect(joined).toMatch(/are not in the key directory/i);
  });

  /**
   * Refusing must not itself be an answer, and neither must accepting. An
   * address the host left off, an address the relay never heard of, and an
   * address that IS on the list all answer a stranger the same on every route:
   * `NOT_ON_THE_LIST` on send, a decoy nonce of the same shape on challenge,
   * `None` on the key directory whoever asks without a credential, and one
   * refusal sentence on ack. The old copy said "the same refusal", and the
   * refusal genuinely was symmetric - it was the ACCEPTANCE that was not, and
   * that is what a passer-by could read the host's list out of. The sentence
   * has to cover both, so the assertion does.
   */
  it("says neither the refusal nor the acceptance gives anything away", () => {
    for (const list of [["1Owner"], ["1Owner", "1Friend"]]) {
      const joined = widenConsequences(list).join(" ");
      expect(joined).toMatch(/the same whether the address they name is one you left off/i);
      expect(joined).toMatch(/never heard of/i);
      expect(joined).toMatch(/or one that is on the list/i);
      expect(joined).toMatch(/cannot (even )?learn who you are relaying for/i);
    }
  });

  /**
   * And the one thing that is NOT closed is named rather than left out. A
   * person already on the list can put a third address in front of the send
   * route and see whether it is accepted. Closing that means accepting a
   * message and discarding it, which is a worse thing to do than to say this.
   */
  it("names the correspondent who can still work out the list", () => {
    const named = widenConsequences(["1Owner", "1Alice"]).join(" ");
    expect(named).toMatch(/the people you list can work out who else you listed/i);
    expect(named).toMatch(/a stranger cannot/i);
    expect(named).toMatch(/not a secret from the people on it/i);
  });

  it("does not keep claiming the list is the whole of the choice", () => {
    // The wording that made the omission a lie rather than a gap.
    for (const line of widenConsequences([])) {
      expect(line).not.toMatch(/that is the whole of (it|the choice)/i);
    }
  });

  it("tells a person whose list is empty that the relay does not work yet", () => {
    const empty = widenConsequences([]).join(" ");
    expect(empty).toMatch(/carry mail for nobody/i);
    expect(empty).toMatch(/including yours/i);
    expect(empty).toMatch(/not a working one/i);
    // It must never describe the empty state as open, which is what it meant
    // before and what would now be exactly backwards.
    expect(empty).not.toMatch(/anyone who can reach this computer.*can post/i);
    expect(empty).not.toMatch(/stops being yours alone/i);
  });

  it("says what a typo on the list costs, and that removal is immediate", () => {
    const named = widenConsequences(["1Owner", "1Alice"]).join(" ");
    expect(named).toMatch(/typo/i);
    expect(named).toMatch(/locks out/i);
    // "as soon as you press Save" used to be made true by dropping the socket,
    // which also hung up on everybody and threw away every uncollected message.
    // The list is swapped on the running relay now, so the promise is kept on
    // the next request instead - including for a caller already connected - and
    // nothing waiting is lost. The sentence says both.
    expect(named).toMatch(/on the next request after you press Save/i);
    expect(named).toMatch(/already connected/i);
    expect(named).toMatch(/nothing waiting on the relay for anybody else is lost/i);
  });

  /**
   * THE BULLET THAT TOLD YOU TO FALSIFY THE BULLET ABOVE IT.
   *
   * The transaction sentence and "go and install a reverse proxy" are in the
   * same four-item list. While the door was gated on the peer's IP address the
   * second made the first false, because every caller behind a proxy arrives as
   * 127.0.0.1. The rule was changed rather than the sentence softened, and the
   * sentence has to name the credential that makes it true.
   */
  it("says why the transaction door survives the proxy it tells you to install", () => {
    for (const list of [[], ["1Owner"], ["1Owner", "1Alice"]]) {
      const joined = widenConsequences(list).join(" ");
      expect(joined).toMatch(/key file/i);
      expect(joined).toMatch(/reverse proxy/i);
    }
    expect(TRANSACTION_DOOR).toMatch(/key file/i);
    expect(TRANSACTION_DOOR).toMatch(/reverse proxy/i);
  });

  it("counts one address as one address", () => {
    expect(widenConsequences(["1Alice"])[0]).toMatch(/the 1 address listed below/i);
    // Whitespace is not a name, and a box of whitespace is still nobody.
    expect(widenConsequences(["", "   "])).toEqual(widenConsequences([]));
  });

  it("tells the person what the allowlist box is for, above the box", () => {
    expect(ALLOWLIST_EXPLANATION).toMatch(/empty means the relay is for you alone/i);
    expect(ALLOWLIST_EXPLANATION).toMatch(/plus your own, which is added for you/i);
    expect(ALLOWLIST_EXPLANATION).toMatch(/refused on every route/i);
    expect(ALLOWLIST_EXPLANATION).toMatch(/on the next request after you press Save/i);
    expect(ALLOWLIST_EXPLANATION).toMatch(/can find out who else is/i);
    expect(ALLOWLIST_EXPLANATION).toMatch(
      /changes nothing while the relay is on this computer only/i,
    );
    expect(source("screens/PrivacyScreen.tsx")).toMatch(/ALLOWLIST_EXPLANATION/);
  });
});

/**
 * THE ORDER OF THE RELAY LIST, WHICH IS NOT A PREFERENCE.
 *
 * A send stops at the first relay that accepts; polling tries every relay. A
 * wallet hosting its own relay always has one that accepts. So a list of
 * `[my own relay, my friend's]` delivers everything into this machine's own
 * mailbox while the friend's replies keep arriving, and the wallet reports it
 * as delivered with no error at all.
 */
describe("a wallet whose own relay sits above somebody else's", () => {
  const OWN_FIRST: RelayEndpoint = {
    ...LOOPBACK,
    relay_urls: ["http://127.0.0.1:8787", "http://192.168.1.24:8787"],
  };

  it("says nothing you send is reaching the other relay", () => {
    const warning = firstAcceptWarning(OWN_FIRST);
    expect(warning).not.toBeNull();
    expect(warning).toContain("http://192.168.1.24:8787");
    expect(warning).toMatch(/stops at the first relay that accepts/i);
    expect(warning).toMatch(/always accepts/i);
    // The half that makes it invisible: the replies still arrive.
    expect(warning).toMatch(/replies from that relay still arrive/i);
    expect(warning).toMatch(/looks two way when it is not/i);
    // And what to do about it.
    expect(warning).toMatch(/put their address above|take that line out/i);
  });

  it("says nothing when the friend's relay is first", () => {
    expect(
      firstAcceptWarning({
        ...OWN_FIRST,
        relay_urls: ["http://192.168.1.24:8787", "http://127.0.0.1:8787"],
      }),
    ).toBeNull();
  });

  it("says nothing when the wallet's own relay is the only one", () => {
    expect(firstAcceptWarning(LOOPBACK)).toBeNull();
  });

  it("says nothing when this wallet's relay is not actually listening", () => {
    // A relay that refuses the connection swallows nothing: the send falls
    // through to the next one, so there is no warning to give.
    expect(firstAcceptWarning({ ...OWN_FIRST, serving: false })).toBeNull();
  });

  it("ignores a trailing slash and case, because a person pasting will not", () => {
    expect(
      firstAcceptWarning({
        ...OWN_FIRST,
        relay_urls: ["http://127.0.0.1:8787/", "http://192.168.1.24:8787"],
      }),
    ).not.toBeNull();
  });

  it("is rendered on both screens, not only where the settings are", () => {
    expect(source("screens/PrivacyScreen.tsx")).toMatch(/firstAcceptWarning/);
    expect(source("screens/MessagesScreen.tsx")).toMatch(/firstAcceptWarning/);
  });
});

/** Which relay took one message, said next to that message. */
describe("naming the relay that accepted a message", () => {
  it("says when a message went no further than this machine", () => {
    const note = acceptedByNote("http://127.0.0.1:8787", LOOPBACK);
    expect(note).toContain("http://127.0.0.1:8787");
    expect(note).toMatch(/relay running on this computer/i);
    expect(note).toMatch(/gone no further than this machine/i);
  });

  it("names the relay plainly when it is somebody else's", () => {
    expect(acceptedByNote("http://192.168.1.24:8787", LOOPBACK)).toBe(
      "Accepted by http://192.168.1.24:8787.",
    );
  });

  it("says nothing about a message no relay took", () => {
    expect(acceptedByNote(null, LOOPBACK)).toBeNull();
    expect(acceptedByNote(undefined, LOOPBACK)).toBeNull();
    expect(acceptedByNote("  ", LOOPBACK)).toBeNull();
  });

  it("is what the wallet actually records, not something the screen inferred", () => {
    // `messenger_send` records the URL that accepted; the screen only prints
    // it. If the core stops recording it, this note is the wrong shape to
    // invent an answer.
    const core = readFileSync(join(HERE, "../../../crates/wallet-core/src/messenger.rs"), "utf8");
    expect(core).toMatch(/pub delivered_via: Option<String>/);
    expect(core).toMatch(/delivered_via: accepted_by/);
  });
});

/**
 * THE SAVE THAT FAILED AFTER IT HAD ALREADY CHANGED SOMETHING.
 *
 * `wallet_update_dust_whisper_settings_desktop` persists the settings and THEN
 * binds the socket, so a save that fails on a port already in use has already
 * changed what is stored. The refreshes used to sit on the success path only,
 * so on that failure the screen kept showing the state from before the save.
 */
describe("the screen after a save that failed", () => {
  it("re-reads the wallet whether the save threw or not", () => {
    const hook = source("hooks/useDesktopWallet.ts");
    const save = hook.slice(hook.indexOf("const handleSaveWhisper"));
    const body = save.slice(0, save.indexOf("\n    [\n"));
    const finallyBlock = body.slice(body.indexOf("} finally {"));
    for (const refresh of ["refreshStatus()", "refreshRelayHealth()", "refreshRelayEndpoint()"]) {
      expect(finallyBlock).toContain(refresh);
    }
  });

  it("has the sentence for a wallet that is set to host and is not listening", () => {
    const notListening = relayReach({ ...LOOPBACK, serving: false, listen_addr: null });
    expect(notListening?.headline).toMatch(/set to host a relay, but nothing is listening/i);
    expect(notListening?.reach).toMatch(/port is already in use/i);
    expect(notListening?.share).toBeNull();
  });
});

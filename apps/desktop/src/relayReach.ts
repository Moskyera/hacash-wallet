/**
 * WHAT THE WALLET MAY SAY ABOUT THE RELAY IT IS HOSTING.
 *
 * The desktop wallet has hosted a relay all along: `auto_start_relay` defaults
 * to on and `crates/wallet-tauri-common/src/desktop_relay.rs` binds the socket
 * and serves it. Two people who install this wallet therefore need nothing
 * else deployed. One of them hosts and the other points at them.
 *
 * What stopped that being a path anybody could take is that no screen said
 * what address the wallet was serving on, and the socket went to loopback with
 * no way to move it.
 *
 * This module is the sentences. They are here rather than in JSX because the
 * risk in this feature is the copy: a guide that says "turn it on and share
 * the address" is lying by omission, and the tests beside this file are what
 * hold it to what is actually true. Three rules:
 *
 * 1. A loopback relay is reachable by nobody. It says that in words, and it
 *    offers no address to share, because there is not one.
 * 2. A wide bind is not reachability. Same network is one thing, the internet
 *    is a router and a firewall rule and an address that stays put, and behind
 *    carrier grade NAT it is not possible at all. All three are said where the
 *    person is deciding.
 * 3. Nothing here promises that sharing an address will work. It says what has
 *    to be true.
 */
import type { RelayEndpoint } from "./api";

export type RelayReach = {
  /** What the wallet is serving, or that it is serving nothing. */
  headline: string;
  /** Who can reach it. */
  reach: string;
  /** The address to give somebody, when there is one worth giving. */
  share: string | null;
  /** What still has to be true before that address reaches anybody. */
  conditions: string[];
  tone: "ok" | "warn" | "idle";
};

/**
 * WHAT A PERSON IS TAKING ON BY MOVING THE BIND OFF THIS MACHINE.
 *
 * Shown next to the control, not after it. This is the screen where a door is
 * opened, so it has to say what walks through it, and every sentence here is a
 * quotation of a rule in the code rather than a hope about one.
 *
 * The rule the whole list now rests on is default deny, in `InboxAllowlist`
 * (crates/dust-whisper/src/messenger_relay.rs): the relay carries mail only
 * for addresses its host named, and an address that is not named gets nothing
 * on any route - it cannot post, cannot be posted to, cannot obtain a mailbox
 * challenge worth anything, cannot collect, cannot acknowledge, and is not in
 * the key directory. The wallet composes the enforced list in
 * `desktop_relay::served_addresses`: this wallet's own address, plus whatever
 * was typed. So an untouched wallet, bound wide, serves exactly one person.
 *
 * The refusals are also all SHAPED the same as the acceptances, which they
 * were not: the challenge route answered a listed address with a nonce and an
 * unlisted one with an empty string, and the key directory answered a stranger
 * about anybody, so a passer-by could read a host's list back out one address
 * at a time. Both are closed, and the sentences below say what a stranger can
 * learn now, which is nothing, and what a listed correspondent can, which is
 * who else is listed.
 *
 * `served` is `served_addresses` from the endpoint report, which is the list
 * the relay is actually enforcing - read off the running relay, not recomputed
 * from the settings box. A screen that quoted the box would leave out the
 * owner, and one that recomputed it could name a list nothing was enforcing.
 */
export function widenConsequences(served: string[] = []): string[] {
  const listed = served.map((a) => a.trim()).filter((a) => a.length > 0);
  const others = Math.max(0, listed.length - 1);
  const shared = [
    // Always, in both branches. The bind control is where a person decides to
    // open a door, and the transaction door is the one they would not know they
    // had. Leaving it off the empty-list branch would leave it off the exact
    // screen a person sees the first time they widen anything.
    "Transactions are a different door and it stays shut. This relay forwards a transaction to your fullnode only when it was submitted from this computer by something that can read this relay's own key file. A machine on your network that tries is refused before its payload is read, whatever the bind is and whoever is on the list, and that stays true if you later put a reverse proxy in front of this relay, where every caller in the world would otherwise arrive looking like this computer. Widening this to let a friend message you does not make you a transaction submitter for your network.",
    "It runs while this wallet is open, and stops when you close it. Mail nobody has collected yet is held in memory and is gone when it stops. Saving this screen does not lose it: changing the list changes the rule on the running relay and leaves what is waiting where it is.",
    "The relay speaks plain HTTP. Until you put HTTPS in front of it, the addresses on each envelope and its timing and size are also readable by every network between the other person and this computer. Section 4 of docs/RUNNING-A-RELAY.md is how to put HTTPS in front of it.",
  ];
  if (listed.length === 0) {
    return [
      "This relay will carry mail for nobody. No address is listed, not even your own, so every message and every mailbox request is refused, including yours. That is the safe state and it is not a working one: add the addresses below.",
      ...shared,
    ];
  }
  const whoElse =
    others === 0
      ? "Nobody else is listed. A neighbour on your network who reaches this port cannot post a message, cannot have one posted to them, cannot get a mailbox challenge worth anything, cannot collect anything and cannot ask the key directory about anybody. Every answer they get is the same whether the address they name is one you left off or one this relay has never heard of or one that is on the list, so they cannot even learn who you are relaying for."
      : `${others} other ${others === 1 ? "address is" : "addresses are"} listed. Everybody else who reaches this port is refused on every route: they cannot post, cannot be posted to, cannot get a mailbox challenge worth anything, cannot collect, cannot acknowledge, and are not in the key directory. Every one of those answers is the same whether the address they name is one you left off or one this relay has never heard of or one that is on the list, so they cannot learn who you are relaying for either.`;
  return [
    `This relay will carry mail only for the ${listed.length} ${listed.length === 1 ? "address" : "addresses"} listed below, and the first of them is your own. ${whoElse}`,
    others === 0
      ? "You will hold nobody else's metadata, because nobody else can leave anything here. That changes the moment you add somebody: see the next line before you do."
      : "You will hold the metadata of the people you listed. For each message that passes through: both addresses, when it was sent, and how big it was. Not the contents, which are sealed to the recipient's key and which this relay cannot open. That is inherent to relaying for somebody and no list removes it. It is also close to nothing, because the fact it reveals is that those two people talk to each other, which both of them already know.",
    "The people you list can work out who else you listed. A stranger cannot, but somebody already on this list can send to an address and see whether it is accepted, and only a listed address is. Closing that would mean taking a message and quietly throwing it away so the two answers matched, which is worse. So the list is not a secret from the people on it.",
    "A wrong or missing address on that list is the person it locks out. Nothing here checks the list against anything, because there is nothing to check it against, so an address with a typo in it simply never matches and their mail is refused with a sentence saying why. Removing an address takes effect on the next request after you press Save, including for somebody who is already connected, and nothing waiting on the relay for anybody else is lost when you save.",
    ...shared,
  ];
}

/**
 * The nobody-listed case, kept as a constant because that is the case the docs
 * and the tests speak about by name. It is also the default: a settings file
 * that predates the list has an empty one, and an empty one is nobody.
 */
export const WIDEN_CONSEQUENCES: string[] = widenConsequences([]);

/** What the allowlist box is for, above the box. */
export const ALLOWLIST_EXPLANATION =
  "This relay carries mail only for the addresses listed here, plus your own, which is added for you. Everybody else who can reach it is refused on every route and learns nothing, including whether the address they asked about is on this list at all. The people who ARE on it can find out who else is, because a message to a listed address is accepted and one to any other address is not. Empty means the relay is for you alone, and that is what it is until you add somebody. Put the Hacash address of each person you are hosting for, one per line. Removing a line stops carrying their mail on the next request after you press Save. This changes nothing while the relay is on this computer only, because nothing else can open a connection to it.";

/** The bind, in the words used on the control. */
export function bindLabel(endpoint: RelayEndpoint | null): string {
  if (!endpoint) return "unknown";
  return endpoint.bind === "all_interfaces" ? "every network on this computer" : "this computer only";
}

/**
 * The relay this wallet is serving, described honestly.
 *
 * `null` when the wallet has not answered yet, in which case the screen says
 * nothing rather than guessing.
 */
export function relayReach(endpoint: RelayEndpoint | null): RelayReach | null {
  if (!endpoint) return null;

  if (!endpoint.hosting) {
    return {
      headline: endpoint.idle_reason ?? "This wallet is not hosting a relay.",
      reach: "Nothing is listening on this computer, so there is no address to give anybody.",
      share: null,
      conditions: [],
      tone: "idle",
    };
  }

  if (!endpoint.serving || !endpoint.listen_addr) {
    return {
      headline: "This wallet is set to host a relay, but nothing is listening.",
      reach:
        "The usual reason is that the port is already in use by something else, and the wallet reports that when it tries to start. Until it is listening, nobody can reach it, including this computer.",
      share: null,
      conditions: [],
      tone: "warn",
    };
  }

  if (endpoint.loopback_only) {
    return {
      headline: `Your wallet is serving a relay on ${endpoint.listen_addr}.`,
      reach:
        "That address is this computer and nothing else. No other machine can reach it, including the machine of the person you are trying to message. There is no address to share while it is bound here.",
      share: null,
      conditions: [],
      tone: "ok",
    };
  }


  // Bound wide is not the same as open. The socket accepts a connection from
  // anybody who can route here, and then the relay refuses every route to an
  // address its host did not name: `InboxAllowlist` in
  // crates/dust-whisper/src/messenger_relay.rs. So what this says is who it
  // will actually serve, taken from `served_addresses`, which is the list the
  // relay is enforcing rather than the box the person typed into.
  const served = (endpoint.served_addresses ?? []).filter((a) => a.trim().length > 0);
  if (served.length === 0) {
    return {
      headline: `Your wallet is serving a relay on ${endpoint.listen_addr}, which is every network this computer is on.`,
      reach:
        "It carries mail for no address at all, so nobody can use it, including you. Anybody who reaches this port is refused on every route. Add the addresses this relay is for below.",
      share: endpoint.lan_url,
      conditions: reachabilityConditions(endpoint),
      tone: "warn",
    };
  }
  const others = served.length - 1;
  return {
    headline: `Your wallet is serving a relay on ${endpoint.listen_addr}, which is every network this computer is on.`,
    reach:
      others === 0
        ? "Anybody on your network can open a connection to that port, and the relay carries mail for your address only. They cannot post a message, have one posted to them, claim a mailbox or ask the key directory about anybody, and every answer they get is the same whichever address they name, including yours."
        : `Anybody on your network can open a connection to that port, and the relay carries mail only for the ${served.length} addresses it lists: yours and ${others} other${others === 1 ? "" : "s"}. Everybody else is refused on every route, and every answer they get is the same whichever address they name, including one that is on the list.`,
    share: endpoint.lan_url,
    conditions: reachabilityConditions(endpoint),
    tone: "warn",
  };
}

/**
 * The transaction path, said where the bind is being decided.
 *
 * A person who widened the bind so a friend could message them has NOT opened
 * a transaction submitter, and the only way they can know that is if we say so.
 * The rule is `SubmitAccess::ThisMachineOnly` in
 * crates/dust-whisper/src/relay.rs, which the wallet sets and never varies, and
 * which refuses a caller from another machine before their payload is read.
 *
 * The sentence names the key file because the credential is what makes it true.
 * The check used to be the peer's IP address, and the very next bullet in this
 * same list tells the person to go and install a reverse proxy - behind which
 * every submitter on earth arrives as 127.0.0.1. A screen must not tell you to
 * do the thing that falsifies its own previous sentence, so the rule was
 * changed rather than the sentence softened: the door wants a secret derived
 * from the relay's key file, which only something on this machine can read and
 * which no proxy can launder.
 */
export const TRANSACTION_DOOR =
  "Transactions are not carried for anybody else, on any bind. This relay forwards a transaction to your fullnode only when it was submitted from this computer by something that can read this relay's own key file; a machine on your network that tries is refused before its payload is read, and so does one arriving through a reverse proxy, which would otherwise make every caller in the world look like this computer. Opening the bind for messages does not make this a submitter for your network.";

/**
 * What has to be true for a shared address to reach anybody.
 *
 * The order is deliberate: the case that works, then the case that takes work,
 * then the case that cannot be made to work. A person on mobile broadband
 * should meet the last one before they spend an evening on the second.
 */
export function reachabilityConditions(endpoint: RelayEndpoint | null): string[] {
  const address = endpoint?.lan_url ?? "the address above";
  const conditions = [
    `On the same network as this computer, ${address} works, once this computer's firewall allows that port in.`,
    "From anywhere else it does not. Reaching this computer over the internet needs a port forwarded to it on your router, a firewall rule to match, and a public address that stays put or a dynamic DNS name that follows it when it changes.",
    "On a connection behind carrier grade NAT, which is most mobile broadband and a good deal of home fibre, there is no port on your router to forward and this cannot be made to work at all. Your router having a private address on its own internet side is the sign.",
    "It is plain HTTP either way. Section 4 of docs/RUNNING-A-RELAY.md is how you put HTTPS in front of it, and section 9 is why an address you publish without that is not one you should publish.",
  ];
  conditions.push(TRANSACTION_DOOR);
  if (endpoint?.lan_addr) {
    conditions.push(
      `${endpoint.lan_addr} is what this computer holds on its network right now. A restart, or your router, can change it, and the address you gave somebody stops working when it does.`,
    );
  }
  return conditions;
}

/** What the other person does with the address, once it reaches them. */
export const SHARE_INSTRUCTION =
  "The other person pastes that address into their own relay list, on their Privacy screen. You both have to be using the same relay: an envelope posted to one relay is only ever collected from that relay, and there is no federation between them.";

/**
 * The half of the enforcement a person meets on the other side of the paste.
 *
 * `validate_relay_url` in crates/dust-whisper/src/client.rs refuses a relay URL
 * that is not loopback and not HTTPS, but only on the transaction path. The
 * messenger path has no scheme check at all. So a plain http address handed to
 * a friend carries their messages and will not carry their transactions, and
 * they should hear that from us rather than from a broadcast that quietly went
 * straight to the node instead.
 */
export const PLAIN_HTTP_LIMIT =
  "A plain http address carries messages, and it will not be used to broadcast transactions: the wallet refuses a relay URL that is neither loopback nor HTTPS on that path, and sends the transaction straight to the node instead when the direct fallback is on. Section 4 of docs/RUNNING-A-RELAY.md is how an address gets HTTPS.";


/** One relay URL, in the shape a comparison can use. */
function sameRelay(a: string, b: string): boolean {
  const norm = (u: string) => u.trim().replace(/\/+$/, "").toLowerCase();
  return norm(a) === norm(b);
}

/**
 * THE ORDER OF THE RELAY LIST, WHICH IS NOT A PREFERENCE.
 *
 * A send stops at the FIRST relay that accepts the envelope
 * (`messenger_send`, crates/wallet-core/src/messenger.rs, which breaks out of
 * the loop on the first success). Collecting mail tries EVERY relay in the
 * list (`messenger_poll_inbox`, no break). That asymmetry is invisible and it
 * is not symmetrical in its consequences either.
 *
 * The wallet hosts a relay of its own, and its own relay always accepts. So a
 * person who was given a friend's address and added it UNDER the line already
 * in the box delivers every outgoing message into the mailbox on their own
 * computer, where the friend cannot collect it. The wallet reports the message
 * delivered, because a relay did accept it. The friend's replies still arrive,
 * because polling tries every relay. The result is a thread that looks like a
 * conversation and carries one direction of it.
 *
 * `null` when the wallet is not in that configuration. It is deliberately not
 * raised when the wallet's own relay is not actually serving: a relay that
 * refuses the connection does not swallow anything, and the send falls through
 * to the next one.
 */
export function firstAcceptWarning(endpoint: RelayEndpoint | null): string | null {
  if (!endpoint || !endpoint.serving || !endpoint.own_url) return null;
  const urls = endpoint.relay_urls.map((u) => u.trim()).filter((u) => u.length > 0);
  const own = endpoint.own_url;
  const ownIndex = urls.findIndex((u) => sameRelay(u, own));
  const otherIndex = urls.findIndex((u) => !sameRelay(u, own));
  if (ownIndex < 0 || otherIndex < 0 || ownIndex > otherIndex) return null;
  return (
    `${own} is above ${urls[otherIndex]} in this wallet's relay list, and a message stops at the ` +
    "first relay that accepts it. The relay on this computer always accepts, so nothing you send " +
    `reaches ${urls[otherIndex]} while it is in that order. Collecting mail tries every relay, so ` +
    "replies from that relay still arrive and the conversation looks two way when it is not. If " +
    `somebody else is hosting for you, put their address above ${own} or take that line out.`
  );
}

/**
 * Which relay took one outgoing message, said next to that message.
 *
 * `delivered` alone was the whole of what the screen was given, and it is true
 * of a message that went no further than this machine. See
 * `ChatMessage::delivered_via` in crates/wallet-core/src/messenger.rs.
 */
export function acceptedByNote(
  deliveredVia: string | null | undefined,
  endpoint: RelayEndpoint | null,
): string | null {
  const via = deliveredVia?.trim();
  if (!via) return null;
  const own = endpoint?.own_url?.trim();
  if (own && sameRelay(via, own)) {
    return (
      `Accepted by ${via}, which is the relay running on this computer. It has gone no further ` +
      "than this machine, so the other person collects it only if they are pointed at this " +
      "computer's address."
    );
  }
  return `Accepted by ${via}.`;
}

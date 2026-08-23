# Running a DUST Whisper relay

**Audience:** someone who has a machine and wants to run a relay, either for
themselves and a few people they know, or for strangers. You do not need to have
read the protocol.

**Why this document exists:** a fresh wallet has no relay.
`DustWhisperSettings::default()` sets `relay_urls: Vec::new()`
(`crates/wallet-core/src/dust_whisper.rs:29-37`), and there is no public relay
shipped in that field, because a default pointing at a machine nobody runs is
worse than an empty field that says what it wants. The Messages screen therefore
tells people to set one. This is where they, or you, learn to run one.

**Read section 6 before you decide.** It is the section that says what you will
be able to see about other people's conversations. It matters more than the rest
of this document.

---

## 1. What you are running, in one paragraph

A relay is two small services in one binary, and neither of them is a blockchain
node. The first is a **mailbox**: wallets post encrypted chat envelopes to it
addressed to a Hacash address, and the wallet that owns that address collects
them by proving it holds the key
(`crates/dust-whisper/src/messenger_relay.rs`). The second is a **transaction
forwarder**: a wallet encrypts a signed transaction to the relay's own key, the
relay decrypts it and posts it to the fullnode it was configured with, so the
node sees the relay's address and not the wallet's
(`crates/dust-whisper/src/relay.rs:90-135`). Both live behind the same listener,
and starting the binary starts both.

It holds **no funds and no wallet**. It holds exactly one key of its own, and
that key's only power is to decrypt transactions people submit through it. It
does not sync a chain, does not validate anything, and cannot spend anyone's
money.

**Running one is optional and it is a favour to strangers.** Nobody is obliged
to. But the messenger does not work at all until somebody does, and the two
people talking have to be using the same one: there is no federation between
relays, and an envelope posted to your relay is only ever collected from your
relay. "Using the same one" is slightly stricter than "both have it in their
list". Section 7 says why, and it is an easy way for two people who did
everything else right to still fail to talk.

---

## 2. What it needs

Almost nothing while it is being used as intended, and the difference between
that and the worst case is entirely about memory. Read the memory section rather
than the table row.

| | |
|---|---|
| CPU | One core is plenty for signature checks. The cost that scales is a poll: the relay clones and returns a recipient's whole inbox in one response, with no paging (`peek`, `crates/dust-whisper/src/messenger_relay.rs:161-167`). |
| Memory | Everything the mailbox holds is in RAM, and the ceiling is far above the usual case. See below. |
| Disk | Effectively none. One 65 byte key file. The relay writes no message store at all. |
| Network | One inbound TCP port, default `127.0.0.1:8787`. Outbound to your fullnode, used only by the transaction forwarder, over whatever scheme the node URL you pass uses. Outbound to a recipient scales with what is sitting in their inbox, per the CPU row. |
| Blockchain | **None.** No full node on this box, no sync, no chain data. It only needs the URL of a node it can reach. |
| Wallet | **None.** No funds, ever. |
| Uptime | Undelivered mail is lost on restart, and that includes a restart the kernel decides on. See section 5 and the memory limit note below. |

### Memory, concretely

The mailbox is a `HashMap` in process memory
(`crates/dust-whisper/src/messenger_relay.rs:1`, `:61-65`). Nothing is written to
disk, so what bounds your memory is what the code caps:

- **200 undelivered envelopes per recipient address** (`MAX_PER_RECIPIENT`,
  `:21`).
- **20 of those per sender** (`MAX_PER_SENDER`, `:37`). What that does and does
  not protect is in section 8, and it is less than it sounds.
- **512 KiB per request** across the whole router (`MAX_SUBMIT_BODY_BYTES`,
  `crates/dust-whisper/src/relay.rs:24` applied at `:43`). A chat message is a
  few hundred bytes; that cap is sized for a large transaction, and it applies
  to envelopes too.
- **7 days** before an undelivered envelope expires (`TTL`, `:38`).
- **8192 outstanding inbox challenges** relay wide (`MAX_PENDING_CHALLENGES`,
  `:46`), each a few dozen bytes, each expiring after 120 seconds.

Now multiply the first cap by the third, which is the step the earlier version of
this section skipped. **200 envelopes at up to 512 KiB each is roughly 100 MB in
one inbox**, and nothing in the code stops a sender from using the whole
allowance on every message. Real chat is nowhere near that. A chat message is a
few hundred bytes, and the process itself idles at about 8 MB (measured on the
relay the section 5 transcripts came from), so a few dozen people talking
normally is a handful of megabytes and that is the number you will actually
observe. But the number an attacker can pick is the other one, and they do not
need your permission to pick it.

Three consequences of that shape, all of them about somebody else's mail:

**There is no cap on the number of distinct inboxes.** Memory tracks the number
of addresses written to since the process started, not the number of people you
meant to serve. Anyone can generate a keypair, so anyone can create inboxes. One
address can cost you about 100 MB, and addresses are free, so the ceiling on the
process is set by your machine and not by the relay.

**A memory limit is an availability decision, not a safety net.** Capping the
process is still the right thing to do, but be clear about what the cap does when
it is hit: the process dies, whether the supervisor kills it or an allocation
fails, and every undelivered message in it is gone, permanently and silently,
exactly as in the restart transcript in section 5. A memory limit converts "the machine falls over" into "everyone's waiting mail
disappears". Both of those are worth choosing on purpose.

**Expired mail is swept lazily.** The 7 day sweep runs on the inbox being
touched (`push`, `peek` and `ack` each call `list.retain`, `:80`, `:166`,
`:175`). An inbox nobody ever writes to or reads again keeps its bytes until the
process restarts.

So: set a memory limit knowing what it costs when it fires, watch the process
size rather than assuming it, and treat restarting as normal maintenance rather
than an incident.

### Build it

```bash
cargo build -p dust-whisper --features relay --bin dust-whisper-relay --release --locked
```

The `relay` feature is off in a default build and the binary declares
`required-features = ["relay"]` (`crates/dust-whisper/Cargo.toml:33-39`), so a
plain `cargo build` produces no relay. That is deliberate: the wallet links the
relay library to run one on loopback for its owner, and shipping a listener that
serves strangers should be something you asked for.

---

## 3. The one key

The relay has a single X25519 secret key, kept as 64 hex characters in
`relay.key` (`crates/dust-whisper/src/bin/dust-whisper-relay.rs:26-27`,
`:46-58`). It is generated on first run if the file is absent, and it is created
with mode `0600` on Unix. **On Windows no such mode is set**
(`:60-70`, the `#[cfg(unix)]` block), so on Windows the file inherits the
directory's permissions and putting it somewhere private is your job.

What the key does, exactly: wallets fetch it from `/whisper/v1/info` and encrypt
transactions to it, and the relay decrypts them with it before forwarding
(`crates/dust-whisper/src/relay.rs:63-70`, `:94`). It has **nothing to do with
chat**. Chat envelopes are encrypted between the two wallets and the relay holds
no key for them at all.

Two things follow.

**Anyone holding this file can decrypt transactions submitted to your relay**,
including any traffic they captured earlier. Do not put it in a repository, a
shared backup, or a container image.

**Losing it is nearly free.** Wallets re-fetch the public key from `/info` on
every submit (`crates/dust-whisper/src/client.rs:104-129`), so a new key is
picked up on the next attempt with no configuration change anywhere. Delete the
file, restart, carry on. Only submissions in flight during the swap fail, and
the wallet reports the failure rather than swallowing it.

You can also pass the key in the environment as `DUST_WHISPER_SECRET_HEX`
instead of a file (`bin/dust-whisper-relay.rs:22-23`), which is what you want
under systemd.

---

## 4. Running it

### Before anything: the port the wallet may already be using

The desktop wallet runs its own relay on loopback, and **`auto_start_relay`
defaults to on** (`crates/wallet-core/src/dust_whisper.rs:29-37`). If DUST
Whisper is enabled and any configured relay URL is a loopback one, the wallet
binds that URL's port itself
(`should_manage_relay`, `crates/wallet-tauri-common/src/desktop_relay.rs:99-105`).
The default in every example below is `127.0.0.1:8787`, and so is the desktop
relay field's own placeholder
(`apps/desktop/src/screens/PrivacyScreen.tsx`), so the two collide by default
rather than by accident. Starting this relay on a machine where such a wallet is
open fails, and the message is about a port rather than about the wallet:

```console
$ dust-whisper-relay --listen 127.0.0.1:8787 --node-url http://nodeapi.hacash.org
Error: Os { code: 10048, kind: AddrInUse, message: "Only one usage of each socket address (protocol/network address/port) is normally permitted." }
```

(That is Windows. Linux says `Address already in use (os error 98)`. The wallet's
own version of the same collision reads "Cannot start the local DUST relay at
{listen}. The port is already in use", `desktop_relay.rs:78-82`.)

Pick one before you go further:

- **Serving other people from this machine:** turn off "Auto-start local relay"
  on the wallet's Privacy screen, and let this relay own the port.
- **Both at once:** give this relay a different port with
  `DUST_WHISPER_LISTEN=127.0.0.1:8788` and leave the wallet's alone. They share
  nothing, including mail, which is rule 6 in section 9.

### The launcher script

```bash
scripts/START-DUST-WHISPER-RELAY.sh https://nodeapi.example.org
```

Windows:

```
scripts\START-DUST-WHISPER-RELAY.bat https://nodeapi.example.org
```

The one argument is **the fullnode URL the transaction forwarder posts to**, and
the script requires it rather than guessing, for a reason that is section 7: a
wallet refuses to broadcast through a relay whose node is not the wallet's own
node, and the mismatch is easy to create and annoying to diagnose. Type it the
way the wallets do, **scheme included**. `nodeapi.example.org` above is a
placeholder; the wallet's stock node is `http://nodeapi.hacash.org`, and the
`https` spelling of that same host is a different node as far as the check is
concerned.

Environment the script reads:

| Variable | Default |
|---|---|
| `DUST_WHISPER_LISTEN` | `127.0.0.1:8787` |
| `DUST_WHISPER_KEY_FILE` | `~/.hacash-dust-whisper/relay.key` |
| `DUST_WHISPER_SECRET_HEX` | unset; read by the binary itself if you set it |
| `DUST_WHISPER_RELAY_BIN` | unset; the release build is looked for first, then the debug build, `.exe` included. The error names every path it tried. |
| `RUST_LOG` | `info`. **Read section 6.4 before raising this.** |

### Or the binary directly

```bash
dust-whisper-relay \
  --listen 127.0.0.1:8787 \
  --node-url https://nodeapi.example.org \
  --key-file /var/lib/dust-whisper/relay.key
```

Those are all the flags there are
(`crates/dust-whisper/src/bin/dust-whisper-relay.rs:11-28`).

### Making it reachable from another machine

Everything above binds loopback, and so does every command in section 5. A
loopback relay is reachable by exactly one machine, which is fine for
development (section 10) and no use to anybody on a different one. **Two people
on two machines cannot test the messenger against it.** This is the section that
changes that.

**1. Decide where it listens.** Keep it on loopback and let a reverse proxy be
the only thing exposed. That is how the Hub and the witness are deployed, and it
is what the rest of this section assumes. If you have a reason to bind the
interface directly instead, the variable is `DUST_WHISPER_LISTEN`:

```bash
DUST_WHISPER_LISTEN=0.0.0.0:8788 \
  scripts/START-DUST-WHISPER-RELAY.sh http://nodeapi.example.org
```

The launcher notices any non loopback bind and says so before it starts. This is
what that run printed:

```console
  NOTE: binding 0.0.0.0:8788. That is not 127.0.0.1 or localhost, so treat
  this listener as reachable by other machines.
```

Binding directly still leaves you serving plain HTTP, which section 9 rule 2
says never to do in public. It is a step on the way, not a destination.

**2. Terminate HTTPS in front of it.** The relay speaks HTTP and has no TLS of
its own. Two configurations that do the job, with `relay.example.org` standing
in for your name and `127.0.0.1:8787` for whatever loopback address the relay is
actually listening on.

Caddy, which obtains and renews the certificate itself:

```
relay.example.org {
    reverse_proxy 127.0.0.1:8787
}
```

nginx, with the certificate from wherever you get certificates:

```nginx
server {
    listen 443 ssl;
    server_name relay.example.org;

    ssl_certificate     /etc/letsencrypt/live/relay.example.org/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/relay.example.org/privkey.pem;

    # The wallet appends fixed paths to the base URL you publish
    # (/whisper/v1/... , crates/dust-whisper/src/protocol.rs:4-9), so the
    # proxy must pass the path through unchanged.
    location / {
        proxy_pass http://127.0.0.1:8787;
        proxy_set_header Host $host;

        # Read section 6.4 first. The default access log records the inbox
        # challenge query string, which is a recipient's address and the
        # moment they checked their mail. This turns that off; a retention
        # policy you actually chose is also a valid answer.
        access_log off;
    }
}
```

Neither config is exercised by this repository's tests, and no proxy is shipped
with the relay. What is exercised is the relay behind them, and step 4 is the
check that tells you the pair works.

This is also the only place you can put a rate limit, because the relay has
none. Section 8 says what that costs you if you skip it. The Hub's guide asks
for the same thing of its own proxy, in the same words: publish only 443 and
apply "per-IP rate, connection and request-size limits"
(`docs/HUB-OPERATOR.md`, its hardening section). In nginx that is `limit_req`
and `limit_conn`; Caddy needs a rate limiting module for the equivalent. What
the right numbers are depends on how many people you serve, and this document
will not invent them for you.

**3. Open one port, and only one.** Inbound 443 to the proxy. Leave 8787 closed
to the outside: if it is reachable, everything section 6 describes is also
reachable in clear, with the HTTPS in front of it doing nothing.

**4. Verify from a different machine**, not from the relay's own. The relay
answering on its own loopback proves nothing about any of the three steps above.

```console
$ curl -sS https://relay.example.org/whisper/v1/info
{"v":1,"pubkey":"...","node_url":"http://nodeapi.example.org"}
```

If that returns the same JSON your own loopback probe returns (section 5), the
address is publishable. If it hangs, it is the firewall; if it returns a proxy
error page,
the proxy is not reaching the relay; if TLS fails, it is the certificate. Fix it
here rather than after somebody has put the URL in their wallet.

### Why the TLS is not optional, and not enforced

The wallet only half enforces it. The transaction path refuses a non loopback
relay URL that is not HTTPS (`crates/dust-whisper/src/client.rs:197-214`).
**The messenger path does not check.** `messenger_send` walks the configured
relay URLs and posts to whatever is there
(`crates/wallet-core/src/messenger.rs:340-353`,
`crates/dust-whisper/src/messenger_client.rs:15-37`), with no scheme check on
the way. So if you publish an `http://` address, wallets will use it for chat,
and every network between them and you sees exactly what section 6 says you see.
Nothing in the code stops that. The TLS is yours to install.

### It has no service unit of its own

There is no packaged systemd unit for the relay. The Hub's
(`scripts/hpay-fast-pay-hub/hpay-fast-pay-hub.service`) is a reasonable model to
copy for the hardening: unprivileged account of its own, no write access
anywhere except the key file's directory, and a memory limit.

---

## 5. Checking it works

Every transcript below was taken from one relay started by
`scripts/START-DUST-WHISPER-RELAY.sh http://nodeapi.hacash.org` on the default
listen address, with the values it really printed. These are all loopback checks,
run on the relay's own machine. They say the process works. They say nothing at
all about whether anybody else can reach it, which is step 4 of section 4.

**It answers, and it tells you its identity.**

```console
$ curl -sS http://127.0.0.1:8787/whisper/v1/info
{"v":1,"pubkey":"JmPxZ9QznfA8wNQaL97Oj3FBamIJbFguP3q058Wos1o=","node_url":"http://nodeapi.hacash.org"}
```

Check `node_url` is the node you meant, **including its scheme**. Wallets compare
that string to their own node and refuse to broadcast if it differs, and the
comparison keeps the scheme (section 7). The relay's own default is
`https://nodeapi.hacash.org` while the wallet's default node is
`http://nodeapi.hacash.org` (`DEFAULT_NODE_URL`,
`crates/wallet-core/src/settings.rs:37`), so those two do not match and a relay
left on the binary's default blocks broadcast for every wallet on stock settings.
That is why the launcher makes you pass the URL and why this transcript shows
`http`.

**The mailbox issues challenges.** Substitute any address; an inbox that does not
exist is fine here.

```console
$ curl -sS "http://127.0.0.1:8787/whisper/v1/messenger/challenge?to=1G7ZT14izrpWCHgMg9rgRHgntWdb7nRQ3"
{"nonce":"4eb31e86f902fdd80dfeb22bb3218c7a","expires_at":"2026-08-23T00:21:30.331686700+00:00"}
```

**It refuses mail nobody signed.** This is the check that stops a stranger
posting a message that a recipient's wallet files as coming from a trusted
contact.

```console
$ curl -sS -X POST http://127.0.0.1:8787/whisper/v1/messenger/send \
    -H 'content-type: application/json' \
    -d '{"envelope":{"v":1,"id":"probe-1","to":"1AVRUYpQ4rjRp2SDvxjhxDCfpLQKsFhxaS",
         "from":"1LsQLdBnVKnLcSbhciqEFrxYzKfLqmpDhc","nonce":"00","ciphertext":"00",
         "sent_at":"2026-08-22T00:00:00Z"}}'
{"ok":false,"err":"envelope is not signed by the key its sender address derives from"}
```

**It refuses an inbox claim nobody can sign for.** Note `auth_ok`: a refusal and
an empty mailbox are different answers, and the wallet reports them differently.

```console
$ curl -sS -X POST http://127.0.0.1:8787/whisper/v1/messenger/inbox \
    -H 'content-type: application/json' \
    -d '{"to":"1AVRUYpQ4rjRp2SDvxjhxDCfpLQKsFhxaS","claimant_pubkey":"00","nonce":"00","signature":"00"}'
{"messages":[],"auth_ok":false}
```

**A restart empties the mailbox, and that is not a bug.** Undelivered mail lives
in memory only. This needs a signed envelope, so it is not a curl one liner: post
a properly signed envelope, claim the inbox, restart the process, and claim it
again with a fresh challenge. The envelope fields are elided below for width;
nothing else is edited.

```console
before restart  {"messages":[{"v":1,"id":"roundtrip-1","to":"1BCNHfp6DZCHZ9cPRPDWsh6VfmgHPRZUsQ",
                "from":"1AZtoSXEw8dzR98yWuqtDHyJLknMzh5zPq", ...}],"auth_ok":true}
after restart   {"messages":[],"auth_ok":true}
```

The relay's own key survives, so `/info` returns the same
`JmPxZ9QznfA8wNQaL97Oj3FBamIJbFguP3q058Wos1o=` after that restart as before it;
only the mail is gone. Anything a recipient had not collected is
gone with it, permanently, and neither wallet is told. Say so to the people who
use your relay, and restart on purpose rather than by surprise. A process killed
for exceeding a memory limit is the same transcript with nobody deciding on it
(section 2).

**The acceptance test is a real message, and it needs two machines.** Finish
section 4 first: publish the HTTPS address, put it in the relay field of two
wallets on two machines, send from one and collect on the other. Everything above
is loopback and proves only that the process is healthy. Nothing above proves
delivery end to end; that does.

---

## 6. What you can see, and what that makes you

This is the section that decides whether you should run one.

On chat, the wallet tells its users this from their side, in
`apps/desktop/src/messengerPrivacy.ts` and the mobile equivalent, and this
section says the same things from yours. If the two ever disagree, one of them is
lying to somebody. Sections 6.1 to 6.4 are the chat side and they match.

Section 6.5 is the transaction side, and it did not match until the sentence
below was added to both shells. What the wallet said about a remote relay was
that it "can hide your IP from the full node", which is the half of the trade
that sounds good. It now also says that the encryption ends at the relay and
that the operator sees the whole transaction
(`apps/desktop/src/screens/PrivacyScreen.tsx`,
`apps/mobile/src/components/WhisperScreen.tsx`, held by the
`relaySourcing.test.ts` case of the same name in each app). If you find that
sentence gone from a wallet, then the users of your relay have not been told
what 6.5 tells you, and saying it yourself is the only thing that fixes it.

### 6.1 You see who is talking to whom, and when

The envelope carries `to`, `from`, `from_pubkey`, `id`, `sent_at` and the
ciphertext (`crates/dust-whisper/src/protocol.rs:61-84`). Everything except the
ciphertext is in clear, and it has to be: the relay routes on `to`, and it
checks the sender's signature against `from` before accepting anything
(`send_handler`, `crates/dust-whisper/src/messenger_relay.rs:209-224`).

So for every message crossing your machine you can read: both addresses, the
sender's public key, the time the sender claims, the time it actually arrived,
and its size. You also see, from the inbox polling, roughly when each recipient
is awake and collecting.

That is the social graph. It is the part of a private messenger that is usually
worth more than the messages.

### 6.2 You cannot read sealed bodies. You can read the rest

A sealed message ("v2") is encrypted with a key derived by ECDH between the two
accounts (`crates/wallet-core/src/messenger_crypto.rs:136-152`, keyed through
`derive_message_key` at `:71`). You hold neither secret and cannot derive it.
Those bodies are genuinely closed to you.

An unsealed message ("v1") is a different story, and pretending otherwise is the
one thing this document will not do. Its key is
`SHA256(domain || lower_address || higher_address)`
(`crates/wallet-core/src/messenger_crypto.rs:51-63`), and both addresses are
sitting in the envelope in clear. **Any relay operator can decrypt every v1
message that passes through, with no key material and no privileged position
beyond having the envelope.** You do not need the code; you need the two
addresses that are printed on the outside.

A wallet sends v1 when it has not yet learned the other party's public key, which
is the case until that person has written back. The wallet says exactly this to
its user: "the relay operator can read what you send here. That changes once they
write to you" (`apps/desktop/src/messengerPrivacy.ts`). It also counts the
messages in a thread that are not known to be sealed and tells the user to treat
those as readable by you.

So the honest statement of your position is: **everything one person writes to
another before that other has written back is readable by you.** The wallet
learns a contact's public key from an envelope that contact sent
(`store.learn_peer_key`, `crates/wallet-core/src/messenger.rs:468`, from an
envelope this wallet collected), and the Messages screen offers no other way to
supply one, so that opening stretch is not a rare case. It is how every new
conversation starts.

**And the end of that stretch is in your hands, which is the part that is easy to
miss.** The wallet switches to sealed bodies only once it holds the peer's key
(`crates/wallet-core/src/messenger.rs:316-323`), and it can only get that key
from an envelope you delivered. An operator who quietly drops one side's mail
keeps both sides sending v1 forever, and both wallets keep reporting a normal,
successful send: a send succeeds as soon as any relay accepts the envelope
(`:341-353`), and there is no delivery receipt anywhere in the poll path
(`messenger_poll_inbox`, `:404-534`). The user's screen reads "Nothing they have
sent has reached this wallet" (`apps/desktop/src/messengerPrivacy.ts:36`), which
a person reads as "my friend has not written back", not as "my relay is holding
their mail".

Do not write this off as a thing you would never do. It is the reason the
sentence above stops where it does. "Everything after it is closed to you" would
be a claim about your own future conduct, not about the code, and this document
does not make those.

### 6.3 The inbox authentication does not apply to you

A caller has to prove they hold the key an address derives from before the relay
hands over that inbox, and again before it deletes anything
(`verify_inbox_auth`, `crates/dust-whisper/src/messenger_auth.rs:98`, which
checks the claimant's key derives to the address at `pubkey_matches_address`,
`:26`). That
check protects an inbox from other people on the network. It does not protect it
from you: the mail is in your process's memory, and it is your process.

The same is true of anything the relay refuses to do to a message. Nothing stops
the operator from dropping a message, delaying it, keeping a copy, or answering
an inbox claim with less than what is waiting. Wallets can notice some of this
(a refused claim is reported as a refusal rather than as an empty inbox,
`apps/desktop/src/messengerPoll.ts`), and they cannot notice most of it. The
people using your relay are trusting you not to, and they have no way to check.

### 6.4 Your logs are the leak you did not plan

The relay writes no message store, which is genuinely good. But "not written
down by the relay" is not "not written down".

The inbox challenge carries the address in the **query string**
(`fetch_challenge`, `crates/dust-whisper/src/messenger_client.rs:40-50`), so a
reverse proxy's default access log records who is collecting mail, with
timestamps, forever, in a file the relay knows nothing about. Configure that
before you publish the URL, not after. The nginx block in section 4 turns that
log off, which is one of the two defensible answers; a retention policy you
chose on purpose is the other.

The relay's own log does the same if you turn it up. At `RUST_LOG=info` requests
are not logged. At `debug`, the `TraceLayer`
(`crates/dust-whisper/src/relay.rs:44`) prints the full URI:

```console
DEBUG request{method=GET uri=/whisper/v1/messenger/challenge?to=1G7ZT14izrpWCHgMg9rgRHgntWdb7nRQ3 version=HTTP/1.1}: tower_http::trace::on_request: started processing request
```

That line is a person's address and the moment they checked their mail. Debug
logging is for debugging, and a relay left at `debug` is keeping records its
users would not expect it to keep.

### 6.5 You decrypt transactions

Separate from chat, and easy to forget because it is the same process. The
transaction forwarder decrypts what wallets send it
(`crates/dust-whisper/src/relay.rs:94`) and posts the plaintext to your node
(`:109-121`). Between those two lines you have the whole signed transaction:
amounts, addresses, everything on it. The privacy that path buys the user is
against the **node**, and it buys it by giving all of it to **you**.

It is also worth knowing what you cannot be tricked into: the relay always
forwards to the node URL you configured and never to a target named by the
client (`:103`), so nobody can use your relay as an outbound proxy to somewhere
else.

### 6.6 In one sentence

**Running a relay means holding other people's metadata, and the early part of
their conversations in plaintext.** If that is not a thing you want to hold,
run a relay for yourself and people you already know, or do not run one. Both
are respectable. Publishing a relay to strangers while telling them it is
private is not.

---

## 7. Pointing a wallet at it

What a user needs from you is one line: the base URL, for example
`https://relay.example.org`. No key, no attestation, no registration.

**Desktop:** Privacy screen, "Relay URLs (one per line)", then Save DUST
Whisper. **Mobile:** More, then DUST Whisper, same field.

Four things that will otherwise cost somebody an evening:

**Both parties need the same relay, and for the sender it must be the first one
that accepts.** The mailbox is per relay and relays do not talk to each other.
Note the asymmetry, because "just add my relay to your list" is not always enough
advice: sending stops at the **first** relay that accepts the envelope
(`crates/wallet-core/src/messenger.rs:341-353`, which breaks out of the loop on
the first success), while polling tries **every** relay in the list
(`:416`, no break). So somebody whose list is `[their own relay, yours]` delivers
to their own relay and never to yours, even though yours is in the list, and
their correspondent polling only yours sees nothing. When you tell a user to add
your relay, tell them where in the list: above any relay their correspondent is
not also using.

**The node URL has to match, for transactions, scheme included.** The wallet
fetches `/info`, compares your `node_url` to its own node, and if they differ it
marks your relay offline with "Relay targets X, but this wallet uses Y. Broadcast
blocked." (`crates/wallet-core/src/dust_whisper.rs:56-80`, comparison at
`node_urls_match`, `crates/dust-whisper/src/client.rs:165-179`). The comparison
normalises a trailing slash, a query, a fragment and case, and it keeps
everything else, **including `http` versus `https`**: it compares
`url.to_string()`, and the scheme is in that string. `https://nodeapi.hacash.org`
and `http://nodeapi.hacash.org` are a mismatch, and since the wallet's stock node
is the `http` one (`DEFAULT_NODE_URL`, `crates/wallet-core/src/settings.rs:37`)
and the relay binary's own `--node-url` default is the `https` one
(`crates/dust-whisper/src/bin/dust-whisper-relay.rs:17-19`), that is the mismatch
you are most likely to ship. Chat is unaffected by any of this, because the
messenger endpoints never look at `node_url`, so the confusing state is real: a
red relay row on the Privacy screen while messages keep working. Publish the node
URL you forward to, character for character, alongside your relay URL.

**Tell them to paste the URL without a trailing slash.** The chat path trims one
(`base_url`, `crates/dust-whisper/src/messenger_client.rs:11-13`); the
transaction path does not (`format!("{relay_url}{INFO_PATH}")`,
`crates/dust-whisper/src/client.rs:182`), so `https://relay.example.org/` becomes
a request for `//whisper/v1/info`, and that is a 404, not a relay:

```console
$ curl -sS -o /dev/null -w '%{http_code}\n' "http://127.0.0.1:8787//whisper/v1/info"
404
$ curl -sS -o /dev/null -w '%{http_code}\n' "http://127.0.0.1:8787/whisper/v1/info"
200
```

The symptom is the same as the one above and has a different cause: relay row
red, chat working.

**HTTPS or it is not private.** Section 4. The messenger path will use a plain
`http://` URL without complaint.

---

## 8. What you are taking on

**Availability, with a sharp edge.** Undelivered mail is in memory and nowhere
else, so a restart drops it, a crash drops it, and an out of memory kill drops
it. A message not collected within 7 days expires. Neither sender nor recipient
is told, in any of those cases. That is a weaker promise than people expect from
a mailbox, and it is your job to say so rather than let them find out.

**Other people's metadata.** Section 6. Decide your logging policy before you
publish the URL.

**Abuse, and the cap that does less than it sounds like.** Anyone can generate a
keypair, so anyone can send, and that second fact is what undoes the first
defence. Be precise about what `MAX_PER_SENDER` buys
(`messenger_relay.rs:21-37`), because the short version of this paragraph used to
be wrong:

- **A flood from one identity costs only itself.** Once a sender holds its 20
  slots in an inbox, its next message evicts its own oldest. Mail already waiting
  from somebody else is untouched, however long the flood runs. Held by
  `a_flood_from_one_key_evicts_only_its_own_messages` in
  `crates/dust-whisper/tests/messenger_inbox_flood.rs`.
- **A flood from many identities can no longer destroy stored mail.** It used
  to: eviction took from whichever sender held the **most** slots, and after a
  wide flood of one-message throwaway keys that is the person the owner actually
  talks to, so a friend's eleven waiting messages were cut to at most one by 260
  keypairs, every envelope properly signed and no bug exploited. A sender that
  holds nothing in a full inbox is now refused instead of being allowed to
  displace what is already there, so a deletion no longer costs the price of a
  key (`a_flood_from_many_keys_cannot_evict_the_genuine_correspondent`, same
  file, which asserts all eleven survive).
- **What that costs, and it is a real cost.** A genuine NEW correspondent
  cannot reach an inbox that is already full, and will be told the inbox is
  full rather than quietly dropped. An inbox only fills when its owner has not
  collected for a while, and collecting empties it, so this is a delay for
  somebody writing to a person who is not reading. Deleting the mail of the
  person they do read was not a delay.

The 512 KiB body limit bounds a single request and does not bound the total
(section 2). Nothing rate limits by IP, and nothing authenticates who is allowed
to use your relay. If you want either, it belongs in the reverse proxy in front
of it. It does not exist in the relay, and no cap the relay has is a substitute
for it.

**No money.** Your relay holds no funds and cannot move anyone's. The worst case
for the relay key is that transactions submitted through you can be read, which
is already true of you (section 6.5).

**A service for other people.** You are running a message service that strangers
may come to depend on. What that means where you live is yours to work out
before you advertise it, not after.

---

## 9. Things that must never be done

1. **Never publish a relay URL you are not going to keep running.** An address
   that stops answering is worse than an empty field: the wallet's messages stop
   arriving with no explanation the user can act on.
2. **Never serve plain HTTP to the public.** The messenger path does not enforce
   TLS, so nothing but you will stop it.
3. **Never leave the relay at `RUST_LOG=debug`.** Section 6.4.
4. **Never put `relay.key` in a repository, a shared backup, or an image.**
   Anyone holding it can decrypt every transaction submitted to you, including
   traffic captured before it leaked.
5. **Never tell users their messages are unreadable to you.** The sealed ones
   are. The unsealed ones are not, and every conversation starts unsealed.
6. **Never run two relays behind one address expecting them to share a
   mailbox.** There is no shared store. Half the mail lands on a machine the
   recipient's next poll does not reach.
7. **Never tell users their undelivered mail is safe with you.** It is in RAM
   only. A restart, a crash or a memory limit firing deletes it silently, and
   nobody is told. Section 8.
8. **Never point people at a relay URL you have only tested from the relay's own
   machine.** Loopback works long before anything else does. Section 4, step 4.
9. **Never treat the per sender cap as abuse protection.** It stops one loud
   identity and does nothing about a hundred cheap ones. Section 8.

---

## 10. Local development

If you just want a relay to develop against, do not follow this document. The
desktop wallet runs one for you: turn on DUST Whisper and "Auto-start local
relay" on the Privacy screen, with `http://127.0.0.1:8787` in the relay field.
Auto-start is on by default (`crates/wallet-core/src/dust_whisper.rs:29-37`), so
usually the only thing you have to type is the URL. The wallet then serves the
relay in process, using its own node URL and a key under the wallet data
directory (`crates/wallet-tauri-common/src/desktop_relay.rs:47-98`). It refuses
to do this for anything except a loopback address (`:99-105`, `is_local_relay_url`
in `crates/wallet-core/src/dust_whisper.rs:46-54`), and it is not available on
mobile.

Because that is on by default, it is also the thing most likely to be holding
port 8787 when you start the relay from section 4 on your own laptop. Turn it off
there, or move one of the two to another port. Section 4 opens with that.

That is a relay only your own machine can reach, which is the right thing for a
laptop and no use at all to anyone else. Two people testing the messenger need
one relay that both machines can reach: bind it, put a proxy and a certificate in
front of it, open one port, and check it from the other machine. That is
"Making it reachable from another machine" in section 4, and it is four concrete
steps rather than a pointer.

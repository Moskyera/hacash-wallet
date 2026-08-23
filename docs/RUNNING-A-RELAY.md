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
| CPU | One core is plenty for signature checks. The cost that scales is a poll: the relay clones and returns a recipient's whole inbox in one response, with no paging (`peek`, `crates/dust-whisper/src/messenger_relay.rs`). |
| Memory | Everything the mailbox holds is in RAM, and the ceiling is far above the usual case. See below. |
| Disk | Effectively none. One 65 byte key file. The relay writes no message store at all. |
| Network | One inbound TCP port, default `127.0.0.1:8787`. Outbound to your fullnode, used only by the transaction forwarder, over whatever scheme the node URL you pass uses. Outbound to a recipient scales with what is sitting in their inbox, per the CPU row. |
| Blockchain | **None.** No full node on this box, no sync, no chain data. It only needs the URL of a node it can reach. |
| Wallet | **None.** No funds, ever. |
| Uptime | Undelivered mail is lost on restart, and that includes a restart the kernel decides on. See section 5 and the memory limit note below. |

### Memory, concretely

The mailbox is a `HashMap` in process memory
(`crates/dust-whisper/src/messenger_relay.rs`). Nothing is written to disk, so
what bounds your memory is what the code caps. Every one of these is a refusal
rather than a deletion, with one exception named as such below: a relay with no
room for mail says so and keeps what it already holds.

- **200 undelivered envelopes per recipient address** (`MAX_PER_RECIPIENT`).
- **20 of those per sender** (`MAX_PER_SENDER`). What that does and does not
  protect is in section 8.
- **16 KiB of ciphertext per envelope** (`MAX_CIPHERTEXT_HEX`, counted in hex
  characters, so 32768 of them). The wallet will not send a body over 4 KiB
  (`MAX_MESSAGE_BODY_BYTES`, `crates/wallet-core/src/messenger.rs`), so this is
  generous for anything a person types.
- **5,000 distinct mailboxes** (`MAX_INBOXES`), **20,000 undelivered envelopes**
  (`MAX_TOTAL_ENVELOPES`) and **48 MiB of stored envelope bytes**
  (`MAX_TOTAL_BYTES`), relay wide.
- **7 days** before an undelivered envelope expires (`TTL`).
- **8192 outstanding inbox challenges** relay wide (`MAX_PENDING_CHALLENGES`),
  each a few dozen bytes, each expiring after 120 seconds. A full table evicts
  its own oldest entry rather than refusing the next caller.
- **512 KiB per request** across the whole router (`MAX_SUBMIT_BODY_BYTES`,
  `crates/dust-whisper/src/relay.rs`). That one is sized for a large
  transaction on the submit path, and is no longer what bounds a chat envelope.
- **20,000 addresses in the key directory** (`MAX_DIRECTORY_ENTRIES`), each one
  an address and a 66 character key, expiring **30 days** after that address was
  last seen sending (`DIRECTORY_TTL`). Call it 3 MiB full. **This is the one
  that evicts rather than refuses**, and it is the exception to the sentence
  above: a full table drops its stalest entries in a batch to make room for the
  address that just sent. That is deliberate and it is safe for a reason worth
  stating, because it is not the reason the mail caps refuse. Dropping a
  directory entry loses nothing anybody is owed: the relay then answers "no key"
  for that address, which is the answer it gave before the table existed, and
  the wallet that asked falls back to v1 and tells its user the message is not
  sealed. There is no state here whose loss can be turned into a false claim,
  which is exactly what makes eviction the right choice here and the wrong
  choice for stored mail. What the directory is for is section 6.2; what it
  costs you to run is section 8.

**So the messenger side of the process cannot exceed about 48 MiB of stored
mail** plus a few megabytes of overhead. Real chat is nowhere near that: a chat
message is a few hundred bytes, the process idles at about 8 MB (measured on the
relay the section 5 transcripts came from), and a few dozen people talking
normally is a handful of megabytes.

Two earlier claims in this section were wrong and are worth naming, because a
relay running an older build still has both:

**"There is no cap on the number of distinct inboxes" is no longer true.** `to`
used to be any non-empty string, so a single keypair could invent mailboxes by
the thousand and the per-sender share multiplied instead of binding. It has to
be a version-0 Hacash account address now, which is the only kind of address a
key can ever sign for and therefore the only kind whose inbox anyone could ever
empty (`is_claimable_address`; held by
`mail_can_only_be_left_for_an_address_a_key_could_collect` in
`crates/dust-whisper/tests/messenger_relay_abuse.rs`). With `MAX_INBOXES` on top
of that, memory tracks the number of real mailboxes and not the attacker's
imagination.

**"200 envelopes at up to 512 KiB each is roughly 100 MB in one inbox" is no
longer true either.** The per-envelope ceiling makes the worst case for one
inbox about 3 MiB, and the relay-wide byte budget bounds the rest
(`an_oversized_body_is_refused`, same file).

**A memory limit is still an availability decision, not a safety net.** Capping
the process is still the right thing to do, and be clear about what the cap does
when it is hit: the process dies, whether the supervisor kills it or an
allocation fails, and every undelivered message in it is gone, permanently and
silently, exactly as in the restart transcript in section 5.

**Expired mail is still swept lazily.** The 7 day sweep runs on the inbox being
touched (`push`, `peek` and `ack` each prune the one list they are working on).
An inbox nobody ever writes to or reads again keeps its bytes until the process
restarts, and it counts against `MAX_TOTAL_BYTES` until then.

**The directory's 30 days is lazy in the same way, and deliberately so.** An
entry past its TTL is never answered with, from the moment it expires: the
lookup checks the one entry's age and refuses it, so what you serve is correct
to the second. The storage it occupies is reclaimed when the table next fills,
not on a timer, because sweeping the whole table is work and the only request
that could trigger it is the unauthenticated one. That is the trade: at most
20,000 entries of memory, and never an answer you should not have given.

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

Half of that is now proven every time the test suite runs, and the half that is
proven is the half about the software.
`crates/wallet-tauri-common/tests/messenger_two_wallets_one_relay.rs` starts a
relay through the same Settings command a person presses, opens two wallets with
separate vaults and separate message stores, and drives both of them through
Tauri IPC: one sends by address, the other polls and reads the plaintext, replies
sealed with ECDH, and the first reads the reply. It then closes both wallets and
reopens them from disk to show the conversation is still there. A recorder on the
wire keeps every envelope and shows what you as an operator could do with it: the
key derived from the two addresses opens the first message of a conversation and
opens neither of the sealed ones. What that run does not cover is your network:
the public address, the certificate, the proxy, the open port and the two
machines. That part is still yours to check, and section 4 is how.

Two more suites run beside it, and they are the ones that speak to what your
machine is exposed to rather than to whether the messenger works.
`crates/dust-whisper/tests/messenger_relay_abuse.rs` attacks the shipped router
over a socket with nothing but an HTTP client: a replayed envelope, a stale one,
an invented recipient, an oversized body, and a flood of unauthenticated
challenge requests. `crates/wallet-tauri-common/tests/messenger_wedged_inbox.rs`
floods a real inbox with two hundred correctly signed envelopes of noise and then
shows, through the same commands the screens invoke, that the owner is told what
happened and that the person they talk to can reach them again after one poll.
Every one of those five things worked before the checks in section 2 and section
8 existed.

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
(`send_handler`, `crates/dust-whisper/src/messenger_relay.rs`).

So for every message crossing your machine you can read: both addresses, the
sender's public key, the time the sender claims, the time it actually arrived,
and roughly its size. You also see, from the inbox polling, roughly when each
recipient is awake and collecting.

"Roughly its size" used to be "its size", exactly: AES-GCM ciphertext is as long
as its plaintext plus a 16 byte tag, so fifty more characters typed were fifty
more bytes on your wire, measured rather than estimated. Bodies are padded to a
256 byte boundary before encryption now
(`PAD_BUCKET`, `crates/wallet-core/src/messenger_crypto.rs`, held by
`body_length_does_not_leak_character_for_character`), so what you read is a
bucket rather than a character count. That is a smaller leak, not no leak, and it
does nothing at all about the rest of this section.

**You also see who somebody is about to write to, and this reaches further than
the mail does.** Before a wallet sends a first message it asks for a key for the
recipient (section 6.2), and it asks the relays it is configured with one after
another until an answer survives checking. The send itself stops at the first
relay that accepts the envelope. Those are not the same list. So if you are
second in somebody's relay list, you can be told "this person is about to write
to address B" for a conversation whose envelopes you will never carry and whose
existence you would otherwise have no way to know about.

The wallet says this to its user in the same breath as the benefit
(`apps/desktop/src/messengerPrivacy.ts` and the mobile copy of it, held by the
`names the cost of asking, not only the benefit` case in
`messengerPrivacy.test.ts`), because it is not a cost the sender pays alone. The
question is a POST rather than a GET, so the address does not land in your access
log by default (`the_address_asked_about_is_never_put_in_the_url`,
`crates/dust-whisper/tests/messenger_pubkey_directory.rs`). What you do with it
after that is section 6.4.

That is the social graph. It is the part of a private messenger that is usually
worth more than the messages.

### 6.2 You cannot read sealed bodies. You can read the rest

A sealed message ("v2") is encrypted with a key derived by ECDH between the two
accounts (`encrypt_body_v2` and `derive_message_key`,
`crates/wallet-core/src/messenger_crypto.rs`). You hold neither secret and
cannot derive it.
Those bodies are genuinely closed to you.

An unsealed message ("v1") is a different story, and pretending otherwise is the
one thing this document will not do. Its key is
`SHA256(domain || lower_address || higher_address)`
(`pair_key_v1`, `crates/wallet-core/src/messenger_crypto.rs`), and both addresses are
sitting in the envelope in clear. **Any relay operator can decrypt every v1
message that passes through, with no key material and no privileged position
beyond having the envelope.** You do not need the code; you need the two
addresses that are printed on the outside.

A wallet sends v1 when it holds no public key for the other party and cannot get
one it is able to check. Until recently that was every opening message without
exception, because a wallet only ever learned a contact's key from an envelope
that contact had already sent it (`store.learn_peer_key`,
`crates/wallet-core/src/messenger.rs`) and no screen offered another way to supply
one. **The first message of every conversation on your relay was readable by
you.**

That is no longer automatic, and the reason is worth understanding before you
decide how you feel about the endpoint it added.

**Your relay now serves the last public key it saw for an address**
(`MESSENGER_PUBKEY_PATH`, `pubkey_handler`,
`crates/dust-whisper/src/messenger_relay.rs`). It is a POST carrying the address
in a JSON body, deliberately not a GET carrying it in a query string, so that
asking does not write the address into your access log or into the log of any
proxy you put in front of this. It is not being given anything new to hold:
`from_pubkey` rides in clear on every envelope you have ever accepted and you
already check it against `from` before storing the envelope. The directory is
your relay writing that down for up to thirty days instead of discarding it when
the envelope is collected, capped at 20,000 addresses (section 2, which also says
what happens when that cap is reached and why eviction is right there and wrong
for mail).

**The wallet asking does not trust your answer, and this is the whole point.** A
Hacash account address is `base58check(0 || RIPEMD160(SHA256(pubkey)))`
(`sys::Account::get_address_by_public_key`), so a public key that derives to
address X is X's key: producing a different one is a second preimage on that
hash, not something an operator can decide to do. Before sealing anything, the
sending wallet re-derives the address from whatever you served and discards it
unless it matches the address it asked about (`verified_peer_pubkey`,
`crates/wallet-core/src/messenger_crypto.rs`, and `lookup_peer_key`,
`crates/wallet-core/src/messenger.rs`).

So there are exactly two things you can do to a wallet that asks, and neither of
them helps you:

- **Answer nothing.** The wallet falls back to v1 and marks the message not
  sealed. That is where every sender already was.
- **Answer with a key of your own.** It fails the derivation check, is treated as
  no answer at all, and the wallet falls back to v1 and marks the message not
  sealed. It never seals to a key it has not itself verified.

Both are held by
`crates/wallet-tauri-common/tests/messenger_two_wallets_one_relay.rs`, which runs
a recorder in the position you occupy: it forges a directory answer, watches the
send fall back, and reads that message. It also watches the honest case and
cannot read that one.

There is a third thing, and it is time rather than secrets: **answer very
slowly.** A relay that accepts the connection and never replies used to cost the
sender the shared client's twenty second budget, and three of them a full minute,
in front of a person who had pressed Send, on the first message of every
conversation and on every message after it until the other side wrote back,
because a lookup that finds nothing writes nothing down. The lookup now owns a
six second budget for the whole relay list and gives no single relay more than
three seconds of it, and running out is the same outcome as having no key:
v1, sent, marked not sealed (`PEER_KEY_LOOKUP_BUDGET`,
`crates/wallet-core/src/messenger.rs`, held by
`a_relay_list_that_never_answers_cannot_hold_a_send_open`). Your relay being slow
still costs your users a wait; it can no longer cost them a minute of one.

**What this costs you to serve, and it is not nothing.** Answering "do you have a
key for this address" tells the asker that the address has sent through your
relay inside the retention window. You already knew that; the asker did not. The
lookup is unauthenticated, because a wallet opening a first conversation is by
definition a stranger to the address it is asking about, so anyone can probe any
address one at a time and learn whether it is one of your users. The key itself
is not the secret being given away: it is on the chain the moment that account
signs anything. The association between an address and your machine is.

**And what it tells you, which is the other half and belongs to somebody else.**
Being asked is itself a fact: it tells you that whoever asked is about to write
to that address, and because a wallet asks every relay it is configured with
while sending to only the first that accepts, you can learn that about
conversations you will never carry. That is in section 6.1 with the rest of the
social graph, and it is on the sender's screen. It is worth reading twice before
you decide your logging policy, because it is the one thing here that a person
who is not your user pays for.

Weigh it against what it replaces, which is the honest comparison: without it,
the opening message of every conversation on your relay arrives in a form you can
read in full, and you learn the same address anyway from the envelope that
follows a second later. Requiring the asker to authenticate would not fix the
probing, because keys are free, and it would hand you a record of who asked about
whom. If you would rather not run the directory at all, an operator who does not
serve that endpoint costs their users exactly the old behaviour and nothing more.

**The end of the unsealed stretch is still partly in your hands.** A wallet that
holds no key and gets no usable answer from any relay keeps sending v1, and both
wallets keep reporting a normal, successful send: a send succeeds as soon as any
relay accepts the envelope (`messenger_send`), and there is no delivery receipt
anywhere in the poll path (`messenger_poll_inbox`). An operator who serves an
empty directory and quietly drops one side's mail keeps both sides on v1 forever.
The user's screen says the wallet holds no key for this contact and that the
operator can read what they send if no key survives checking
(`apps/desktop/src/messengerPrivacy.ts`), which a person may read as "my friend
has not written back" rather than "my relay is withholding".

Do not write this off as a thing you would never do. It is the reason the
sentences above stop where they do. "Everything after the first message is closed
to you" would be a claim about your own future conduct, not about the code, and
this document does not make those.

### 6.3 The inbox authentication does not apply to you

A caller has to prove they hold the key an address derives from before the relay
hands over that inbox, and again before it deletes anything
(`verify_inbox_auth`, `crates/dust-whisper/src/messenger_auth.rs:98`, which
checks the claimant's key derives to the address at `pubkey_matches_address`,
`:26`). That
check protects an inbox from other people on the network. It does not protect it
from you: the mail is in your process's memory, and it is your process.

The same is true of anything the relay refuses to do to a message. Nothing stops
the operator from dropping a message, keeping a copy, or answering an inbox claim
with less than what is waiting. The people using your relay are trusting you not
to, and for those three they have no way to check.

What a wallet does notice, so that you know which of your options are quiet ones:

- **A refused claim** is reported as a refusal and not as an empty inbox
  (`apps/desktop/src/messengerPoll.ts`).
- **A relay that does not answer** is reported as "Messages may be waiting".
- **A tampered or forged envelope** is counted and discarded, and the wallet says
  how many.
- **Delaying a message no longer hides it.** The time on an envelope is the
  sender's own signed claim, so holding mail back used to file it in the middle
  of the recipient's history under a plausible clock time, with the thread not
  even moving to the top of their list. The wallet keeps its own arrival time now
  and orders the conversation on that, and a message that arrives more than ten
  minutes after it says it was written is marked "held, arrived ..." with a date
  (`received_utc`, `crates/wallet-core/src/messenger.rs`;
  `apps/desktop/src/messengerTiming.ts` and the mobile copy).
- **Refusing a message tells the sender why.** Your relay's own words, "inbox
  full" included, now reach the person who tried to send
  (`delivery_error` on the message `messenger_send` returns).

Dropping mail silently, and answering `auth_ok` with an empty list while holding
somebody's messages, remain invisible from the wallet side. There is no delivery
receipt anywhere in the protocol.

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

**The key lookup is a POST for exactly this reason.** It carries the address it
asks about in a JSON body, not a query string, so it does not appear in that
line or in your proxy's access log by default
(`the_address_asked_about_is_never_put_in_the_url`,
`crates/dust-whisper/tests/messenger_pubkey_directory.rs`). That matters more
than it does for the challenge, because the challenge is asked by the owner of
the mailbox about themselves, while the lookup is asked by a stranger about
somebody else, and it reaches relays that never carry the message (section 6.1).
It is not a defence against you. Body logging is a setting, and if you turn it
on you are keeping that record too.

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

**Running a relay means holding other people's metadata, answering whether a
given address is one of your users, being told who somebody is about to write
to even when you will not carry it, and reading in plaintext every message
written before either party could get a key for the other.** That last group is
smaller than it was, because your relay can now hand a sender the key it already
saw and the sender checks it against the address rather than trusting you (6.2).
It is not empty, and the metadata is not affected at all. If that is not a thing
you want to hold, run a relay for yourself and people you already know, or do
not run one. Both are respectable. Publishing a relay to strangers while telling
them it is private is not.

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
(`messenger_send`, `crates/wallet-core/src/messenger.rs`, which breaks out of the loop on
the first success), while polling tries **every** relay in the list
(`messenger_poll_inbox`, no break). So somebody whose list is `[their own relay, yours]` delivers
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
(`messenger_relay.rs`), because the short version of this paragraph used to
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

**Three things that used to be free, and are not any more.** Each of these was
done against a running relay with an HTTP client and nothing else, and each is
now refused. They are listed so that an operator on an older build knows what
they are carrying:

- **Replaying one captured envelope deleted the sender's mail.** A stranger who
  copied a single envelope off an unencrypted hop could post it twenty times;
  because a replay carries the real sender's real signature, the per-sender cap
  charged every copy to that sender and evicted twenty of their genuine waiting
  messages. The relay now refuses an envelope whose id it already holds, and
  refuses one whose signed `sent_at` is more than 30 minutes old or more than 5
  minutes ahead (`a_replayed_envelope_cannot_delete_the_senders_mail` and
  `an_envelope_older_than_the_window_is_refused`,
  `crates/dust-whisper/tests/messenger_relay_abuse.rs`). If your senders' clocks
  are badly wrong, they will now be told so instead of being quietly replayable.
- **Filling the challenge table locked out every inbox on the relay.** 8320
  unauthenticated GETs, needing no key and no signature, and every honest owner's
  correctly signed claim came back refused, because a full table handed an empty
  nonce to everybody. A full table now evicts its own oldest entry instead
  (`a_challenge_flood_cannot_lock_an_owner_out_of_their_own_inbox`).
- **Inventing recipients parked unbounded memory on your machine.** Section 2.

**The key directory, which is new and which you should size up yourself.** It
adds one table and one unauthenticated endpoint, and both are levers:

- **Flooding it out.** Keys are free, so a flood of throwaway senders can push
  honest entries out of the 20,000 slots. It costs the flooder one signed,
  accepted envelope per entry, which is the same price as filling an inbox, and
  it buys strictly less: an evicted entry means you answer "no key", the asking
  wallet sends v1 and says on its own screen that the message is not sealed.
  Nothing is deleted that anyone was promised, and nothing false is ever
  produced. Compare that to the mail caps, where eviction was the bug.
- **Probing it.** The lookup needs no key and no signature, so anyone who can
  reach the port can ask about any address as fast as your network allows and
  learn which addresses use your relay. Answering costs one hash lookup and no
  walk of the table on purpose (`sender_key`), and expiry and eviction are both
  done on the write path, which costs a signed envelope. So the cheap question
  stays cheap for you as well as for them. What it gives away is section 6.2.
- **What neither of them can do.** Nothing an asker sends changes what you hold,
  and nothing you answer changes what a wallet seals to, because the wallet
  re-derives the address from your answer before it uses it (section 6.2).

**What is still not there.** Nothing rate limits by IP, and nothing
authenticates who is allowed to use your relay. If you want either, it belongs in
the reverse proxy in front of it. It does not exist in the relay, and no cap the
relay has is a substitute for it. The caps above bound what one machine can be
made to hold; they do not stop the requests arriving.

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
10. **Never run a relay build older than the caps in section 2 on a public
    address.** On an older build, one stranger with an HTTP client can park
    unbounded memory on your machine, lock every inbox on your relay with
    unauthenticated GETs, and delete a sender's waiting mail with bytes copied
    off the wire. Section 8 names all three.

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

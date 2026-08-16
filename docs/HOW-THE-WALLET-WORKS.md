# How the wallet works

A plain guide to the whole wallet, for the people who use it.

No prior knowledge is assumed. Every word that could be jargon is explained the
first time it appears. Where something is unfinished, unproven, or a test run
rather than a product, this page says so in the same breath, not in a footnote.

Two companion pages go deeper on narrower topics. Read this one first.

- [HOW-IT-WORKS.md](HOW-IT-WORKS.md) — how your key is protected, in detail.
- [agent-wallet/HOW-THE-AGENT-WALLET-WORKS.md](agent-wallet/HOW-THE-AGENT-WALLET-WORKS.md)
  — the AI Agent Wallet's screens and limits, in detail.

Contents

1. [What this wallet is](#1-what-this-wallet-is)
2. [What your wallet can hold](#2-what-your-wallet-can-hold)
3. [Why there are two wallets](#3-why-there-are-two-wallets)
4. [The three ways money moves](#4-the-three-ways-money-moves)
5. [What "instant" honestly means](#5-what-instant-honestly-means)
6. [What a channel actually is](#6-what-a-channel-actually-is)
7. [If the other side cheats](#7-if-the-other-side-cheats)
8. [What it costs](#8-what-it-costs)
9. [The AI agent: what it can and cannot do](#9-the-ai-agent-what-it-can-and-cannot-do)
10. [How to stop things](#10-how-to-stop-things)
11. [Backing up, and what restoring undoes](#11-backing-up-and-what-restoring-undoes)
12. [What is still a test and must not hold real money](#12-what-is-still-a-test-and-must-not-hold-real-money)
13. [Checking any of this yourself](#13-checking-any-of-this-yourself)

---

## 1. What this wallet is

It is an app for Windows and Android that lets you hold and send money on the
Hacash blockchain.

**Self-custody** means nobody else holds your money. There is no company account
and no password reset. There is a secret number called a **private key**, and
whoever has that key can spend the money. The app's whole job is to keep that
key away from everyone but you.

Two things follow from that, and people miss both:

- **Your money is not in the app.** It is on the blockchain. The app holds the
  key that moves it.
- **A backup is a copy of the key.** Anyone who gets your backup file and your
  passphrase can spend your money from their own computer. Treat the backup file
  exactly like cash.

This is **not a hardware wallet**. A hardware wallet keeps the key inside a
sealed chip that cannot hand it out. This app has to unscramble your key into
your computer's memory to use it, so software running on your device with enough
power could, in principle, read it. That is a real difference in kind, and
[HOW-IT-WORKS.md](HOW-IT-WORKS.md) explains it properly. Keep here only what you
would keep on a phone.

## 2. What your wallet can hold

Four kinds of thing. All of them live on the Hacash blockchain.

**HAC** is the main Hacash coin. It is what you pay blockchain fees with, so you
need a little of it even if you mainly hold something else.

**HACD** are Hacash Diamonds. Each one is a unique collectible with a short name
of four to six letters, drawn from a fixed sixteen-letter alphabet, so names like
`WTYUIA` are valid and names with a `Q` or an `R` in them are not. You do not own
a quantity of HACD, you own particular named ones. You can send up to 200 in a
single transaction.

**BTC on Hacash** is Bitcoin that has been moved onto the Hacash chain. It sits
at your ordinary Hacash address and is counted in satoshi, the smallest Bitcoin
unit. It is not Bitcoin on the Bitcoin network, and this wallet cannot send it
to a Bitcoin address.

**HIP-20 assets** are tokens that other people have issued on Hacash. Each one is
identified by a plain serial number, and that number is the only thing the
blockchain knows about. The friendly name, ticker and logo you see come from a
community explorer website and are **display only** — the wallet never uses them
to decide what to sign. Check the serial number, not the name.

The AI Agent Wallet, described below, is narrower: it can hold and send **HAC and
nothing else**.

## 3. Why there are two wallets

Open the app and you choose one of two spaces: **My Wallet** or the **AI Agent
Wallet**.

They are not two views of one wallet. They are two separate wallets:

- different private keys,
- different addresses,
- different passphrases,
- different encrypted files on disk.

No key, no passphrase and no file is shared between them. No agent and no paired
phone can touch My Wallet. Money does not flow between the two on its own; if you
want the Agent Wallet to have money, you send it money exactly as you would send
anyone else.

**Only one is open at a time.** When you switch spaces, the app locks the one you
are leaving before it opens the one you are going to. Going from My Wallet to the
Agent Wallet, if the lock does not succeed, the Agent Wallet does not open at all
and you are told so. This is the desktop app doing the locking for you, not a law
of physics — but it is what the shipped app does in both directions.

Why bother? Because the point of the Agent Wallet is that you can put a small,
losable amount in it and let a piece of software ask it for payments. That is
only a sane thing to do if the software cannot reach your real savings. Two keys
is how that is guaranteed rather than promised.

## 4. The three ways money moves

### a. On the blockchain — the ordinary way

You sign a transaction, it goes to the Hacash network, miners put it in a block,
and after a while it is settled and irreversible. This is how HAC, HACD, BTC on
Hacash and HIP-20 assets all move. It always costs a network fee, paid in HAC.

It is slower than the other two and it is the only one that needs nobody's
cooperation but yours. That makes it the fallback for everything.

### b. Fast Pay

Fast Pay lets you and a **payment hub** move HAC between yourselves without
touching the blockchain each time. A hub is just a server run by somebody who has
opened a payment channel with you; the next section explains what a channel is.

Payments through Fast Pay land in seconds and cost nothing at all — no network
fee, no wallet fee. The catch is that whoever you are paying also has to have a
channel open with the same hub.

If Fast Pay is not available for a particular payment, My Wallet quietly falls
back to the blockchain and tells you so before you tap Send. Your Fast Pay tab
shows whether the next send will be instant or on chain.

**Honest note on availability.** The wallet ships with no public hub configured.
The only built-in address it will try is a hub running on your own machine, and
the hub setting is empty by default. So unless you have deliberately set one up
or been given one, Fast Pay is simply off and your sends go on the blockchain.

The Agent Wallet has a Fast Pay channel of its own, entirely separate from My
Wallet's, with one important difference: **it has no fallback.** If the channel
cannot carry the payment, the payment fails rather than going on chain.

### c. The fee-free contract channel

The AI Agent Wallet also has a newer kind of channel, run by its own small
program living on the blockchain. Such a program is called a **contract**: code
that the whole network runs and agrees on, so neither side can quietly change the
rules. Payments on it carry no wallet fee and no hub fee, and again there is no
fallback to the blockchain.

This is the only one of the three with the full argument-settling machinery
described in section 7. It is also the newest and least proven part of the whole
system: the desktop will only connect it to a **test** network, and its owner
controls are deliberately locked on mainnet. Section 12 says exactly how unproven.

## 5. What "instant" honestly means

Instant is true for one specific thing and false for everything around it.

**Instant and free:** a payment made through a channel that is already open. It
is an exchange of signed notes between you and the hub. Nothing is mined, nothing
waits, nothing is charged.

**Not instant:** everything that touches the blockchain.

- **Opening a channel** is a blockchain transaction. The hub will not treat the
  channel as usable until that transaction has **six confirmations** — six blocks
  built on top of it. A Hacash block is aimed at one every five minutes, so plan
  for roughly half an hour, not seconds.
- **Closing a channel** is another blockchain transaction, with the same
  six-confirmation wait before the hub treats it as settled.
- **Claiming money back after a dispute** (section 7) is a blockchain transaction
  too.

So the honest sentence is: *payments inside an open channel are instant and free;
getting in and getting out are ordinary blockchain transactions and take
blockchain time.*

One more thing "instant" does not mean. A Fast Pay payment being complete means
you and the hub have both signed a note saying so. It does not mean the
blockchain has recorded anything. The blockchain only learns the final numbers
when the channel closes. The wallet's own mainnet safety report says this
plainly: *settled does not mean the blockchain will enforce it for you.*

## 6. What a channel actually is

Two people — in practice you and a hub — each put some HAC into a locked box on
the blockchain. The blockchain records who put in what, and refuses to let either
of them take money back out on their own.

From then on, instead of doing blockchain transactions, the two of you swap
signed notes. Each note says the same thing in a different split: *of the money
in this box, X is now yours and Y is now mine.* Every note is numbered, and each
new note has a higher number than the last. Both of you sign every note. Neither
of you can write one alone.

That is a payment. Paying someone 1 HAC is writing a new note that gives them 1
more and you 1 less, signing it, and getting their signature back. Nobody mines
anything. That is why it is instant and free.

At the end, somebody shows the blockchain the latest note, and the blockchain
opens the box and pays out according to it.

**The normal ending is friendly.** You and the hub both sign one final closing
transaction, it goes on the blockchain, and everybody gets their share. In this
wallet, closing a Fast Pay channel works exactly this way: you prepare the close,
the hub co-signs it, and it goes on chain. The wallet has **no button that closes
a channel without the hub**, and the code that would have done it is deliberately
switched off in favour of the co-signed route.

That last sentence matters, and section 7 is about what happens when the friendly
ending is not available.

## 7. If the other side cheats

The obvious attack on a channel is this. You and the hub have swapped fifty
notes. The hub kept a copy of note number three, from back when it had most of
the money. It goes to the blockchain, shows note three, and says "this is the
final split."

The contract's answer is a timer, and four steps. Here they are without the
jargon.

**Challenge — "here is the note I say is final."**
Somebody shows the contract a note. The contract will not look at a note unless
three things hold: both parties' signatures are on it, its number is higher than
any note it has already been shown, and the two halves add up to exactly what is
in the box. Then it starts a countdown. In the settings reviewed for this wallet
the countdown is **12 blocks**, which at a five-minute block target is about an
hour.

**Respond — "no, here is a later one."**
While the countdown is still running, the other side can show a note with a
higher number. Same rules: both signatures, higher number. The newer note
replaces the older one. That is the whole defence — an old note is beaten by
simply producing a newer one, and a newer one always exists if the cheat is
about an old note.

**Finalize — "time is up."**
Once the countdown reaches zero, anybody at all can tell the contract to close
the books. The last note it was shown becomes the final split. Nothing can change
it after that.

**Claim — "send me my share."**
Finalizing decides the numbers. It does not move any coins. A separate
transaction has to go to the blockchain to actually pay the money out. Your share
can only be paid out once: the contract ticks it off and refuses a second
attempt. And the contract does not care who sends that transaction, because the
money can only go to your address — so a stranger doing it for you is doing you a
favour, not a theft. That said, the only program that builds this transaction
today is the hub's, so in practice it is the hub that sends it.

Notice that all four steps depend on somebody being awake and watching the
blockchain during the countdown. Software that does this watching is normally
called a watchtower. There is such a program here, it lives on the hub, and it
refuses to act unless it has at least 3 of the 12 blocks left — because a
response that arrives one block too late does not cost a fee, it costs the
channel.

### The honest part

Everything above is real code in this repository, and the contract really is
deployed — checked against the blockchain's own records rather than taken on
trust. But that chain is a small private one the project runs itself for testing.
It is not the Hacash mainnet. And before you rely on any of it, four more things
are true today.

1. **Your wallet cannot start a challenge.** The programs that build and send
   challenge, respond, finalize and claim all live on the hub side. There is no
   button in the wallet and no request you can send to the hub that starts one on
   your behalf.
2. **The whole sequence has never been run to the end, on any chain.** The
   payout step in particular has never once been executed by the blockchain's
   contract engine. It is written, reviewed and tested against a stand-in, not
   proven against the real thing.
3. **The hub's own share cannot be claimed cleanly.** The contract tracks your
   claim exactly, but tracks the hub's out of one shared pot with no per-channel
   marker. Fixing that needs a change to the contract itself. Until then the
   hub's settled share stays stuck inside the contract. Your share is the one
   that is tracked properly, which is the right way round, but it is a known
   defect and not a resolved one.
4. **For ordinary Fast Pay, none of this applies yet.** The Hacash network the
   wallet talks to does not currently offer a way to exit a Fast Pay channel
   without the hub's cooperation, and the wallet checks for that and finds it
   missing. The wallet's own mainnet gate refuses to call itself ready for this
   exact reason.

So the honest summary of "what if the other side misbehaves" is: **the mechanism
is built and the contract is on chain, but today getting your money out of a
channel needs the hub to cooperate.** That is why the mainnet caps in section 12
are as small as they are, and why the wallet tells you on screen that Fast Pay
depends on the hub you chose.

## 8. What it costs

Two different fees exist and they are not the same thing.

The **network fee** goes to Hacash miners. Every blockchain transaction pays one.
The wallet estimates it for you before you sign.

The **wallet fee** goes to the app's own treasury address,
`1LFPqztfKhamVuzzV5WV6pHfykktGD5pMW`. It is shown to you before you sign and it
appears in the transaction itself as a separate payment, so anyone can see it on
the blockchain. It cannot be switched off in settings — the wallet resets it
before every send.

| What you are doing | Wallet fee | Network fee |
| --- | --- | --- |
| Sending HAC on the blockchain | 0.3% of the amount, added on top | Yes |
| Sending HACD | 0.003 HAC flat, per transaction | Yes |
| Sending BTC on Hacash | 0.3% of the amount, added on top | Yes |
| Sending a HIP-20 asset | None | Yes, paid in HAC |
| Fast Pay | None | None |
| An AI Agent Wallet payment | None | Yes, fixed at exactly 0.001 HAC |

The 0.3% is added to what you pay, not taken out of what arrives. Send 100 HAC
and the recipient gets 100 HAC; you are debited 100 HAC, plus 0.3 HAC, plus the
network fee.

Notice the last row. The Agent Wallet charges no wallet fee at all, and its
approval screen actively refuses to sign anything that carries one.

## 9. The AI agent: what it can and cannot do

An **agent** here means a piece of software on your own computer — an AI
assistant or similar — that you have allowed to ask this wallet for payments.

**The agent never holds a key.** Not a copy, not a limited one, not a temporary
one. It talks to the wallet over a private channel on your own machine (a named
pipe on Windows, a socket on Linux). There is no internet port, no web server,
and the listener is off unless you turn it on.

Everything an agent is allowed to ask for is on this list, and the list is the
whole list:

- read basic wallet information,
- read the balance,
- propose a payment,
- check the status of a payment it proposed,
- list the payments it proposed,
- cancel one of its own payments that has not been signed.

There is no "sign this", no "export the key", no "send this raw transaction", no
"open a channel". Those requests do not exist in the protocol, so they cannot be
smuggled through.

For every payment it proposes, you set the rules:

- **Who it may pay.** By default an agent can only pay addresses on a list you
  wrote. You can turn on a setting that lets it *propose* a payment to somebody
  not on the list, but that still only reaches your approval screen, and
  approving once never adds that address to the list. A separate blocklist is
  absolute — nothing overrides it.
- **How much per payment.** Checked against the total leaving the wallet,
  amount plus fee, not against the amount alone.
- **How much per day.** This is a rolling 24 hours counted backwards from right
  now, not a calendar day, so there is no midnight reset. It also counts money
  that has not left yet: a request waiting for your approval and a payment that
  has been sent but not confirmed both count while they are outstanding.
- **How many requests at once.**

**Nothing is ever paid without you.** There is no automatic mode in this release.
Every proposal stops and waits for a person.

**And, in the pilot build, nothing is paid without your phone either.** After you
approve on the desktop, the wallet signs but does not send. It sends only once
your paired Android phone has signed a receipt confirming the wallet has not been
rolled back to an older state. If no such phone is paired, the desktop refuses
your approval *before* signing anything, and tells you which control fixes it.

Which device gets to say yes is a per-agent setting. The one the desktop actually
writes today puts the decision on the desktop and refuses it from the phone. There
are settings that move that authority to the phone, in which case the phone can
approve or reject one exact request it has checked, using your fingerprint.
Approving signs that one decision and nothing else.

Two cautions about the phone either way. It is a witness and a second pair of
eyes; it is not a copy of the wallet. It cannot start a payment, change a rule,
or reach My Wallet, and no key from either wallet is ever stored on it. And two of
its screens are blank on purpose: spending rules and payment history are never
sent to a phone, so an empty history on the phone never means no payment
happened. Read both on the desktop.

## 10. How to stop things

Four controls, and they do different things. In an emergency use the first.

**Disable All Agent Payments** — the real stop. It writes a marker to disk before
it does anything else, so it survives a crash or a force-quit, and it cancels any
permission already handed out inside the app. It also shuts down the agent's
connection and the phone listener, and cancels any pairing in progress. Turning
payments back on can only be done on the unlocked desktop, in person. No agent
and no phone can do it.

**Stop connector** — closes only the local connection the agent talks through. It
does not disable payments. An agent that reconnects can ask again.

**Lock Agent Wallet** — locks the wallet behind its passphrase. It stops work in
progress, but it is a lock, not a policy. Unlocking resumes normal operation with
payments still enabled.

**Revoke** — removes one agent permanently. It cannot be undone. It is the right
control for an agent you no longer want and the wrong one for an emergency.

Two things no control can do.

**Nothing can undo a transaction that has already reached the network.** Once it
is broadcast it belongs to the network. Stopping payments prevents everything
that has not got that far, and nothing that has.

**There is no stop button on the phone today.** The phone's own screens say so
and point you at the desktop. If you need to stop the agent, you need the
desktop.

## 11. Backing up, and what restoring undoes

The two wallets back up separately, and the two backups are different in kind.

**My Wallet's backup** is one encrypted file holding your key, your settings,
your post-quantum keystore if you have one, your channel dispute records and your
encrypted messages. Restoring it also restores the security settings from the
moment you took it — so an old backup can bring back a security key you replaced,
undo a Cold Vault activation, or reinstate an old passphrase. The details are in
[HOW-IT-WORKS.md](HOW-IT-WORKS.md) section 10.

**The Agent Wallet's backup is not really a backup of a key**, and this is the
part people get wrong. A key has no history, so restoring one loses nothing. What
keeps an Agent Wallet safe is the *record* — what has already been spent, which
agents may spend, which agent you revoked, which phone is your witness. That
record is what gets saved, and **restoring it is a rewind, not a repair.**

Four things follow. The wallet makes you read and tick all four before it will
make a backup, and again before it will restore one:

1. **Restoring rewinds what has been spent.** Spending limits go back to what they
   were when you made the backup, and the wallet may pay again for something it
   has already paid for. That money is really gone twice.
2. **A revoked agent comes back.** Every agent that could spend when you made the
   backup comes back live with its allowance reset, including one you have revoked
   since. You have to revoke it again yourself.
3. **Your witness phone will refuse, for ever.** It can see the wallet has gone
   backwards, so it stops approving. You have to move the witness role onto a
   different handset before the wallet can pay at all.
4. **The backup file is a working wallet.** The file plus its passphrase can spend
   your money, at the same time as the wallet you are holding. Store it as you
   would store cash, and never beside the passphrase.

A restore refuses rather than half-runs. All four files inside are parsed,
decrypted, cross-checked and authenticated before a single byte is written, and it
will not write over a wallet that is already on the computer.

## 12. What is still a test and must not hold real money

This section is the one to reread before you fund anything.

**The AI Agent Wallet is a pilot.** It is not even compiled into the ordinary
desktop build — a normal build shows a screen saying the feature is unavailable.
The build that does have it is meant for a disposable test wallet on a test
network. Do not put mainnet money you are unwilling to lose into an Agent Wallet.

**No payment has ever been made on real hardware against a real node.** Every
proof so far ran against a stand-in. The project's own notes record that a single
week of actually running things found eight defects that had all passed the
tests. Green tests are not evidence that something works.

**The channel dispute path has never run end to end.** Section 7 covers this.
Built and reviewed, never completed on any chain, and the payout step never
executed by the contract engine at all.

**The wallet's own mainnet gate says no.** The hub publishes a machine-readable
readiness answer that anyone can ask it for. Read on the pilot hub on 16 August
2026, it said `trustless_finality: false` and `payments_enabled: false`, and
listed its reasons by name. That refusal is deliberate, and it is meant to be
the last thing changed rather than the first. Ask the hub yourself rather than
trusting this page: the answer is at `/v1/readiness/mainnet`.

**Mainnet Fast Pay, where it is allowed at all, is capped very small.** The
ceilings are hard limits in code, not suggestions: **1 HAC per payment, 10 HAC per
channel, and 100 HAC across everyone using that hub combined.** The wallet also
makes you tick a box saying you understand it depends on the hub and is not a
guaranteed exit to the blockchain.

**Post-quantum keys are testnet only.** Hacash supports signatures designed to
resist future quantum computers, and this wallet can make them — but it refuses
to use them outside a test network, and it refuses before anything is built or
signed. If you see quantum features, that is what they are: a preview.

**HIP-20 assets are not available to the Agent Wallet.** It sends HAC and nothing
else.

**Nobody outside this project has audited the code.** There has been no
independent security review of any of it. The Windows installer is not yet signed
by a hardware-backed signing service. Mobile has not completed a full on-device
test pass.

Treat all of this as software being hardened in the open. Not as a finished
custody product.

## 13. Checking any of this yourself

Nothing here is a summary of a promise. Each claim is a claim about code, and the
code is in this repository.

| Claim | Where to look |
| --- | --- |
| The 0.3% wallet fee and where it goes | `crates/wallet-core/src/send_options.rs` |
| Fast Pay costs nothing | `crates/wallet-core/src/send_options.rs`, `fast_pay_fee_breakdown` |
| Six confirmations to open or close a channel | `crates/l2-fast-pay-hub/src/state/open.rs`, `state/close.rs` |
| Challenge, respond, finalize, claim | `hpay_channel_registry_v2.fitsh`, in the pinned Hacash full-node checkout beside this repo |
| The watchtower's timing rules, explained at length | `crates/l2-fast-pay-hub/src/hvm_registry_watchtower.rs` |
| The full list of what an agent may ask for | `crates/agent-types/src/lib.rs`, `Capability` |
| Agent spending limits, including the rolling day | `crates/agent-wallet-core/src/service/payment.rs` |
| The emergency stop that survives a crash | `crates/agent-wallet-core/src/emergency.rs` |
| The four restore consequences, and their tests | `crates/agent-wallet-core/src/service/backup.rs` |
| What full mainnet still requires | [l2/MAINNET_READINESS_MAP.md](l2/MAINNET_READINESS_MAP.md) |
| Known pilot limitations, in detail | [agent-wallet/TESTNET_PILOT_LIMITATIONS.md](agent-wallet/TESTNET_PILOT_LIMITATIONS.md) |

If you find a sentence on this page that the code does not support, that is a bug
worth reporting. A document that overstates what a wallet does is worse than no
document.

# Your first mainnet channel, step by step

This is the operator guide for one person, on one machine, opening one bounded
mainnet Fast Pay channel and holding a way out of it.

Every flag below was read off `--help` on the binary you are going to run,
rather than copied from older documentation. Where a number is a default, that
default was read from the built binary.

Read the whole page once before you start. Nothing here spends money until
Step 8, and Step 7 is a read only check you can press as often as you like.

## What you are building

Three things talk to each other:

1. A **fullnode** you run, synced to Hacash mainnet. It is the only thing that
   tells your wallet the truth about the chain.
2. A **Hub** you run, pointed at that fullnode. It countersigns.
3. Your **wallet**, pointed at both.

The Hub is you. That matters, and Step 10 explains why.

## Before you start

- Disk: a full Hacash chain plus index. Measured here: the chain to height
  776093 fits comfortably, and the machine had 346 GB free throughout.
- Time: **about 7 minutes**, measured, not days. An earlier version of this page
  said days and that was wrong. Hacash's early blocks are tiny, and the sync ran
  at roughly 290000 blocks per minute before slowing near the tip.
- A funded mainnet address with about 0.2 HAC for the canary. Not 7.

## Step 1: build the fullnode

```
cd C:/Users/KQHEX/Documents/hacash-fullnodedev
set CARGO_TARGET_DIR=C:/hpay/nodetarget
cargo build --release -p hacash --bin fullnode
```

The package is `hacash`, not `app`. `app` is a library crate in the same
workspace and `cargo build -p app --bin fullnode` fails with
`no bin target named fullnode in app package`.

Give this build its **own** `CARGO_TARGET_DIR`. Sharing one target directory
between the node and the wallet, or between several builds at once, produced
three separate false failures in one day here, including
`crate typenum required to be available in rlib format` and two type mismatches
that vanished on a clean rebuild. If you see an error that makes no sense,
build into a fresh directory before you believe it.

Copy the binary to where it will live, because the data directory is resolved
relative to the **executable**, not the working directory:

```
copy C:\hpay\nodetarget\release\fullnode.exe C:\hpay\fullnode.exe
```

## Step 2: the config, and the trap that silently costs you days

Create `hacash.config.ini` next to the binary:

```
data_dir = hacash_mainnet_data

[node]
listen = 3337
boots = 54.193.49.59:3337, 182.92.163.225:3337, 54.219.80.127:3337
not_find_nodes = false
fast_sync = false

[server]
enable = true
listen = 8080
bind = 127.0.0.1

[miner]
enable = false

[diamondminer]
enable = false
```

### The setting that decides whether your transactions ever leave

`backbone_peers` defaults to **4**, and on a node nobody can dial that is the
whole of your connection to Hacash. It is the single most important line in this
file after the boot nodes.

Four signed mainnet transactions were sent from a node running that default.
Every one left the socket, measured, `4 peers considered, 4 selected, 4 sent,
0 failed`. Not one reached a miner, and the official public node answered
"transaction not found" for all of them, for two days. The identical bytes,
posted by hand to a well connected node, were mined in two minutes. Nothing was
wrong with the transactions. They had nowhere to go.

Raising it fixed that on the next send, with no other change:

```
backbone_peers = 32
offshoot_peers = 200
```

The network gave 10 peers rather than 4, and the next transaction propagated on
its own: the public node had it in its pool within seconds, without anybody
carrying it there.

You still cannot force people to dial you. What you can do is dial more of them,
and if your router will not forward a port this is the only lever you have.

**The trap.** Without the `[node]` section carrying boot nodes and
`not_find_nodes = false`, hacash does not fail. It starts an **isolated local
chain** of its own. The height sits near zero, everything looks like it is
working, and you are not on Hacash at all. If your height is not climbing into
the hundreds of thousands, you are on your own private chain.

**Why `fast_sync = false`.** It is not superstition and it is not about
corruption; that claim was tested and was wrong. `fast_sync` trusts a Type 3
transaction's declared signers instead of verifying the signatures. This node's
whole job is to tell you the truth about your own money, so it verifies.

**Why `bind = 127.0.0.1`.** The API answers only this machine. Do not widen it
without a reverse proxy and a reason.

**Where the chain lands.** `data_dir` belongs at the very top, above the first
`[section]`, because it is read from the ini root. It resolves next to the
executable, so with the binary at `C:/hpay/fullnode.exe` the chain goes to
`C:/hpay/hacash_mainnet_data`.

## Step 3: sync, and know when it is done

```
./fullnode.exe hacash.config.ini
```

Check it:

```
curl http://127.0.0.1:8080/query/capabilities
```

You are ready for the next step when all of these are true:

- `chain.id` is **0** and `chain.mainnet` is **true**
- `chain.height` is at least **765432**
- `network.block_1_hash` is
  `001e231cb03f9938d54f04407797b8188f0375eb10f0bcb426dccae87dcadb56`

That block 1 hash is the anchor. A node claiming mainnet with any other block 1
is not mainnet, and the wallet works this out for itself rather than believing
the node's own label.

### A real one, measured

This is a node that had just finished, checked against every clause the wallet
uses:

```
chain id 0, mainnet true, height 776093, network kind mainnet
block 1 anchor         matches
tip fresh              age 165s of max 3600
transaction_ready      true      (it is under `network`, not at the top level)
transaction_format_version 2
node_profile_id        hacash-mainnet
network_instance_id    5a310ec0f487a37156a182c67778495f66e5c7502f9871829edc790023b123cf
api                    all five true, including transaction_submit_bound
actions enabled        1, 2, 3, 14 and 1041 (ChainAllow 0x0411)
action_guard           true
```

`channel_unilateral_exit` reads **false** and that is expected. It belongs to the
registry rail, which this guide does not use and which costs about 2000 HAC to
deploy. Nothing on your path reads it.

### The node must be reachable, or it is only half connected

A synced node is not a connected node, and **the app answers this for you now**.
You no longer have to count sockets in a terminal to find it out.

The node publishes the answer in the same capabilities document you already
fetched:

```
curl http://127.0.0.1:8080/query/capabilities
```

```json
"peers": {
  "measured": true,
  "total": 4,
  "inbound_established": 0,
  "outbound_established": 4,
  "public": 4,
  "inbound_proven": false,
  "role": "leaf"
}
```

`inbound_established` is the only number that means anything here. It counts
peers that dialed **your** node and finished the handshake. `role` is that same
number in one word: `participant` if anybody reached you, `leaf` if nobody did.

And the wallet reads it. **Run the check** on the Fast Pay screen and the
preflight now carries an item called
`node_can_be_reached`, which says in words what a leaf cannot do rather than
printing a count. On a node nobody has reached it appears directly under the
banner, in green runs as well as red ones, because that is exactly the case
that used to look fine.

It is a **warning and not a refusal**, deliberately. A leaf still downloads
every block and checks it for itself, so everything else the preflight tells you
is still true, and a payment that never reaches a miner never confirms and
leaves your money where it is. What it cannot do is be reached, so nothing
proves it can carry your signed channel open or your close voucher out to the
miners. You are told before the deposit rather than after, and the decision
stays yours.

### What the wallet now does about it when you send

Being warned was the first half. The second half is that a leaf's transactions
now have somewhere to go.

On **mainnet**, when your own node accepted a signed transaction and that node
is a leaf, the wallet posts the **identical signed bytes** to the official
Hacash node as well. Your own node is still asked first and its answer is still
the answer. This adds a second door, it does not replace the first.

This was measured, not guessed. Four signed transactions sat in a leaf's own
pool for two days while every relay counter said the bytes had been sent. The
same bytes, taken out of that pool by hand and posted to the official node,
were mined into block 776333 in under two minutes. Nothing was wrong with the
transactions. They had no way out.

**Signing is a separate question and the rule there has not moved.** The wallet
still refuses to do mainnet *signing* against a remote node over plaintext
HTTP, because the node you sign against is the node that tells you the
balances, fees and chain state you are signing over. Submitting bytes that are
already signed is a different act: the transaction is fixed, its hash is
computed on your machine before anything is sent, and an endpoint that edits it
breaks the signature it carries. The worst a submit endpoint can do is drop it,
which is what is already happening to a leaf.

**It tells you, in the send result and in the history row**, that the
transaction went out through somebody else's node, and that the connection was
made directly from your device, so that node saw your network address next to
your transaction. That last part is the real cost, and it is the thing running
your own node was hiding. Whether the transaction was actually mined is still
something only your own node reading its own chain can tell you: the official
node echoing your transaction's hash proves it saw the bytes, nothing more.

**Three things it deliberately will not do:**

- **Not on testnet or a pilot chain.** There is no official node for those, and
  pointing a chain 7 transaction at mainnet infrastructure would be wrong.
- **Not when your own node refused the transaction.** A refusal is a failed
  send and stays one. Forwarding it would push bytes your own node judged
  invalid at public infrastructure from your address, and would turn a failure
  you can retry into a success you cannot take back.
- **Not when DUST Whisper is switched on.** Whisper exists to keep a full node
  from learning where your wallet is, and this door is a direct connection from
  your device, which is precisely what you asked it to prevent. In that case
  the wallet says the door was there and that it did not use it, so the choice
  stays yours: turn Whisper off if you would rather the official node carried
  your transactions.

None of this is a substitute for opening the port. A reachable node carries its
own transactions and does not need anybody's help, which is why the rest of
this step is still worth doing.

**Zero is the failure, and it used to be silent.** A node with outbound peers
syncs blocks perfectly, reports a fresh tip, answers every readiness clause, and
looks completely healthy. It was running exactly like that here for over an hour
while two transactions sat in its own pool, and the official public node had
never heard of either of them. Treat that last part as suggestive rather than
proven: a remote node answering "transaction not found" may simply not serve
mempool lookups. The zero itself is measured and is not in doubt.

If you want to confirm it against the operating system rather than against the
node's own word, this is the same fact from outside. Note that
`netstat -an | findstr :3337` showing `LISTENING` proves nothing: it only means
the port is ready to be called, not that anybody called.

```
powershell -c "(Get-NetTCPConnection -LocalPort 3337 -State Established).Count"
```

Windows blocks the inbound port by default and says nothing. Open it yourself,
in an **Administrator** terminal, because this is a firewall change and nobody
should make it on your behalf:

```
netsh advfirewall firewall add rule name="Hacash P2P 3337" dir=in action=allow protocol=TCP localport=3337
```

If the machine is behind a router, forward TCP 3337 to it as well. Then restart
the node and run the preflight again. `inbound_established` should stop being
zero within a few minutes, and the item turns green on its own.

An older node build has no `peers` block at all. The preflight shows that as
**NOT CHECKED** and never as a pass, because a missing answer is not a passing
answer.

**Freshness matters and it keeps mattering.** The wallet refuses a tip older
than **3600 seconds**. A node that fell behind while you were making tea will
refuse to sign, correctly. Keep it running.

## Step 4: create the Hub identity

The Hub holds a private key. On Windows, keep it in a DPAPI file rather than in
your shell history:

```
cd C:/Users/KQHEX/Documents/moskyera-quantum-wallet
cargo build --release -p l2-fast-pay-hub --features server --bin fast-pay-hub
```

```
./fast-pay-hub.exe --create-dpapi-identity --identity-dpapi-file C:/hpay/hub.identity
```

It prints **only the public Hub address** and exits. Write that address down.
It never replaces an existing file.

Send that Hub address a small amount of HAC. It earns no fee under this design,
but an address the chain has never seen is awkward to work with.

## Step 5: run the Hub

```
./fast-pay-hub.exe --identity-dpapi-file C:/hpay/hub.identity --state-file C:/hpay/hub-state.sealed.json --node-url http://127.0.0.1:8080 --listen 127.0.0.1:8790 --deployment-profile mainnet-bounded-pilot --mainnet-allowed-users YOUR_WALLET_ADDRESS --mainnet-max-payment-hac-zhu 10000000 --mainnet-max-channel-funding-hac-zhu 20000000 --mainnet-max-aggregate-tvl-hac-zhu 20000000
```

Three things about those numbers, all read off the binary:

- `--mainnet-max-payment-hac-zhu` and `--mainnet-max-channel-funding-hac-zhu`
  both default to **0**. Zero means nothing is permitted. You must set them.
- `--mainnet-max-aggregate-tvl-hac-zhu` defaults to **100000000**, which is
  1 HAC. If you set a per channel cap above the aggregate, the Hub refuses to
  start and names both numbers. That refusal is correct, not a bug.
- 1 HAC = **100,000,000 zhu**. The values above are 0.1 HAC per payment and
  0.2 HAC per channel and in total. That fits the canary with room and caps
  your exposure at 0.2 HAC.

`--mainnet-allowed-users` is your own wallet address. A Hub does not publish its
allowlist, so if you get this wrong you find out by being refused at the first
open, not before.

`--identity-dpapi-file` supplies the Hub address. Without it the Hub refuses
with `--hub-address is required`, before it looks at anything else.

Journal and state keys: the Hub tells you at startup if it wants them. Give each
its own 32 byte hex key and keep them somewhere you will still have after a disk
failure. State you cannot open is a channel you cannot close.

### What a correct start looks like

Run against a real Hub binary, this is the output, verbatim:

```
Rollback anchor: NONE configured. external_rollback_anchor_ready will read false and full mainnet stays blocked
Fast Pay hub: HPAY Fast Pay Hub
Hub address:  1BvqPBEzUztrSDfXWcDkFV1WangaKHVvbN
Node API:     http://127.0.0.1:8080
Listen:       127.0.0.1:8790
INFO Fast Pay hub listening addr=127.0.0.1:8790
```

The first line is expected and is not an error. A rollback witness is what would
catch a Hub restored from an older backup. Without one, `full mainnet` stays
blocked and the **bounded pilot** is what you get. That is the mode this guide
is for.

### The refusal you want to see

Set a per channel cap above the aggregate on purpose and the Hub refuses, naming
both numbers and the fix:

```
Error: State("mainnet pilot aggregate TVL cap (20000000 zhu) is below the
per-channel funding cap (100000000 zhu). This Hub would publish a channel cap it
could never fund. Raise --mainnet-max-aggregate-tvl-hac-zhu to at least
100000000, or lower --mainnet-max-channel-funding-hac-zhu to at most 20000000.")
```

If you see that, the Hub is doing its job.

## Step 6: build the app with the feature that carries the exit

**Do not use a plain `yarn tauri build`.** `apps/desktop/src-tauri/Cargo.toml`
has `default = ["custom-protocol"]`, and the exit lives behind a feature that is
not in it. A default build registers the voucher commands and then answers
`Agent channel close is disabled in this build`, which is a sentence you find
out about after your deposit is already on chain.

Build it the way the release workflow does:

```
cd apps/desktop
node node_modules/@tauri-apps/cli/tauri.js build --bundles nsis,msi -- --locked --features agent-wallet-bounded-mainnet-pilot
```

Verify the feature actually landed, rather than trusting the flag. The check is
that the disabled-branch sentence is **absent** from the binary:

```
grep -a "Agent channel close is disabled in this build" release/hacash-wallet.exe
```

No match means the exit is compiled in. A match means it is not, whatever the
command line said.

## Step 7: THE EXIT IS IN THE AGENT WALLET, NOT THE MAIN FAST PAY SCREEN

This is the correction that matters most on this page, and an earlier version of
it got this wrong.

Every voucher command is named `agent_wallet_*` and lives in
`crates/wallet-tauri-common/src/agent_commands.rs`. The main wallet has
`hub_declaration` and the preflight, both read only, and **no way to take or
broadcast a voucher at all**.

So a channel opened on the main wallet's Fast Pay screen has **no unilateral
exit**. The money leaves only if the Hub co-signs a cooperative close. That is
the exact thing this whole design exists to avoid.

Use the **Agent Wallet**. It is a separate wallet with its own address, its own
key and its own channel, and it is the only one that can hold an exit.

Taking the voucher does **not** need a paired phone.
`take_l2_channel_close_voucher` requires an active session, the right network
and an active channel binding. The phone requirement is on *approving payments*,
not on getting your way out.

## Step 8: point the wallet, and put the Agent Wallet address on the Hub

Settings, node URL:

```
http://127.0.0.1:8080
```

Loopback HTTP is deliberately allowed. Remote plaintext HTTP is refused.

Then create the Agent Wallet and read its address. It is **not** your main
wallet's address, and this catches people: the Hub's `--mainnet-allowed-users`
must contain the **Agent Wallet's** address, so restart the Hub with it before
any money moves. A Hub does not publish its allowlist, so the wrong address here
surfaces as a refusal at your first open and not before.

Fund the Agent Wallet address with the deposit plus a little for fees.

## Step 9: open the channel, and take the exit

Open with **0.1 HAC**. Not 7. Not 1.

Then, in the Agent Wallet, find **Your way out** and press **Ask the hub for the
exit**.

You cannot forget this step, and that is by design. Until you hold the voucher
the screen says so and the wallet **refuses to make Fast Pay payments**:

> You do not hold a signed exit for this channel yet. Until you do, this wallet
> will not make Fast Pay payments, because the deposit is on chain and the only
> way to get it back is to ask the hub to close the channel.

Between the deposit confirming and the voucher arriving there is a real gap
where you have no leverage, because the Hub cannot countersign a channel that
does not exist yet. Keep it short. Treat Hub silence inside it as an incident.

The wallet verifies the voucher before storing it: it decodes the bytes,
requires exactly the two actions, requires that no transfer is present, checks
it names your channel and your chain, checks the hash, and verifies **both**
signatures cryptographically. It takes the Hub's word for nothing.

Once stored you hold a transaction that refunds your whole deposit to you and
nothing to the Hub, never expires, can be broadcast by you alone, and pays its
own fee out of the refund.

**One voucher per channel, ever.** Both sides refuse a second.

Back the wallet up now. The voucher travels in the encrypted backup and has been
proven to survive a close, a backup and a restore.

## Step 10: use it, and know what is true

Make one small payment in each direction you care about. 0.001 HAC.

To close normally, close cooperatively. To leave without the Hub, broadcast the
voucher.

### What is trusted, in plain words

The Hub must countersign the voucher **once**, at the start. Nothing in Hacash
can force it. If it never signs, your deposit is stuck until it cooperates or
forever, and consensus offers no recourse: there is no unilateral close action
and no challenge action on this rail.

That is the whole trust assumption and it is not dressed up. This pilot is
**trusted**, not trustless.

### What it costs the Hub

Once you hold a delta zero voucher, you can spend the channel down and still
recover the full deposit. The Hub carries that. It is fine because the Hub is
you. It stops being fine the moment the Hub is somebody else, and shipping this
to a third party Hub needs work that is not done.

### The risk is stranding, not theft

A Hub that stops answering does not take your money. It locks it, and nobody can
release it. A Hub cannot settle alone: `channel_close` requires both signatures
at the consensus level. Any older receipt would pay you more, not less, because
the Hub deposits nothing into the channel.

## If something goes wrong

- **Height near zero.** Step 2, the trap. You are on an isolated chain.
- **"mainnet signing requires HTTPS".** Your node URL is remote plaintext. Use
  the loopback node.
- **"not allowlisted".** Your address is not in `--mainnet-allowed-users`.
- **Hub refuses to start naming two numbers.** Your per channel cap is above
  your aggregate cap. Step 5.
- **Tip stale.** Your node fell behind. It refuses on purpose.
- **The check says a Hub cannot issue a voucher.** Do not fund it. That is the
  strand this check exists to catch.

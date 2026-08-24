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

- Disk: a full Hacash chain plus index. Give it room.
- Time: syncing from zero takes days, not hours.
- A funded mainnet address with about 0.2 HAC for the canary. Not 7.

## Step 1: build the fullnode

```
cd C:/Users/KQHEX/Documents/hacash-fullnodedev
cargo build --release -p app --bin fullnode
```

The binary lands in `target/release/fullnode.exe`.

## Step 2: the config, and the trap that silently costs you days

Create `hacash.config.ini` next to the binary:

```
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

## Step 6: point the wallet

Open the wallet. Settings, node URL:

```
http://127.0.0.1:8080
```

Loopback HTTP is deliberately allowed. Remote plaintext HTTP is refused, and
that refusal is one of the few things standing between you and somebody else
choosing your transaction bytes.

On the Fast Pay screen, Hub API URL:

```
http://127.0.0.1:8790
```

A phone cannot host the node, so a phone needs an HTTPS address for both. Set
the desktop up first.

## Step 7: press the check

Desktop: Fast Pay, under "Turn Fast Pay ON", the button above "Enable Fast Pay".
Mobile: the Fast Pay channel screen, under Setup, above "Preview channel open".

It sends five read only requests. It signs nothing, unlocks nothing and
broadcasts nothing.

- **NOT READY**: stop. Fix what the item names. An item marked
  "FATAL, NOT CHECKED" counts as failed, because a question nobody answered is
  not a question that came back clean.
- **READY**: go on, and re run it at the top of Step 8. The answer goes stale in
  about five minutes.

Read the block titled "What this check cannot tell you, whatever colour it is".
Green is a statement about infrastructure at one instant. It is not a statement
that your money is safe.

## Step 8: open the channel, with 0.1 HAC

Not 7. Not 1. **0.1 HAC.**

Preview the open, read the reviewed transaction, and confirm. Wait for
confirmations. The deposit is now on chain.

**This is the hostage window.** Between here and Step 9 you have no way out that
does not need the Hub. It exists because the Hub cannot countersign a channel
that does not yet exist. Keep it short and treat Hub silence here as an
incident, not a delay.

## Step 9: take the voucher, before you pay anybody

**Do this before the first payment. Not after.**

Take the close voucher. The wallet verifies it before storing it: it decodes the
bytes, requires exactly the two actions, requires that no transfer is present,
checks it names your channel and your chain, checks the hash, and verifies
**both** signatures cryptographically. It does not take the Hub's word for any
of it.

Once it is stored you hold a transaction that:

- refunds your whole deposit to you and nothing to the Hub;
- never expires, because the chain has no lower bound on transaction age;
- can be broadcast by you alone, because nothing binds it to a submitter;
- pays its own fee out of the refund, so you need no other balance to escape.

The Hub cannot revoke it, cannot expire it, cannot redirect it and cannot alter
it. Those are consensus properties, not promises.

**One voucher per channel, ever.** Both the Hub and the wallet refuse a second.
That is deliberate: several valid closes for one channel would let you pick the
one paying you most, which would be pure loss to the Hub for no gain to you.

Back the wallet up now. The voucher travels in the encrypted backup and it has
been proven to survive a close, a backup and a restore. A voucher you cannot
restore is not a way out.

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

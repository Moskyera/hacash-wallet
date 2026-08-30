# The close voucher, run on chain 7

Date: 2026-08-24
Evidence category: `LOCAL_PRIVATE_CHAIN`
Status: the owner recovered the whole deposit, alone, with the Hub dead.

This records one complete run of the L1 channel close voucher against the
private HPAY Local Pilot chain. Nothing in it is simulated. The node is the
real `fullnode.exe`, the Hub is the real `HubState` behind the real
`build_router` that `fast-pay-hub.exe` serves, and the wallet is the real
`AgentWalletManager`. Every transaction below was mined by that node's own
block executor.

## The trust, in plain words

The Hub signs the voucher once, at the start, and nothing in Hacash can make
it. If the Hub refuses, the deposit stays in the channel and the owner has no
way to get it out on their own. There is a real window, between the moment the
channel open confirms and the moment the countersigned close comes back, during
which the owner's coin is on chain and the owner holds nothing. The wallet
closes that window as fast as it can, inside the same call that confirms the
open, and it does not pretend the window is not there.

After the voucher exists the exposure moves entirely onto the Hub. A delta zero
close refunds the balances the channel recorded when it opened, so the owner can
spend the channel down to nothing and still take the whole opening deposit back.
Nothing in the protocol stops them. That is acceptable in this pilot for one
reason only: the owner runs the Hub. It would not be acceptable between
strangers.

The word trustless does not apply to any part of this, and it is not used
anywhere in the feature.

## The safety critical rule

Exactly one voucher per channel, ever, taken at delta zero, never refreshed.

A refresh would leave the owner holding several valid closes for one channel,
each with its own transaction hash, only the first of which can be mined. The
owner would pick the one that pays them most, which is always the oldest, so
refreshing is pure loss to the Hub for no owner benefit: the delta zero voucher
already pays the owner the maximum. There is no refresh entry point in the
wallet and no second slot in the Hub.

## The network, verified before every stage

Re-read from `/query/capabilities` at every stage of the run, never once at the
top.

| Field | Value |
|---|---|
| Endpoint | `http://127.0.0.1:8197` |
| Chain ID | `7` |
| Mainnet | `false` |
| Network kind | `local_pilot_v1` |
| Node profile | `hpay-local-pilot-chain-v1` |
| Block 1 | `000087f67e55660eaefed72e0b9499147556a33a34f18fa48900f4a2fa30cd29` |
| Network instance | `9ebd8657a72faed35ed4d6e309fab2ef259f054e4820684fab6c6b848e4438f3` |
| Node | `hacash-fullnode 1.0.10` |

No mainnet endpoint was contacted at any point, and nothing was broadcast
anywhere except this node.

## The parties

| Role | Address |
|---|---|
| Owner Agent Wallet | `1PbRGWwKJLVugwmnkocMrvtiyo5SQpgfa3` |
| Hub | `1N1HDKxgSek3M6DCW53MBTnJVmbMcFxnbz` at `http://127.0.0.1:8791`, profile `local-pilot` |
| Funding source | `1KCRLdAATCyeEPPtYn27RpJTdLV9Ueamk`, the chain 7 pilot identity |

The owner wallet address is generated inside the Agent Wallet and no shipped
code path can mint coin to it, so the deposit was moved in with two ordinary L1
sends through the Personal Wallet's own `send_hac`:
`6ee35f9767f9affd53ab2ddfaf044b18e48e5beded021f541f6cf3ad7ff8b570` and
`2adcf40edda725b3691b477dd280976524f68cdf478246beddd954a6d263563b`.

## The run

### 1. The channel opened, 1 HAC, zero Hub deposit

Opened by `prepare_l2_channel_setup` and `confirm_l2_channel_setup`.

```
channel      0a6afaadcf67daf2b5979ec6a7ab24e4
reuse        1
open_height  4419
left         1PbRGWwKJLVugwmnkocMrvtiyo5SQpgfa3   1 HAC
right        1N1HDKxgSek3M6DCW53MBTnJVmbMcFxnbz   0
status       0 (open)
```

### 2. The voucher was countersigned and handed back, not broadcast

`confirm_l2_channel_setup` reached `Confirmed` at height 4425 and took the
voucher in the same call, through `take_l2_channel_close_voucher`.

```
transaction  e96d467b5e103bf0421b5ef269d4d1eedc3e009559ec250cf524755e3f699eb1
commitment   e87ad17090159213d48809747ad7c9d51b236143d2d43f6a73168f425308df2e
refund       1 HAC          (the balance recorded at open)
deposit      1 HAC
network fee  0.000203 HAC   (paid by the owner, out of their own balance)
```

The owner re-proved it from the bytes with
`hacash_wallet_core::l1_channel_close_safety::verify_channel_close_voucher_bytes`,
which checks the topology, the chain binding, the channel id, the fee payer, the
hash, and both party signatures. Nothing was taken on the Hub's word.

### 3. The channel was still open, and still usable

Read back from the node immediately after the voucher was issued:

```json
{"id":"0a6afaadcf67daf2b5979ec6a7ab24e4","status":0,"open_height":4419,
 "close_height":0,"reuse_version":1,
 "left":{"address":"1PbRGWwKJLVugwmnkocMrvtiyo5SQpgfa3","hacash":"1"},
 "right":{"address":"1N1HDKxgSek3M6DCW53MBTnJVmbMcFxnbz","hacash":"0"}}
```

Taking the voucher writes no `channel_lifecycle` and no close record on the Hub,
so unlike a cooperative close it does not freeze the channel.

### 4. A real Fast Pay payment, so the ledger delta was not zero

Driven through the shipped chain: an agent intent, a mobile approval signed by a
companion device, `sign_prepared_approved_fast_pay_bill`, then
`submit_signed_approved_fast_pay_bill` into the live Hub.

```
committed 8000 units (0.008 HAC), wallet fee 0, network fee 0
```

From this point the voucher paid the owner more than the channel owed them, which
is the whole shape of the Hub's exposure.

### 5. The Hub was killed

The server task was aborted and the socket went away. Proved, not assumed:

```
GET http://127.0.0.1:8791/v1/health
ConnectError("tcp connect error", 127.0.0.1:8791,
  Os { code: 10061, kind: ConnectionRefused })
```

### 6. The wallet was closed, backed up, and restored

`create_agent_wallet_backup`, then `restore_agent_wallet_backup` into a
completely separate empty store, then unlock. The restored wallet held the same
transaction hash and the same exact bytes.

### 7. The exit was broadcast by the owner alone

`broadcast_l2_channel_close_voucher`, from the restored wallet, through the
owner's own node. This path constructs no Hub client at all, not even to read.

```
broadcast at height 4425
transaction e96d467b5e103bf0421b5ef269d4d1eedc3e009559ec250cf524755e3f699eb1
via         http://127.0.0.1:8197
```

### 8. Read back off the chain

Mined at height 4427:

```
block  4427  0000000014bdee2cd1cffc71dc025426385438fd36a0366a1952051ebb1b9112
type   2
main   1PbRGWwKJLVugwmnkocMrvtiyo5SQpgfa3   (the owner pays the fee)
fee    203:242                              (0.000203 HAC)
```

The channel, closed:

```json
{"id":"0a6afaadcf67daf2b5979ec6a7ab24e4","status":2,
 "open_height":4419,"close_height":4427,
 "distribution":{"left":{"hacash":"1"},"right":{"hacash":"0"}},
 "final_arrival":{"left":{"hacash":"1"},"right":{"hacash":"0"}}}
```

The money:

| Address | Before | After | Change |
|---|---:|---:|---:|
| Owner `1PbRGWwKJLVugwmnkocMrvtiyo5SQpgfa3` | 199,975,900 Zhu | 299,955,600 Zhu | +99,979,700 Zhu |
| Hub `1N1HDKxgSek3M6DCW53MBTnJVmbMcFxnbz` | 0 Zhu | 0 Zhu | 0 |

The owner got back exactly 100,000,000 Zhu, the whole deposit recorded at open,
less the 20,300 Zhu L1 fee they paid themselves to broadcast it. The Hub got
nothing, and had never held any of this coin on chain. The 0.008 HAC the owner
had already spent through the channel stayed spent from the Hub's point of view
and was refunded to the owner anyway, which is the exposure stated at the top of
this document, now measured rather than asserted.

## Negative proofs, on the same real node

### The Hub refuses a second voucher for one channel

A copy of the wallet was restored from backup and made to forget its voucher,
which is the only way to get the shipped client to build a different request
naming the same channel. Run twice, once while the ledger was still delta zero
and once after the payment. Both were refused, and no second signature was ever
produced.

### The wallet refuses a voucher that is not exactly one

Run against the exact bytes the Hub really signed and against five things that
are not them:

```
control: the Hub-countersigned bytes verify
one signature only:      close voucher must carry exactly the two party signatures
flipped Hub signature:   1N1HDKxg... signature verification failed
three actions:           close voucher actions must be exactly [ChainAllow, ChannelClose]
wrong second action:     close voucher actions must be exactly [ChainAllow, ChannelClose]
wrong chain:             close voucher must bind exactly chain 1
```

"One signature only" is not a synthetic case. Those are the exact bytes the
wallet presented to the Hub before it countersigned, replayed with the same
expected hash, because `fill_sign` does not change `hash()`. A close the Hub
never signed is refused for the reason it should be.

### One place the bytes-only check does not reach, stated plainly

Flipping the final byte of the encoding does NOT make
`verify_channel_close_voucher_bytes` refuse. The transaction still parses,
consumes every byte, hashes to the same value and carries two valid party
signatures, so `hash()` does not cover that byte.

```
final byte flipped: bytes-only check STILL PASSES
commitment moves e87ad170...308df2e -> 0b3d160a...498d703
final byte flipped, durable record: RecoveryRequired
```

What refuses it is the durable record, which also pins a SHA-256 over the exact
bytes the Hub returned. So the byte exactness of a stored voucher comes from the
commitment, not from the transaction check, and the two are not
interchangeable. Any future caller that verifies bytes without also pinning the
commitment would accept a mutated encoding.

### The voucher survives the wallet being closed and restored

Proved in step 6 above, and the exit that settled on chain was broadcast from
the restored store, not from the wallet that took it.

## What this run does not prove

1. **It does not prove the Hub is safe to run for strangers.** Every identity
   here belongs to one person. The Hub countersigned because it was asked by its
   owner. Nothing here tests an adversarial Hub or an adversarial owner, because
   there was not one.

2. **The Hub side rule "no voucher once any payment exists" was not isolated on
   chain.** The wallet refuses Fast Pay until a voucher is held, so a paid
   channel with no voucher cannot be reached through shipped code at all. Both
   post-payment attempts above were refused, but the one-voucher-per-channel
   check runs first, so the ledger check was not the guard observed. It stays
   covered only by the Hub crate's own tests against an in-process node.

3. **The hostage window is longer in practice than the code makes it look.** The
   Hub will not countersign a channel it cannot see finality evidenced, and that
   is six confirmations. In this run the deposit was committed on chain at height
   4419 and the voucher arrived after height 4425. On a chain averaging several
   minutes a block that is the better part of an hour with the coin committed and
   no exit in hand. The code closes the window between the open *confirming* and
   the voucher, which is seconds; it cannot close the window between the open
   being *mined* and the open confirming.

4. **A Hub that loses its key before countersigning strands the deposit, and
   this run produced a live example of exactly that.** An earlier attempt in the
   same session ran with a Hub identity that existed only in memory. The channel
   open was mined before the process ended, and the key is gone:

   ```
   channel      6baa48c5bfa1a71802cf698cd2d98c01
   left         1PU5X5sdojZcXn64rqhq1Y5BCSQ6oNmoBn   1 HAC
   right        17C1PjiZEFqTfhx52g7AuydbZi5W6CtH4A   0
   open_height  4414, still open
   ```

   That 1 HAC of chain 7 pilot coin cannot be recovered by anybody. It is not a
   defect in the feature; it is the feature's premise, demonstrated by accident.
   A `ChannelClose` needs both parties, and the Hub is not there to sign one.

5. **Nothing here was run on mainnet, and nothing here should be.** The caps,
   the profile and the whole trust argument are for a bounded pilot on a private
   chain.

## How to run it again

The instrument is
`crates/agent-wallet-core/src/service/companion/tests/chain7_live_voucher.rs`.
Both tests are `#[ignore]`, so a plain `cargo test` never runs them, and both
refuse any node that is not chain 7 with `mainnet: false` and network kind
`local_pilot_v1`.

```
set RUST_MIN_STACK=67108864
set HPAY_LIVE_WORKDIR=<a short path, under 200 characters>
set HPAY_LIVE_FUNDING_DPAPI=<the funded chain 7 DPAPI identity file>
set HPAY_LIVE_HUB_LISTEN=127.0.0.1:8791
set HPAY_LIVE_WAIT_SECS=5400

cargo test -p agent-wallet-core --features agent-wallet-testnet-pilot --lib -- \
  --ignored --exact --nocapture --test-threads=1 \
  service::companion::tests::chain7_live_voucher::the_owner_exits_alone_while_the_hub_is_dead
```

Two things the harness has to get right, both learned the hard way:

- The Hub identity and its listen port are written into the wallet's durable
  channel setup record, so a resumed run has to bring back the exact same Hub.
  The instrument derives the Hub account from a seed file in the work directory
  for this reason. A run that loses the Hub key strands the deposit, as item 4
  above shows.
- The wallet auto-locks while six confirmations accumulate, so the wait loop
  unlocks again on every pass, which is what an owner sitting in front of it
  would do.

The verifier negatives read the store the run above leaves behind and need no
chain time:

```
cargo test -p agent-wallet-core --features agent-wallet-testnet-pilot --lib -- \
  --ignored --exact --nocapture --test-threads=1 \
  service::companion::tests::chain7_live_voucher::the_wallet_refuses_a_voucher_that_is_not_exactly_one
```

## The negatives, on the same live chain

Four more `#[ignore]` tests live in the same file. They exist because a path
that only works when nothing goes wrong is not proven, and each one breaks
exactly one thing against the real node and a real Hub over real HTTP.

```
cargo test -p agent-wallet-core --features agent-wallet-testnet-pilot --lib -- \
  --ignored --exact --nocapture --test-threads=1 \
  service::companion::tests::chain7_live_voucher::<name>
```

| name | what it breaks | chain time |
| --- | --- | --- |
| `a_hub_outage_inside_the_envelope_refuses_the_discard_and_the_retry_still_opens_the_channel` | the Hub settlement route, after the wallet signs | about 70 s |
| `a_retry_after_the_envelope_expires_fails_cleanly_and_the_dead_setup_has_an_exit` | the same route, held down past the envelope | about 11 min |
| `a_mainnet_shaped_consent_is_refused_on_a_chain_that_is_not_mainnet` | nothing; it asks for a consent this chain cannot take | none |
| `the_amounts_the_panel_names_are_the_amounts_the_core_refuses` | ten malformed deposit amounts | about 25 s |

Each takes its own work directory under `HPAY_LIVE_WORKDIR` and its own owner
wallet, so each gets a fresh deterministic channel ID. Extra optional ports:
`HPAY_LIVE_HUB_OUTAGE_LISTEN` (8892), `HPAY_LIVE_HUB_OUTAGE_FRONT` (8894),
`HPAY_LIVE_HUB_EXPIRED_LISTEN` (8893), `HPAY_LIVE_HUB_EXPIRED_FRONT` (8895),
`HPAY_LIVE_HUB_AMOUNTS_LISTEN` (8896).

### Why the outage is a proxy and not a killed process

The first draft of these tests simply aborted the Hub before the confirm. It
went red, and the red was worth more than the green would have been:

```
[neg ] confirm against a dead Hub: ChannelSetupHubNotReady(
         "l2: hub unreachable: error sending request for url (.../v1/health)")
[neg ] stored phase Prepared, signature present false, node tx hash None
```

`confirm_l2_channel_setup` re-verifies the Hub before it signs, so a Hub that
is already gone is refused while the setup is still `Prepared` and provably
unsigned. That is the good case, and it is now asserted first. It is not the
state this feature exists for. To reach the state the owner of this machine was
actually in, the front door has to stay up and the settlement route has to
refuse, which is what a reverse proxy in front of the Hub does. Everything else
in those runs is the real Hub, the real router and the real chain.

### The two clocks the dead-request exit reads

`abandon_dead_l2_channel_setup` needs both the envelope closed and the
transaction past `CHANNEL_OPEN_DEAD_AFTER` (600 s), and the gap between them is
covered on purpose:

```
[neg ] signed at 1788089380, envelope closes 1788089680,
       unusable by anybody after 1788089980
[neg ] envelope closed but transaction still young: ChannelSetupNotDiscardable
[neg ] 17 clean retry failures, no hang, nothing half written
[neg ] discard on the dead setup: ChannelSetupNotDiscardable
[exit] abandoned operation 0f394140-fef8-4c89-b67e-4925d7a0bacb
[coin] owner 150000000 -> 150000000 Zhu across the whole dead setup
```

The guard reads the clock its caller passes, so the test waits out the real 600
seconds rather than handing it a future `now`, which would prove nothing. The
run then re-prepares on the same deterministic channel ID and opens it for
real, which is the claim that matters: a retired dead request does not brick
the channel.

### The consent this chain cannot take

There is no mainnet-shaped consent for a private chain, and the instrument
pins it rather than leaving it as an assumption:

```
[neg ] testnet wallet plus mainnet consent: InvalidPaymentRequest
[neg ] mainnet wallet anchored on chain 7 block 1: InvalidPaymentRequest
[neg ] control: the testnet consent is accepted
```

`create_wallet` refuses a testnet wallet carrying
`AGENT_MAINNET_PILOT_ACKNOWLEDGEMENT`, and `network_mode: "mainnet"` pins
`MAINNET_BLOCK_ONE_HASH` as the anchor and needs the
`agent-wallet-bounded-mainnet-pilot` feature, neither of which a chain-7 run
has. So the consent exercised on this chain is the testnet one, and the
mainnet consent gate itself is not covered here.

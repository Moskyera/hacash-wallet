# HPAY registry response watch

A small program that answers an arbitration challenge on an HVM registry
channel for somebody who is not awake.

It is not part of the Hub. In the case it exists for, the Hub is the party
challenging.

## What it protects, exactly

A registry channel settles through an arbitration window. Either party may
`challenge` with a bill; the other has `challenge_blocks` to `respond` with a
newer one; whatever stands when the window closes is what gets paid. On the
reviewed profile that window is 12 blocks, about an hour, of which about 45
minutes are usable after the margin a response needs to be mined in.

If a challenge names a bill older than yours, this answers it with yours. If a
close is already settled correctly, it finalises it and sends the money to your
own address.

## What it does not protect

**Nothing at all while it is not running.** There is no queue and no
catch-up. A challenge that opens and expires while this is stopped is lost.

It does not renew the channel's storage lease. That is a separate clock and it
is the one that destroys money outright rather than misallocating it: when the
lease lapses the deposit becomes unrecoverable by anyone, including you. Renew
it from the wallet. This program prints a warning when it sees the lease
running low, because it is the process most likely to be looking.

It is a best-effort stand-in, and the exact size of the gap is printed at every
start, computed from your own channel rather than asserted.

## What it cannot do, by construction

- **It cannot start a close.** There is no challenge step in the program.
  No flag and no configuration opens an arbitration window against you.
- **It cannot pay itself or anyone else.** The contract's `PermitHAC` hook
  pins the destination to the channel's left party and the amount to
  `c_left_balance_` to the zhu. Measured on a real chain: a third party trying
  to pay itself gets `Arithmetic(90): cannot compare different types Nil and
  U8(4)`; trying a different amount gets `HPAY_LEFT_PAYOUT_MISMATCH`.
- **It holds no key of yours.** The kit it reads is a channel binding plus a
  bill both parties signed. It is not a private key and cannot be turned into
  one.

This is a better trust profile than a Lightning watchtower, whose justice
transaction is a bearer instrument and therefore has to be handed over
encrypted. The worst a dishonest operator can do here is learn your channel
balance; the worst an absent one can do is nothing.

Anyone can run one for you. A friend, a VPS, or you on a second machine.

## The one mistake that costs you

**A stale kit.** Export a fresh one after every payment.

On this rail every bill you sign pays you less than the one before it, so an
older bill is one the provider prefers. Answering with a bill older than your
real head installs a split in the provider's favour. The program refuses to act
when it can see the chain is ahead of the kit, but it cannot see a payment you
made that the chain has not settled.

## Install

```bash
cargo build -p l2-fast-pay-hub --features registry-response-watch \
  --bin hpay-registry-response-watch
```

The feature is deliberately not in a default Hub build.

Then, as root, with `install.sh`, `hpay-registry-response-watch.service` and
the built binary in the same directory:

```bash
chmod +x install.sh hpay-registry-response-watch
sudo ./install.sh
```

The installer asks for the kit file, the fullnode URL and the responder's
fee-paying key, refuses a poll interval that could step over a whole challenge
window, installs a dedicated unprivileged service account and starts the watch.

## Before you install

- A synchronized HPAY-capable Hacash full node this machine can reach. **Not a
  Hub endpoint.** If this program depended on the Hub it would be useless in
  the exact case it exists for.
- A dedicated fee-paying key with a small balance. Three network fees is the
  whole budget. **Never your wallet key.**
- The exit kit exported from the wallet, and a habit of refreshing it.

## Verify

```bash
# What would this protect? Reads no chain, needs no key, sends nothing.
hpay-registry-response-watch --kit /etc/hpay-registry-response-watch/exit-kit.json \
  --node-url http://127.0.0.1:8080 explain

# One real look at the chain, signing and submitting nothing.
hpay-registry-response-watch --kit ... --node-url ... once --dry-run

sudo systemctl status hpay-registry-response-watch
sudo journalctl -u hpay-registry-response-watch -f
```

`explain` and `--dry-run` reach the identical decision the live loop would.

## Reading the log

```
  ok   height 91234  channel OPEN  chain serial 4  storage lease 9812 blocks left
  ACT  Respond submitted, tx 3f0c...
  MISS a response is needed and only 2 blocks of the window remain ...
  STOP the chain is ahead of this kit ...
```

`ok` every interval is the healthy state, and it is printed rather than being
silent, because a watcher that says nothing while healthy cannot be told apart
from one that has died.

`MISS` means this watcher was not running when it needed to be.

`STOP` means the kit is stale; the loop exits rather than retrying, because
every further attempt would try to install a split that favours the other
party. Export a fresh kit.

## The honest state of this

The response guarantee is **best-effort while your device is off**. It rests
today not on this program but on a property of the rail: every bill you sign
pays you less than the one before, so a stale challenge from the provider hands
money back to you. That property is exactly two refusals:

- `crates/l2-fast-pay-hub/src/hvm_registry.rs` — `right_hub_deposit_zhu != 0`
  is refused, so the provider never has principal of its own in the channel.
- `crates/l2-fast-pay-hub/src/hvm_registry_ledger.rs` — `checked_sub` on the
  left balance, so no bill can move value back towards you.

If either changes — a refund path, a non-zero Hub deposit, inbound routing
where you are the recipient — an unanswered window starts costing real money
and this program stops being optional.

Two things are owner decisions, not engineering, and neither is settled:

1. **Whether anyone operates a watchtower service.** Nothing here assumes one
   does. This program is what makes such a service buildable by anybody
   without key custody; it is not a claim that one exists.
2. **What minimum `challenge_blocks` to enforce on new channels.** Nothing
   enforces one today. `HVM_REGISTRY_HUMAN_ANSWERABLE_CHALLENGE_BLOCKS` (288,
   24 hours) is written down as a default to argue with, and it is read only to
   decide how loudly the startup notice speaks. A wider window is safer for a
   sleeping user and also a longer wait, and a longer lock on your own money,
   during an honest exit.

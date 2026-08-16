# Running a rollback anchor witness

**Audience:** someone who has a machine and wants to run a witness. You do not
need to have read the protocol.
**Decision it implements:**
[ADR-001-EXTERNAL-ROLLBACK-ANCHOR.md](ADR-001-EXTERNAL-ROLLBACK-ANCHOR.md),
"Who runs the witness".
**When it goes wrong:**
[ROLLBACK-ANCHOR-RECOVERY.md](ROLLBACK-ANCHOR-RECOVERY.md). Read that before you
need it, not during.
**Wire details, if you want them:**
[ROLLBACK-ANCHOR-PROTOCOL.md](ROLLBACK-ANCHOR-PROTOCOL.md).

---

## 1. What you are running, in one paragraph

A witness is a counter that only goes up. A Hub asks it for permission before
using its signing key: *"I am about to sign bill number 5 on this channel, and it
looks exactly like this."* The witness writes that down, fsyncs it, and answers
with a signed receipt. If the Hub ever comes back and asks for number 5 again
with a different bill, the witness refuses, in writing, under signature.

That is the whole job. The witness holds **commitments, never bills**. It cannot
pay anyone, cannot sign a bill, does not know any balance, does not know who
anyone is beyond an address string, and never talks to a blockchain.

The reason it has to be *your* machine and not the Hub's is the only interesting
part: a Hub's own safety checks all read the Hub's own state file, and none of
them survive that file going backwards. Restore a Hub from last night's backup
and it will happily sign bill 5 a second time with different numbers. Both
signatures are valid. Somebody loses money. The witness catches that only because
it was not in the backup.

---

## 2. What it needs

Very little. This is the point.

| | |
|---|---|
| CPU | One core is plenty. It hashes a small message and appends a line. |
| Memory | Tens of megabytes. The whole counter table lives in RAM and on disk. |
| Disk | A few hundred bytes per payment witnessed, appended forever. A busy Hub for a year is megabytes. |
| Network | Inbound HTTPS. Nothing outbound. |
| Blockchain | **None.** No full node, no sync, no chain data, no RPC. |
| Wallet | **None.** No funds, ever. The keys sign statements, not money. |
| Uptime | This is the real cost. See section 8. |

It does not need to be a big machine. A small VPS, a spare box, a container on
infrastructure you already have — all fine, subject to the one rule in section 5.

### Build it

```bash
cargo build -p l2-fast-pay-hub --features rollback-witness \
  --bin hpay-rollback-witness --release --locked
```

The `rollback-witness` feature is deliberately off in a default Hub build. There
is no in-process witness and no local-file mode: a configuration that would
collapse the anchor back into a file on the Hub's own disk has to be *built*, not
selected.

---

## 3. The two keys

You need two, and they must be two.

**The receipt key.** Online. It lives on the witness box, in the service
environment, and signs unattended thousands of times a day: every receipt, every
refusal, every status probe. Treat it like a TLS private key — it is exposed by
definition, and its compromise is bad but survivable.

**The authorisation key.** Offline. It signs exactly two things: the deployment
attestation, roughly monthly, and a resynchronisation authorisation during an
incident, hopefully never.

> **The authorisation key must not live on the witness machine.** Not in the
> environment file, not in the systemd unit, not in a password manager that
> syncs to it, not "temporarily while I set this up".

Here is why, in one sentence. When a Hub operator restores a Hub from an old
backup, the only thing standing between that and a double-signed bill is a human
being with the offline key deciding whether the restore is legitimate. If that
key is on the witness box, then whoever gets into the witness box can sign their
own permission slip, and the entire authorisation step in the recovery procedure
becomes decorative. The witness service refuses to run `attest` when the two keys
are the same, but it cannot tell whether the second key is sitting in the same
directory.

Keep it on a laptop, a hardware token, an offline machine, a printed backup in a
safe. Anywhere that is not the thing serving traffic.

---

## 4. Where the store goes

One append-only file. Give it a directory of its own:

```bash
sudo install -d -o hpaywitness -g hpaywitness -m 0700 /var/lib/hpay-rollback-witness
# --store /var/lib/hpay-rollback-witness/witness-store.log
```

The file's first line is a header written once, at creation, containing the
store's `witness_instance_id`. Every Hub pins that value on first contact. If the
file is deleted and re-created, the id changes, and every Hub pointed at you
refuses to sign until a human works out why. That is correct behaviour and it is
the single most valuable check in this design — re-provisioning a witness with a
fresh counter is the cheapest possible attack on it.

So:

- **Back the store up.** Losing it is an incident (Procedure B in the recovery
  document), and it means every Hub you witness stops signing until you rebuild
  the store to a position at or above where those Hubs already are.
- **Never delete it to "start clean".** If you think you need to, you are in an
  incident; go and read the recovery document.
- **Never truncate or compact it.** The log slice covering a gap is the evidence
  an operator needs to reconstruct missing bills. It is tiny. Keep all of it.

---

## 5. The one rule: separate backup sets

> **The witness store must not be in the same backup set as any Hub it
> witnesses.**

Not the same snapshot, not the same volume group, not the same nightly job, not
the same restore runbook, not the same VM image.

If they are backed up together, they are restored together, and a Hub restored
alongside its own witness comes back with the counter exactly where the Hub
expects it. Every signature verifies. Both sides come back internally consistent
at an older position, and the Hub signs bill 5 for the second time as if nothing
happened.

**One narrow form of this is caught, and only one.** The Hub scans its own state
directory and the directory beside it for a witness durable store — by content,
not by filename — and on a mainnet profile it refuses to start if it finds one,
naming the file. Off mainnet it starts and publishes
`witness_store_in_hub_state_tree: true`. So the laziest version of this mistake,
where the store lands in the same directory as the Hub state and the keys, is
caught for you.

**Everything past that is not.** Move the store one directory further out, onto a
second disk on the same host, into a container volume mounted from the same
snapshot, or onto a different machine that your nightly job happens to sweep up
with the Hub — and nothing detects it. No message, no counter, no attestation and
no scan. The check is a lint that a single `mv` defeats; it exists so the weak
configuration cannot be reached by accident or by drift, not because it is a
boundary.

So the real defence is where you put the file and how you back it up, and that
part is yours. The code catches the version of this mistake that people make by
accident. It cannot catch the version you make on purpose, and it cannot catch
the one your backup software makes on your behalf.

The corollary, if you run the witness for your own Hub: separate infrastructure
means separate infrastructure. Different host, different backup schedule,
different restore procedure, ideally a different provider. If your disaster
recovery plan restores both from one snapshot, you do not have an anchor, you
have a very elaborate copy of your Hub's state file.

Be honest with yourself about this. Nobody will check it, which is exactly why it
matters.

---

## 6. Running it

### First run: create the store and read its identity

```bash
export HPAY_WITNESS_RECEIPT_SECRET_HEX=<64 hex characters, generated on this box>

hpay-rollback-witness \
  --witness-id acme-witness-1 \
  --store /var/lib/hpay-rollback-witness/witness-store.log \
  instance
```

It prints four lines. Keep them; Hub operators need three of them.

```
witness_id=acme-witness-1
witness_epoch=1
witness_receipt_address=1Abc...
witness_instance_id=9f2c...
```

Pick a `witness_id` that identifies you and stick to it. It is pinned in every
Hub's configuration and changing it is a configuration incident on every one of
them.

### Serve

```bash
hpay-rollback-witness \
  --witness-id acme-witness-1 \
  --store /var/lib/hpay-rollback-witness/witness-store.log \
  serve --listen 127.0.0.1:8791
```

Bind loopback and put HTTPS in front of it with a reverse proxy, exactly as the
Hub is deployed. Hubs on a mainnet profile refuse plaintext transport outright,
so a witness without TLS is a witness nobody serious can use.

Two routes, both `POST`, both answering with a signed message or nothing:

- `/witness/v1/anchor` — reserve a position. This is the money path.
- `/witness/v1/status` — liveness and current position. Advances nothing.

Run it under its own unprivileged service account, with the store directory
writable by that account and nothing else. The
[Hub's systemd unit](../../scripts/hpay-fast-pay-hub/hpay-fast-pay-hub.service)
is a reasonable model for the hardening.

---

## 7. Pointing a Hub at it

A Hub operator asking to use your witness needs five things from you. Four are
public values you can send in an email; the fifth you have to sign.

| What you send | Where it comes from |
|---|---|
| The URL | Your HTTPS endpoint, e.g. `https://witness.acme.example` |
| `witness_id` | The `--witness-id` you chose |
| `witness_receipt_address` | Printed by `instance` |
| `witness_authorisation_address` | Printed by `attest`, on stderr |
| The signed attestation | `attest`, below |

The attestation is bound to **one exact Hub identity**, so you issue one per Hub,
and you need their Hub address first.

```bash
# Run this OFF the serving host, on the machine that holds the offline key.
# It needs a readable copy of the store to name the instance id.
hpay-rollback-witness \
  --witness-id acme-witness-1 \
  --store ./witness-store.log \
  attest \
  --hub-identity 1HubAddressGoesHere \
  --authorisation-secret-hex <offline key> \
  --posture neutral-third-party \
  --witness-operator "Acme Ltd" \
  --separation-statement "Witness runs on independent hosting at a different provider from this Hub, with its own backup schedule and its own restore procedure. No shared snapshot, volume or backup job. Receipt key on the witness host; authorisation key offline, held by a named person who does not operate the Hub." \
  --validity-days 30 \
  > hub-1-attestation.json
```

**`--posture` is one of three**, and it changes what the guarantee is worth, so
pick the true one:

- `counterparty` — you are the other side of the channels this Hub settles.
- `neutral-third-party` — you have no stake in the channels.
- `same-operator-separate-infrastructure` — you also run the Hub, but on
  genuinely separate infrastructure with separate backups.

There is deliberately no "same host" value. A configuration that wants it cannot
express it.

**`--separation-statement` is free text and it is read by a human at three in the
morning.** Write what actually separates your failure domain from theirs:
hosting, backup schedule, key custody. Do not write "separate". Write what is
separate.

**`--validity-days` is weeks, not years.** The attestation expires and the Hub
refuses until you sign a fresh one. That is the point: it forces someone to look
at whether the statement is still true, rather than setting it once in 2026 and
finding out in 2029 that the witness was migrated onto the Hub's cluster.

The Hub side then looks like this — one address, four pinned values, no code:

```bash
export HACASH_HUB_ROLLBACK_WITNESS_ID=acme-witness-1
export HACASH_HUB_ROLLBACK_WITNESS_RECEIPT_ADDRESS=1Abc...
export HACASH_HUB_ROLLBACK_WITNESS_AUTHORISATION_ADDRESS=1Def...
export HACASH_HUB_ROLLBACK_WITNESS_ATTESTATION_FILE=/etc/hpay-fast-pay-hub/witness-attestation.json

scripts/START-HUB-WITH-REMOTE-WITNESS.sh https://witness.acme.example
```

Changing witness later is a change to those five values. It is never a code
change, a rebuild, or a conversation with anyone but the new witness operator.

---

## 8. Verifying it works

### On your box, before anyone points at you

**The store exists and has an identity.** `instance` prints a non-empty
`witness_instance_id`. Run it twice; the id must be identical. If it changes, you
are creating a new store each time and your `--store` path is wrong.

**It answers a status probe.** Substitute a Hub address you expect to serve —
an unknown Hub is fine here and reports a counter of zero. The nonce must be 64
hexadecimal characters; a shorter one is rejected as malformed and you get an
empty `400` back, which is easy to misread as the service being broken.

```bash
NONCE="$(openssl rand -hex 32)"
curl -sS https://witness.acme.example/witness/v1/status \
  -H 'content-type: application/json' \
  -d "{\"hub_identity\":\"1HubAddressGoesHere\",\"witness_id\":\"acme-witness-1\",\"nonce\":\"${NONCE}\"}"
```

```json
{"status":{"status_version":1,"witness_id":"acme-witness-1","witness_epoch":1,
 "witness_instance_id":"aca98c…","witness_boot_id":"6a7786…",
 "hub_identity":"1HubAddressGoesHere","nonce":"875fb6…",
 "counter_value":0,"channels":[],"observed_at":1786893331},
 "signature_hex":"03808a…"}
```

Check three things in it:

1. `nonce` echoes exactly what you sent. A status without your nonce is a
   recording, not a liveness proof.
2. `witness_instance_id` matches what `instance` printed. If it does not, you are
   talking to a different store than you think — a staging box, an old container,
   a load balancer with two backends. Fix that now; it is the exact condition
   that makes every Hub pointed at you refuse.
3. `counter_value` and `channels` are what you expect for that Hub.

**It survives a restart.** Stop it, start it, probe again. `witness_instance_id`
and `counter_value` must be unchanged; `witness_boot_id` will differ, and that is
the only thing that should. The counter is rebuilt by replaying the log from
disk, not held in memory, and this is the check that proves it.

**A second witness on the same store is not a thing.** Do not run two processes
against one store file, and do not put the store on network storage shared
between instances. One store, one process.

### Once a Hub is pointed at you

The Hub does the real verification, and it tells you the answer. Ask its operator
for `GET /v1/readiness/mainnet` and read the `rollback_anchor` object. (It is not
on `/v1/health`: that endpoint does no I/O by design, so it has no live evidence
to publish.) A `rollback_anchor` of `null` means the Hub has no verified live
witness at all — not configured, not reachable, or not verifying against its
pinned keys. When it is present:

- `witness_id`, `witness_instance_id`, `witness_operator`, `witness_posture` —
  what the Hub thinks it is talking to. Check they are you.
- `witness_endpoint_is_local` — must be `false`. If it is `true`, that Hub is
  talking to something on its own host and you are not its anchor.
- `witness_store_in_hub_state_tree` and `witness_co_located` — must both be
  `false`. `true` means the Hub found a witness counter store inside its own
  backup set. Whether or not it is *your* store, that Hub has an anchor problem
  and should not be signing.
- `attestation_valid` and `attestation_expires_unix` — diary the expiry.
- `startup_probe_agreed` — the Hub and you agree on every channel it holds.

A Hub that starts, probes, and prints `witness agreed on every channel this Hub
holds` is a working anchor. That line is the acceptance test.

### Drill it before you rely on it

Once, on a test Hub, with no real value at stake:

1. Take a Hub backup, make a few payments, restore the Hub from the backup.
2. Confirm the Hub refuses with `rollback_anchor_hub_behind_witness` and does
   **not** sign.
3. Walk Procedure A in the recovery document end to end, including producing the
   gap export from your log and signing a resynchronisation with the offline key.

If you have not done this, you do not know that your offline key is reachable in
an incident, and finding that out during a real one is the worst possible time.

---

## 9. What you are taking on

Say yes to this with your eyes open.

**Availability is a real obligation.** When you are down, every Hub pointed at
you stops signing. Not degraded — stopped. That is deliberate and correct, and
there is no bypass flag, so your outage is their outage. If you cannot commit to
a reasonable uptime, say so before someone points a Hub at you rather than
after.

**You will be asked to authorise a recovery.** Sooner or later a Hub operator
restores from a backup and needs a resynchronisation signed. That is a human
decision requiring evidence, made against
[Section 5 of the recovery document](ROLLBACK-ANCHOR-RECOVERY.md#5-authorisation-who-may-approve-a-resynchronisation),
possibly at an unhelpful hour. You are the check on that operator. Take it
seriously or do not offer the service.

**You will not be asked to hold money, and you cannot lose theirs.** Your keys
sign statements about positions. There is no path from your key material to
anybody's funds. The worst a compromised receipt key does is let an attacker
forge receipts for a Hub that is *also* lying about its position — which still
requires the Hub's own signing key.

**You learn very little about them.** Commitments, serials, channel identifiers,
counters. No balances, no amounts, no bill contents, no payer or payee. If a Hub
operator asks what you can see, that is the honest answer.

---

## 10. Things that must never be done

Short list. Each one turns a working anchor into a decoration.

1. **Never lower the counter or a channel's serial.** Not to match a Hub, not
   temporarily, not to test something. It only goes up. A counter that can go
   down is a file, and a file is not an anchor.
2. **Never restore the store from a backup to make a Hub's refusal go away.**
   That deletes the record of what was signed and replaces a detected problem
   with an undetectable one.
3. **Never re-create the store to "reset".** A fresh witness starts at zero and
   agrees with everything. That is not agreement, it is amnesia.
4. **Never put the offline authorisation key on the witness host.** Section 3.
5. **Never share a backup set with a Hub you witness.** Section 5. This one is
   invisible until the day it matters.
6. **Never run two witness processes against one store.**
7. **Never write an attestation you cannot defend.** The posture and the
   separation statement are published by every Hub that trusts you, to every
   wallet that reads that Hub's health. They are a statement about you.

---

## 11. Local development

If you just want a witness to develop against, do not follow this document. Run:

```
scripts/DEV-ONLY-HUB-AND-WITNESS-SAME-HOST.sh      # or the .bat on Windows
```

It starts a Hub and a witness together on one machine, which is the
configuration this entire document tells you not to build. It prints why at
startup, in full, every time. It exercises the real protocol — receipts,
refusals, startup probes, recovery drills — and it anchors nothing, because the
witness is in the same failure domain as the thing it is witnessing.

That is fine for a laptop. It is not fine anywhere that holds value, and the Hub
publishes `witness_endpoint_is_local: true` and
`witness_operator: LOCAL-DEV-NO-SEPARATION` in its `rollback_anchor` object so
that anyone reading `/v1/readiness/mainnet` can tell the difference.

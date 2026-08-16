# Rollback anchor: operator recovery procedure

**Status:** design, written before the code, per ADR-001 action item 1.
**Audience:** the person on call. Not the person who built this.
**Companion document:** [ROLLBACK-ANCHOR-PROTOCOL.md](ROLLBACK-ANCHOR-PROTOCOL.md)
defines the messages this procedure refers to.
**Decision it implements:**
[ADR-001-EXTERNAL-ROLLBACK-ANCHOR.md](ADR-001-EXTERNAL-ROLLBACK-ANCHOR.md).

---

## STOP. Read this box before you touch anything.

The Hub has refused to sign. **That refusal is the system working, not the system
broken.** It means the external witness holds a record of a signature this Hub's
state does not know about. The most likely cause is that this Hub was restored
from a backup.

If you make the Hub sign anyway, it will co-sign a bill serial that has already
been co-signed with different balances. Both signatures are valid to the
contract. Whichever reaches `finalize` first wins and the other party's money is
gone. That is the exact loss this refusal just prevented.

**Do not, right now:**

1. Do not restart the Hub repeatedly hoping it clears. It will not, and each
   restart destroys timing evidence.
2. Do not restore the witness from a backup to "match" the Hub. That deletes the
   only record of what was signed.
3. Do not disable, bypass, or reconfigure the anchor check to restore service.
   Service being down is the cheap outcome here.

**Do, right now, in this order:**

1. Read the refusal identifier the Hub printed. Find it in
   [Section 2](#2-what-the-hub-is-telling-you) below.
2. Run the evidence capture in [Section 3](#3-capture-evidence-before-anything-else).
   It takes minutes and everything after it depends on it.
3. Answer the three questions in [Section 4](#4-which-situation-are-you-in).
   Do not skip to a procedure before you have answered them.

**Expected time to safe restoration: hours, not minutes.** If someone is telling
you this needs to be back in five minutes, the correct answer is that the
channels stay frozen and nobody loses money while frozen. Tell them that.

---

## 1. What the anchor is, in one paragraph

Every safety check inside this Hub is enforced against its own state file. The
ledger refuses a bill whose serial is not exactly `previous + 1`, refuses a
commit when the head moved, and allows at most one unresolved progression per
channel. None of that survives the state file going backwards, because the file
is the thing that lied. The anchor is a counter held by a separate service —
the **witness** — on separate infrastructure, which only ever goes up. The Hub
asks the witness before it uses its signing key and refuses if the witness has
already seen something this Hub's state does not contain.

The witness holds **commitments, never bills**. It cannot pay anyone, cannot
sign a bill, and does not know any balance. It knows only: *for this Hub, on
this channel, a bill at serial N with commitment X was reserved at counter C.*

---

## 2. What the Hub is telling you

The Hub emits exactly one of these identifiers. Find yours.

| Identifier | Plain meaning | Go to |
|---|---|---|
| `rollback_anchor_hub_behind_witness` | The witness has seen a higher serial on a channel than this Hub's head. **This is the restore case.** | [Procedure A](#procedure-a--the-hub-is-behind-the-witness) |
| `rollback_anchor_fork_at_serial` | Hub and witness are at the *same* serial with *different* bill commitments. Two different bills exist at one position. Worse than being behind. | [Procedure A](#procedure-a--the-hub-is-behind-the-witness), then read [Section 8](#8-where-this-procedure-cannot-be-made-safe) |
| `rollback_anchor_counter_skipped` | The witness's global counter advanced further than this Hub accounts for. Someone else used this Hub's counter. | [Procedure C](#procedure-c--two-hubs-are-live-split-brain) |
| `rollback_anchor_witness_behind_hub` | The witness's record is *lower* than this Hub's head. The witness lost state. | [Procedure B](#procedure-b--the-witness-is-behind-the-hub) |
| `rollback_anchor_witness_instance_changed` | The witness's durable store identity changed. It was re-provisioned, or you are talking to a different witness. | [Procedure B](#procedure-b--the-witness-is-behind-the-hub) |
| `rollback_anchor_witness_unreachable` | Network, DNS, TLS, or timeout. No evidence either way. | [Section 6](#6-the-witness-is-simply-down) |
| `rollback_anchor_witness_is_not_external` | The configured witness failed the separation checks — its URL names this host or plaintext, it shares this Hub's key, or its durable store is sitting inside this Hub's own backup set. | [Section 7](#7-the-witness-failed-the-separation-check) |
| `rollback_anchor_attestation_missing_or_expired` | The deployment attestation naming who runs the witness is absent or out of date. | [Section 7](#7-the-witness-failed-the-separation-check) |
| `rollback_anchor_channels_latched_in_refusal` | Published on `/v1/readiness/mainnet`, not on the signing path. One or more channels are **already condemned** in this Hub's durable state by an earlier refusal, and will not sign again until the procedure that condemned them is completed. The count is in `limitations`. This appears whether or not a witness is configured now: a latch lives in `hub-state.json`, so removing the witness configuration does not clear it. | Whichever procedure the original refusal named — re-read your incident record, not this table |

**You do not have to catch the log line.** A Hub whose startup probe did not
agree still starts, and it publishes the identifier above as a blocker on
`/v1/readiness/mainnet`, with the same identifier spelled out in `limitations`.
Read it from there. If the process is not running at all, that is not the anchor:
the anchor refuses signatures, not the process. Look at the exit status and the
configuration, and note that a partial `--rollback-witness-*` configuration is
refused outright at startup on purpose.

---

## 3. Capture evidence before anything else

Do this before you change one byte. Everything downstream — the authorisation,
the counterparty conversation, the post-incident review — needs it, and some of
it is destroyed by a restart.

Copy all of the following into an incident directory, off this host:

1. **The Hub's refusal record.** The identifier, the channel
   (`binding_commitment`), the Hub's own head serial and bill commitment, the
   Hub's `journal_sequence` and `journal_head_hash`, and the timestamp.
2. **The witness's signed refusal.** The witness does not just say no — it
   returns a signed `HubWitnessRefusalV1` stating its own high-water counter and
   its high-water serial and bill commitment for that channel. **This signed
   object is the single most important artefact in the incident.** Save it
   verbatim. Do not reformat it.
3. **The Hub's state file and journal, untouched.** Take a copy. Do not repair,
   compact, or migrate anything.
4. **What was restored, and from when.** The backup set identifier, its
   timestamp, who ran the restore, and why. If nobody restored anything, write
   that down too — that is a much more serious finding and it changes
   [Section 4](#4-which-situation-are-you-in).
5. **The witness's gap export.** Ask the witness operator for the signed
   append-only log slice covering `hub_head_serial + 1` through
   `witness_head_serial`, for each affected channel. This is a read-only query.
   It lists, per serial, the reserved bill commitment and the counter value.

If you cannot obtain item 2 or item 5, you cannot complete any procedure in this
document safely. Say so and escalate rather than proceeding on inference.

---

## 4. Which situation are you in

Answer all three. In this order. Do not reorder them — question 1 is first
because acting on the others while it is unanswered is the one move that can
turn a frozen Hub into a lost-funds incident.

### Question 1 — Is a second Hub instance live right now?

Two Hubs holding the same key on the same channels is split brain. Resynchronising
one of them while the other is signing produces exactly the double-signature the
anchor exists to prevent.

Check, in this order:

- Ask the witness whether it currently holds a live lease for this
  `hub_identity`, and for which `witness_boot_id`/client. A witness that has
  issued a receipt in the last few minutes to a client that is not this process
  is a live second Hub.
- Check the `previous_counter_value` on the witness's most recent receipt for
  this Hub against what this Hub last recorded. A jump means something else
  consumed counter values.
- Check your own infrastructure: old VM not decommissioned, failover that
  activated, container that was never stopped, a "test" Hub pointed at
  production keys.

**If yes → [Procedure C](#procedure-c--two-hubs-are-live-split-brain). Stop
everything else.**

### Question 2 — Which side moved backwards?

Compare the witness's high-water serial to this Hub's head serial, per channel.

- Witness higher than Hub → the **Hub** moved backwards.
  → [Procedure A](#procedure-a--the-hub-is-behind-the-witness)
- Hub higher than witness → the **witness** moved backwards.
  → [Procedure B](#procedure-b--the-witness-is-behind-the-hub)
- Equal serial, different bill commitment → a fork. Two different bills exist at
  one serial. Treat as Procedure A and read Section 8 before you finish.

### Question 3 — Does the restore story match the gap?

Take the backup timestamp from evidence item 4 and the timestamps on the witness
gap export from item 5. The gap should begin at, or just after, the backup
timestamp, and end at the restore.

- **They match.** Ordinary disaster recovery. Procedure A is designed for this.
- **The gap starts before the backup**, or there is no restore at all, or the
  gap covers a period nobody can account for. **This is not a recovery incident.
  It is a security incident.** Freeze everything, preserve evidence, and escalate
  to whoever owns security response before running any procedure in this
  document. Resynchronising would destroy the evidence and may be exactly what an
  attacker is waiting for you to do.

---

## Procedure A — the Hub is behind the witness

**This is the normal case: a Hub restored from a backup taken before some bills
were signed.**

### What the Hub sees

Its state is internally perfect. Every check inside the file passes. The ledger
head for channel `C` is a fully-signed bill at serial `N`, its journal is intact
and its checkpoint verifies. Nothing local is wrong, because nothing local can
see the problem. The only thing that knows is the witness, which reports serial
`M > N` for that channel with bill commitment `X`.

The `M - N` bills in between were signed by this Hub's key, are held by the
counterparty, and are valid to the contract. They exist. Your state has
forgotten them. Your job is to get them back, not to work around them.

### The one rule that makes this safe

> **A resynchronisation moves the Hub forward to the witness. It never moves the
> witness backward to the Hub.**

The witness's counter and its per-channel high-water serial are never lowered by
this procedure — not by one. Everything below is about recovering the *bills*
that fill the gap so that the Hub can honestly adopt the witness's position. If
the bills cannot be recovered, the channel is retired, not resynchronised.

### Steps

**A1. Freeze the affected channels.** They are already frozen — the Hub is
refusing. Do not unfreeze. Confirm the Hub is not serving new payment requests
for any channel in the gap.

**A2. Determine the exact gap, per channel.** From the witness export:
serials `N+1 .. M`, each with its reserved bill commitment. Write them down.
This list is the checklist you will tick off.

**A3. Ask the counterparty for the missing bills.** For each channel, request
every fully-signed bill from serial `N+1` to `M`. The counterparty holds them;
that is why they are the counterparty. Send them the serial list and the bill
commitments from the witness so they can identify exactly what you need.

This is a normal, expected request. It is not an admission of anything beyond
"we restored from backup and need copies of bills you already hold."

**A4. Verify every returned bill. All three checks, no exceptions.**

For each bill at serial `S` in `N+1 .. M`:

1. Its commitment equals the commitment the **witness** recorded at serial `S`.
   (If it does not, the counterparty is presenting a bill that was never
   reserved. Stop. Escalate. Do not accept it.)
2. Its Hub-side signature verifies against **this Hub's** signing key.
3. Its serial chains: it extends the bill at `S-1`, and the balances are a
   consistent progression from the head at `N`.

A bill that fails any of the three is not a bill for this purpose. It does not
partially count.

**A5. Decide the outcome per channel.** There are exactly two.

- **Every serial `N+1 .. M` reconstructed and verified.** The gap is closed. The
  Hub can adopt the bill at serial `M` as its head. Proceed to A6 with
  `gap_resolution = ReconstructedFromVerifiedBills`.
- **One or more serials could not be reconstructed.** The channel **cannot be
  returned to service**. It is retired: the parties settle at the highest
  mutually verified position, or the channel closes through the L1 path. Proceed
  to A6 with `gap_resolution = ChannelRetiredWithoutReconstruction` and a
  counterparty acknowledgement (see [Section 5](#5-authorisation-who-may-approve-a-resynchronisation)).

There is no third outcome. In particular there is no "adopt serial `M` and move
on" without the bills — see item 7 of
[Section 9, things that must never be done](#9-things-that-must-never-be-done).

**A6. Obtain the resynchronisation authorisation.** This is a
`WitnessResyncAuthorisationV1`, issued by the witness operator's **offline**
authorisation key — deliberately not the online receipt key, so compromising the
running witness does not let anyone forge a resync. See
[Section 5](#5-authorisation-who-may-approve-a-resynchronisation) for who signs
and what they need to see.

The authorisation names one channel. There is no blanket authorisation covering
several channels; if four channels are gapped, that is four authorisations, each
with its own evidence.

**A7. Apply it.** The Hub, on presentation of a valid authorisation:

- verifies the authorisation signature against the pinned offline key, that it
  has not expired, and that it names this `hub_identity`, this
  `binding_commitment` and this witness;
- verifies that `baseline_serial` equals the witness's *current* recorded serial
  — never lower, and never a serial the witness has not seen;
- verifies the supplied bill at `baseline_serial` against `baseline_bill_commitment`;
- writes the new head and journals the resynchronisation as a first-class event;
- refuses everything if any of the above fails.

The witness records the authorisation in its own append-only log at the same
time. **The resynchronisation is itself witnessed.** You cannot perform one by
editing a file on the Hub, and there is a permanent external record that it
happened.

**A8. Restart and confirm.** The startup probe should now agree with the witness
on every channel. If it does not, you have missed a channel — go back to A2. Do
not proceed on a partial agreement.

**A9. Write the incident up.** Include the backup gap, every serial recovered,
every serial not recovered, and who authorised. This document exists because
someone did this before you; the next person needs yours.

---

## Procedure B — the witness is behind the Hub

The witness reports a *lower* serial than the Hub's head, or its store identity
changed. The witness lost state, was re-provisioned with a fresh counter, or you
are pointed at a different witness than you think.

**This is not a case where you may proceed by letting the witness catch up
silently.** A witness that can be reset is not an anchor, and a Hub that
tolerates a reset witness has no anchor either.

1. **Do not sign.** The Hub will refuse. Leave it refusing.
2. Confirm which witness you are actually talking to: the endpoint, the pinned
   `witness_id`, the pinned receipt public key, and the `witness_instance_id` on
   the last receipt you hold. A changed `witness_instance_id` means a new durable
   store, full stop.
3. If you are pointed at the **wrong** witness (a staging instance, a stale DNS
   record, a failover that pointed somewhere new), fix the configuration and
   restart. That is a configuration incident, not a recovery one.
4. If you are pointed at the **right** witness and it genuinely lost state, the
   witness must be rebuilt to a position **at or above** the Hub's current head,
   from the witness's own backups and from the Hub's records, under the same
   authorisation process as Procedure A — and the rebuild must be documented as
   a period during which the anchor guarantee did not hold.
5. Until it is rebuilt and re-attested, `external_rollback_anchor_ready` is
   `false` and must be reported `false`. The Hub is running without an anchor.
   Treat that as a service-affecting outage, because it is.

**Honest note:** a witness that lost its state has already told you something
about how it is operated. Fix that before restoring service, not after.

---

## Procedure C — two Hubs are live (split brain)

**This is the most dangerous state in this document.** Two processes hold the
same signing key and both believe they own the channels.

1. **Stop the Hub you are looking at. Now.** Do not investigate first. A
   stopped Hub cannot double-sign.
2. Identify and stop the other one. Check every host, VM, container, failover
   target and orchestrator that could have started a Hub with this key.
3. Only when you are certain that **zero** Hubs are running, ask the witness for
   the true position of every channel. The witness's record is authoritative
   here precisely because it was outside both of them.
4. Bring up exactly one Hub. If its state is behind the witness — it will be —
   run Procedure A against the witness's position.
5. Rotate the Hub signing key if you cannot account for where the second
   instance's copy of it came from.
6. This is a post-incident review with a named owner, not a ticket you close.

---

## 5. Authorisation: who may approve a resynchronisation

A resynchronisation moves the Hub's position. The Hub operator is exactly the
party who benefits from a rollback, so **the Hub operator cannot authorise their
own resynchronisation.** The authorisation must be signed by a key the Hub
operator does not hold.

| Gap resolution | Required signatures | Required evidence |
|---|---|---|
| `ReconstructedFromVerifiedBills` | Witness operator's **offline authorisation key** | The signed witness refusal (evidence item 2), the signed witness gap export (item 5), and, for every serial in the gap, the verified bill and the three A4 check results |
| `ChannelRetiredWithoutReconstruction` | Witness operator's offline authorisation key **and** the counterparty for that channel | All of the above, plus a counterparty acknowledgement naming the highest mutually agreed serial and stating that they accept the channel is being retired at that position |

Additional requirements that hold in both rows:

- **One authorisation per channel.** No blanket authorisations.
- **Short expiry.** Hours, not days. An authorisation that can sit in a
  configuration file is a permanently disabled check.
- **Offline key.** The witness's receipt key is online and signs unattended, all
  day, without a human. The authorisation key is not that key, is not on the
  witness host, and is used only for incidents. If they are the same key,
  compromising the running witness is enough to forge a resynchronisation, and
  the whole authorisation step is decorative.
- **The witness logs it.** The authorisation is recorded in the witness's
  append-only log before the Hub applies it.

### When the witness operator *is* the Hub operator

ADR-001 deliberately leaves the posture open: the witness may be run by the
counterparty, a neutral third party, or the same operator on separate
infrastructure. In the third posture, the same organisation holds both keys, and
the separation of duties above is procedural rather than cryptographic.

Say so out loud rather than pretending otherwise. In that posture:

- the authorisation key must still be offline and held by a **different named
  person** than the one performing the recovery;
- both names go in the incident record;
- the Hub publishes its posture on `/v1/readiness/mainnet`, as the
  `rollback_anchor` document beside the flag (see the protocol document), so a
  counterparty can see what the guarantee is actually worth without asking.

This is weaker. It is not nothing — it still means a restore cannot be
laundered into service by one person at 3am without a second signature — but
anyone relying on this Hub is entitled to know which posture is in use.

---

## 6. The witness is simply down

Network partition, DNS, TLS expiry, the witness host is rebooting.

**The Hub refuses to sign. That is correct and it is not negotiable.** An
unreachable oracle is not evidence. The Hub already behaves this way when the
fullnode is unreachable, for the same reason.

**The Hub keeps running.** Refusing to sign and refusing to start are different
things, and the second one is worse: a Hub that will not start cannot serve a
cooperative close, cannot answer readiness, and cannot tell you why. So a Hub
whose witness was unreachable at boot starts, serves reads, readiness and
cooperative close, refuses every signature, and publishes
`rollback_anchor_witness_unreachable` in `blockers` on `/v1/readiness/mainnet`.
Nothing is waived by it running: the startup probe has not agreed, and the
signing path gates on that.

1. Confirm it is really reachability and not a refusal: a refusal is *signed*, a
   reachability failure is not. If you have a signed refusal, you are not in this
   section.
2. Fix the reachability problem. Certificates, DNS, firewall, capacity.
3. The Hub resumes on its own once the witness answers. No authorisation, no
   resynchronisation, nothing to approve — because nothing moved. It re-runs the
   startup probe every 30 seconds while the refusal is a reachability one, so you
   do not need to restart it, and restarting it buys you nothing. Only a probe
   that agrees on every channel restores signing.
4. If the outage is long, the correct escalation is "restore the witness", never
   "bypass the witness".

There is no supported configuration in which the Hub signs while the witness is
unreachable. If someone asks for one, the answer is that the bounded pilot
profile exists for deployments that accept Hub trust, and it reports
`trustless_finality: false` honestly. Use that instead of lying about the anchor.

---

## 7. The witness failed the separation check

`rollback_anchor_witness_is_not_external` or
`rollback_anchor_attestation_missing_or_expired`.

The Hub has decided its configured witness is not distinguishable from its own
host, or that nobody has attested to where the witness runs. See the degradation
guard section of [ROLLBACK-ANCHOR-PROTOCOL.md](ROLLBACK-ANCHOR-PROTOCOL.md) for
what is checked.

This is a configuration incident. Someone pointed the Hub at a witness on
localhost, or reused the Hub's key for the witness, or left a witness counter
store inside the directory tree that gets backed up and restored with the Hub,
or let the deployment attestation lapse.

**If the refusal names a file**, that is a witness durable store the Hub found
in its own backup set. Restoring this Hub would restore that counter along with
it, which is the one thing an anchor must not allow. Move the store onto
infrastructure that is genuinely separate from this Hub's failure domain — not
to another directory on the same disk — and re-attest. Do not simply delete it
without first establishing whether it is the store your live witness is using;
if it is, deleting it is destroying the anchor's record, which
[Section 9](#9-things-that-must-never-be-done) item 3 forbids.

1. Do not "fix" it by relaxing the check.
2. Find out whether the witness has *always* been in that position, or whether
   it moved. If it has always been there, this Hub has never had an anchor and
   every claim it published to that effect was wrong. That is a disclosure
   question, not just a config fix.
3. Move the witness to infrastructure that is genuinely separate from the Hub's
   failure domain, re-attest, restart.

---

## 8. Where this procedure cannot be made safe

Stated plainly, because smoothing it over would make this document worse.

**A fork at the same serial cannot be repaired by this procedure.** If the Hub
and the witness are at the same serial with different bill commitments, two
different bills were signed at one position. One of them may already be on its
way to `finalize`. Recovering "the correct one" is not something you can
determine locally — both are validly signed by this Hub. All this procedure can
do is freeze the channel, produce the evidence, and hand it to the parties. The
resolution is a settlement between the parties, possibly through the L1 dispute
path, not a state repair. If the anchor is working correctly this should be
unreachable; reaching it means the anchor was bypassed, absent, or defeated at
some earlier point, and that is the thing to investigate.

**A co-restored witness is undetectable from the Hub.** If the witness's durable
store was inside the same backup set as the Hub's state and both were restored
together, both come back internally consistent at the older position and every
check in this system passes. No message, no signature and no counter can
distinguish that from normal operation. This is the entire reason the witness
must not live in the Hub's failure domain, and the reason the separation checks
exist even though they are weak. If you are recovering a Hub and the witness
came out of the same backup, **you have no anchor for that window** and must
treat the channels as unanchored regardless of what the Hub reports.

**Reconstruction depends on the counterparty's cooperation and their records.**
Procedure A works because the counterparty holds the bills. If they cannot or
will not produce them, no amount of Hub-side work recovers the gap. The channel
retires. Build the relationship and the record-keeping expectation before you
need them, not during.

**The gap serials, once retired, are gone.** Payments in an unreconstructed gap
are not recoverable by this procedure. They may be recoverable commercially
between the parties. That is a different conversation and this document does not
pretend to have it.

---

## 9. Things that must never be done

Each of these has an obvious appeal at 3am. Each one causes the loss the anchor
exists to prevent.

1. **Never re-sign the gap.** Do not generate fresh bills at serials `N+1 .. M`
   to "catch up" to the witness. Those serials already have signed bills, held by
   the counterparty. Signing new ones is manufacturing the exact double-signature
   the anchor prevented, by hand, deliberately. If you do this, both bills are
   valid, whichever reaches `finalize` first wins, and someone loses their money.
   This is the single most important line in this document.
2. **Never lower the witness's counter or serial.** Not to match the Hub, not
   "temporarily", not to test something. The counter only goes up. A witness
   whose counter can go down is a file, and a file is not an anchor.
3. **Never restore the witness from backup to resolve a Hub-behind situation.**
   That deletes the record of what was signed and replaces a detected problem
   with an undetectable one.
4. **Never point the Hub at a different witness instance to get past a refusal.**
   A fresh witness starts at zero and agrees with everything. That is not
   agreement, it is amnesia.
5. **Never disable the anchor check, raise a bypass flag, or set
   `external_rollback_anchor_ready` by configuration.** The flag is a
   measurement, not a switch. If you need to run without an anchor, run the
   bounded pilot profile, which says so honestly in its own output.
6. **Never resynchronise while a second Hub might be live.** Question 1 of
   Section 4 exists for this. Answer it first, every time.
7. **Never adopt the witness's serial without the bill.** "The witness says
   serial 9, so I will set our head to 9" leaves the Hub asserting a position it
   cannot substantiate, with unknown balances, and the next bill it signs is
   built on a fiction. Adopt a serial only against a bill that passed all three
   A4 checks.
8. **Never edit the state file, the journal, or the checkpoint by hand.** Not to
   fix, not to inspect-and-save, not to reformat. Copy it, work on the copy,
   leave the original alone.
9. **Never let an authorisation live in a config file.** Short expiry, one
   channel, one incident, then it is dead.
10. **Never remove the witness configuration to clear a latch.** Deleting the
    `--rollback-witness-*` flags is the cheapest-looking way out of a refusal and
    it is the worst one: it does not resolve the rollback, it removes your only
    way of seeing it. The condemnation is in `hub-state.json`, not in the flags,
    and the Hub goes on refusing that channel with the anchor gone — which is
    correct, and is the point. A latch is cleared by completing the procedure
    that raised it and by nothing else. If the Hub still refuses after you
    removed the anchor, that is the design working, not a bug to route around.

---

## 10. Quick reference card

Print this. Tape it to something.

```
REFUSAL AT 3AM
  1. Is a second Hub live?              -> if yes: STOP EVERYTHING, Procedure C
  2. Who moved backwards?
       witness ahead  -> Procedure A    (the normal restore case)
       hub ahead      -> Procedure B    (the witness lost state)
       same serial,
       different bill -> Procedure A + read Section 8
  3. Does the gap match the backup?
       no             -> SECURITY INCIDENT, freeze, escalate, do not resync

ALWAYS
  Capture the signed witness refusal before anything else.
  Resync moves the Hub forward to the witness. Never the witness back to the Hub.
  Adopt a serial only against a bill that verifies against
      (a) the witness's commitment, (b) this Hub's signature, (c) the chain.
  Missing bill = channel retires. There is no third option.

NEVER
  Re-sign the gap.  Lower the counter.  Restore the witness to match.
  Swap witnesses.   Bypass the check.   Resync during split brain.

The frozen Hub is the safe Hub. Slow is fine. Wrong is not.
```

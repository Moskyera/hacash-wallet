# ADR-001: The external monotonic rollback anchor

**Status:** Proposed
**Date:** 2026-08-16
**Deciders:** repository owner
**Blocks:** full mainnet. `MainnetReadinessV1::evaluate` refuses with
`external_monotonic_rollback_anchor_is_not_ready` unless the profile is the
bounded pilot (`readiness.rs:136-141`), and
`measure_external_rollback_anchor_ready()` returns a hardcoded `false`
(`readiness.rs:409`).

## Context

### What the anchor is actually for

Every safety property in this Hub rests on its durable state being **the latest**
state. The channel ledger refuses a bill whose serial is not exactly
`previous + 1`, refuses a commit when the ledger head moved, and keeps at most
one unresolved progression per channel. All of that is enforced *against the
state file*.

None of it survives the state file going backwards.

Restore a Hub from a backup taken ten bills ago and every one of those checks
passes again, against a stale head. The Hub will happily co-sign serial 4 a
second time with different balances. Both signed bills are valid to the
contract. The one that reaches `finalize` first wins, and the other party's
money is gone. No amount of in-file validation catches this, because the file is
the thing that lied.

An anchor is a counter that lives **outside** the state and only ever goes up.
Before the Hub uses its signing key it reads the anchor, and refuses if the state
it holds is behind what the anchor has already seen.

This is not a new idea in this repository. The Agent Wallet already does it: a
paired Android device holds a counter in the platform keystore and signs receipts
over wallet-state commitments, under domains
`HPAY/COMPANION/ROLLBACK-ANCHOR/V1` and `HPAY/COMPANION/WITNESS-RECEIPT/V1`
(`crates/companion-protocol/src/witness.rs:13-14`). That subsystem sets its own
`external_rollback_anchor_ready = true`
(`crates/agent-wallet-core/src/service/companion/witness.rs:180`). The Hub has
nothing equivalent.

### Forces

- **The Hub is a server.** It is expected to be restored from backup, migrated
  between machines, and run under an operator who is not the counterparty. An
  anchor that makes disaster recovery impossible will be disabled by the first
  operator who needs it at 3am.
- **A wrong anchor is worse than none.** If the anchor can be rolled back with
  the state, it provides false assurance and the readiness flag becomes a lie.
- **Existing requirements are already written**
  (`docs/agent-wallet/EXTERNAL_ROLLBACK_ANCHOR_REQUIREMENTS.md:29`,
  `docs/l2/L2_SAFETY_MODEL.md:172`) and name three shapes: a TPM counter, an OS
  keystore counter, or a remote witness.
- **The flag must stay honest.** Whatever lands, `health()` must keep reporting
  conservatively and `mainnet_readiness()` must report `false` until the anchor
  genuinely holds. That contract was just settled in `233c470` and must not be
  reopened to make this land.

## Decision

Implement **Option C, a remote witness**, as the anchor, with the TPM counter
(Option A) available as an optional second factor for single-operator
deployments.

## Options considered

### Option A: TPM 2.0 NV monotonic counter

| Dimension | Assessment |
|---|---|
| Complexity | Medium. TSS bindings, NV index provisioning, one more failure mode at startup. |
| Cost | Low, on hardware that has a TPM. |
| Scalability | Poor. One counter per machine. |
| Team familiarity | Low. No TPM code in this tree today. |

**Pros:** genuinely cannot go backwards, hardware-enforced. No network
dependency. Cheap to read on the signing path.

**Cons:** binds the Hub to one physical machine. Migration and disaster recovery
become manual, delicate operations, and a lost TPM is an unrecoverable channel
set. Cloud and container deployments frequently have no usable TPM. Windows-only
in practice for this codebase, which already has a Windows-only identity path
that has caused problems.

### Option B: OS keystore counter

| Dimension | Assessment |
|---|---|
| Complexity | Low. |
| Cost | Low. |
| Scalability | Poor, same single-machine limit. |
| Team familiarity | Medium. DPAPI is already used for pilot identities. |

**Pros:** simplest to build; reuses machinery the pilot already has.

**Cons:** **this does not actually solve the problem.** A DPAPI-sealed counter is
a file. It is in the same filesystem, the same backup set, and the same restore
as the state it is supposed to guard. Restoring the machine restores the counter.
It defends against someone editing `hub-state.json` by hand and against nothing
else. Listing it as an option in the requirements document was optimistic.

### Option C: Remote witness — **recommended**

A second, small service holding the highest `(channel, serial)` it has seen. The
Hub sends a commitment before using its signing key; the witness records it and
returns a signed receipt; the Hub refuses to sign without a receipt whose
counter is at least what it last saw.

| Dimension | Assessment |
|---|---|
| Complexity | Medium. One service, one protocol, one durable store. |
| Cost | Low. The witness is tiny and stateless apart from a counter table. |
| Scalability | Good. One witness serves many Hubs; counters are per channel. |
| Team familiarity | **High.** The exact shape already exists and is proven. |

**Pros:** survives Hub restore, machine migration and full host loss, which is
precisely the threat. It is the only option here that does. The protocol,
domain-separation and receipt-verification patterns can be lifted from
`companion-protocol`'s witness rather than invented. It can be operated by the
counterparty, by a neutral third party, or by the same operator on separate
infrastructure — each a different trust posture, same code.

**Cons:** an availability dependency on the signing path: witness down means no
new bills. That is the correct failure direction (refuse, do not sign) but it is
a real operational cost. Adds a network round trip before every signature. If the
witness is run by the same operator on the same host, it degrades to Option B and
must be prevented from doing so silently.

### Option D: On-chain anchor

Write the counter to the chain.

| Dimension | Assessment |
|---|---|
| Complexity | Medium. |
| Cost | **High.** A fee and a block wait per counter bump. |
| Scalability | Poor for a fee-free rail. |
| Team familiarity | High. |

**Pros:** trustless, needs no new party.

**Cons:** defeats the point of the rail. The entire value of the fee-free channel
is that payments do not touch the chain; anchoring every bill on-chain reintroduces
the fee and the confirmation wait per payment.

### Option E: Reuse the companion device witness directly

Point the Hub at the same Android companion protocol the Agent Wallet uses.

**Rejected.** It is designed around a phone the owner carries, a biometric prompt
and a private-LAN transport (`is_private_v4`). A Hub is a server that must sign
unattended. The *pattern* is right and should be copied; the *transport and
liveness model* are wrong for this caller.

## Trade-off analysis

The decisive question is **what the anchor must survive**. The threat is not a
careless edit, it is a restore. A, B and E all keep the counter inside the same
failure domain as the state:

- **B** shares the filesystem. Restoring the host restores the counter. It
  defends against nothing that matters.
- **A** survives a file restore but not a machine migration, and turns a lost
  motherboard into lost channels.
- **C** is the only one whose counter is not restored when the Hub is.

Against that, C's cost is availability: a witness outage stops new bills. That is
acceptable because it fails in the safe direction, and because the same
constraint already exists elsewhere on this path — the Hub already refuses to
sign when the node is unreachable, on the same principle that an unreachable
oracle is not evidence.

D is ruled out on purpose rather than on cost alone: it would make a fee-free
rail charge a fee per payment.

## Consequences

**Easier**
- Restoring a Hub from backup becomes safe: the anchor refuses, loudly, instead
  of the Hub silently double-signing.
- `external_rollback_anchor_ready` becomes a measurement with a subject, and
  full mainnet stops being structurally unreachable.

**Harder**
- The signing path gains a network dependency and a round trip.
- There is one more service to deploy, monitor and back up.
- Disaster recovery needs a written procedure: how a legitimately restored Hub
  re-synchronises with the witness, and who authorises it. This is the part most
  likely to be got wrong, and it must be designed before the code.

**To revisit**
- `crates/wallet-core/src/l2_hub.rs:718-724` gates `TrustlessOnly` on health
  flags. It is inert today and is being repointed at the readiness document in
  separate work. Confirm that landed before this flag can ever be `true`.
- Whether one witness may serve multiple Hubs, and what that means for the trust
  story if the witness operator is also a Hub operator.

## Action items

1. [ ] Write the recovery procedure **first**: what a restored Hub does when its
       state is behind the anchor, who may authorise a resynchronisation, and what
       evidence that authorisation requires. If this cannot be written clearly, do
       not build the rest.
2. [ ] Define the witness protocol, copying the domain separation and receipt
       shape from `crates/companion-protocol/src/witness.rs` rather than inventing
       one. Bind each receipt to the channel, the serial and the Hub identity.
3. [ ] Build the witness service with a durable, append-only counter store.
4. [ ] Add the Hub client and put the check on the signing path, before the key is
       used, alongside the existing pre-use precondition re-verification.
5. [ ] Refuse a witness that cannot be distinguished from the Hub's own host, so
       Option C cannot silently degrade into Option B.
6. [ ] Replace `measure_external_rollback_anchor_ready()` (`readiness.rs:409`)
       with a real measurement, and prove **both** directions: false with no
       witness configured or reachable, true only with a live witness and a valid
       receipt.
7. [ ] Optional: add the TPM counter as a second factor for single-operator
       deployments, ANDed with the witness, never substituted for it.

## Who runs the witness

This was previously left open. It is decided here, because leaving it open makes
the design look like it costs three services to run and that impression is wrong.

### Who runs what

**The wallet user runs nothing.** No node, no Hub, no witness. They point their
wallet at somebody else's Hub and somebody else's node, which is what they
already do today. Nothing in this ADR changes what a wallet has to install. The
anchor is entirely a property of the Hub they chose, and the only thing it costs
the user is the ability to *read* what that Hub's anchor is worth — which is why
the posture and the operating entity are published beside the flag rather than
hidden behind it.

**The Hub operator runs a Hub, and points it at a witness over the network.**
One service, plus an address in their configuration. They are not required to run
a witness themselves, and running one is not the normal starting position.

**The project will run one public witness, so that an operator needs no second
machine to start.** Stated as an intent, because **it does not exist yet**: there
is no public witness address today and nothing in this repository points at one.
When it exists, a Hub operator with nothing but a Hub can point at it, get a real
external anchor on day one, and be honestly better off than with no anchor at
all. It is the *default* only in the sense of "the address most operators will
paste first", never in the sense of "what the code reaches for on its own".

**A Hub holding serious value points somewhere else.** Its own witness on
separate infrastructure, the counterparty's witness, or a neutral third party.
That move is a change of address in configuration. It is not a code change, not a
build flag, not a fork, and not a conversation with us. The same binary and the
same protocol serve every one of these; the only things that differ are who holds
the receipt key and whose backup set the counter lives in.

### The two things that must never happen

**1. The shared witness must never become mandatory.** There is no code path in
which the project's witness address is privileged over any other. It is not
compiled in, not a fallback when the configured witness is unreachable, not a
second witness consulted alongside the operator's, and not a requirement for the
readiness flag to read true. An operator must be able to point at an address we
have never heard of and get exactly the same behaviour, including the same
`external_rollback_anchor_ready` measurement. If a shared witness were mandatory,
the whole design would have moved the trust rather than removed it: every Hub on
the rail would depend on one service run by one party, who could then freeze the
rail, and who would be the single most attractive target in the system. It would
also make us a party to every channel we are not otherwise in.

The test for this rule is simple and should be applied to any future change: if
the project's witness went away permanently, every Hub pointed at a different
witness must be entirely unaffected, and every Hub pointed at ours must be able
to recover by editing one line of configuration.

**2. There must never be a bypass that lets a Hub sign while the witness is
unreachable.** No `--allow-unwitnessed-signing`, no "degraded mode", no grace
period, no timeout that proceeds, no operator override, no environment variable,
no emergency flag. An unreachable oracle is not evidence, and a Hub that signs
without a receipt has no anchor at exactly the moment the anchor is being tested.
The correct behaviour when the witness is down is that the Hub refuses to sign
and the channels freeze. Frozen channels lose nobody any money; a bypass loses
somebody all of it.

A deployment that genuinely cannot accept the availability cost has an honest
option already: the bounded pilot profile, which reports `trustless_finality:
false` and says out loud that it depends on trusting the Hub. Use that. Do not
run a mainnet profile with a hole in it and call it an anchor.

If either rule looks like it needs an exception, the exception is the bug.

### What a same-operator witness is actually worth

Recorded honestly here, because this is the posture most Hubs will start in and
it is the one most easily oversold.

A witness run by the same operator as the Hub, on separate infrastructure and in
a separate backup set, **does** catch:

- a Hub restored from an old backup after a disk failure, a bad migration or a
  failed upgrade — the ordinary disaster-recovery case, and the most likely one;
- an operator error: the wrong snapshot restored, a stale volume reattached, a
  state file copied from a staging box;
- a second Hub instance started by accident against the same keys, through the
  global counter;
- a state file quietly reverted underneath a running Hub;
- silent bit rot or filesystem corruption that rolls the state back.

It **does not** catch a deliberate rollback by the operator who holds both keys.
That operator can stop the Hub, stop the witness, restore both to an earlier
point together, and every check in this system passes: same
`witness_instance_id`, counter where the Hub expects it, every signature valid.
No message, no counter and no attestation can distinguish that from normal
operation. Against a dishonest operator, a same-operator witness is worth
nothing, and this document will not pretend otherwise.

That is why the posture travels with the flag. A counterparty-run or neutral
witness is what turns the anchor from "protects the operator from their own
infrastructure" into "protects the counterparty from the operator". Both are
worth having. They are not the same guarantee and must never be reported as one.

### The counterparty ratchet, which narrows the paragraph above

Everything said above is true *Hub-side*. It stops being the whole truth once
the receipts ride back to the counterparty with the bill.

The rule is one sentence: **every new bill must carry a receipt from at least
one witness that receipted the counterparty's most recently accepted bill** —
enforced, more strongly, as *no witness the counterparty recorded may
disappear without the counterparty being told*. The counterparty keys that
memory by `binding_commitment` and stores it inside its own authenticated L2
state commitment, on a different machine, under a different key
(`crates/wallet-core/src/l2_safety.rs`, `accept_anchored_bill`).

This closes the circularity that the rest of this document accepts. To roll
back past serial S and re-spend, the Hub must present a bill at or below S. Any
witness that receipted the counterparty's bill at S holds S and refuses
anything at or below it. So the Hub must present the new bill *without* that
witness — and the overlap rule makes the counterparty refuse it. The Hub is
caught by the one party it cannot swap out, using memory it cannot reach.

It also narrows the "undetectable" case above. An operator who stops both,
restores Hub *and* witness together, and restarts does pass every Hub-side
check. It does not pass the counterparty's: the counterparty holds
`highest_counter_value` and `accepted_serial` from its last bill's receipt, in
a store that was in neither backup set, and the restored counter going
backwards is a hard refusal.

What the ratchet does **not** do, stated plainly:

- It guarantees **continuity, not honesty**. For a brand-new counterparty with
  no history there is nothing to compare against, so the set is whatever the
  Hub declares. A Hub malicious from the start can present a witness set it
  fully controls and the ratchet will faithfully preserve that set forever.
  This is irreducible without an external registry of witnesses. It matters
  less than it sounds — a fresh channel at serial 0 has nothing to roll back
  to, and the ratchet accrues from the first bill onward — but it is real, and
  the counterparty's only defence against a set that was corrupt from bill one
  is the trust decision it makes *before* bill one: who runs the witness.
- It does not defeat a **colluding** witness: one already in the counterparty's
  recorded set, same key, same instance, willing to fabricate monotone counters
  and re-receipt a serial it already holds. No check here can see that. It is
  the same residual as a same-operator witness, above.

Write it as "the wallet verifies the witness set has not changed since it first
saw one", never as "the wallet verifies the witness set".

#### The counterparty's memory is not self-anchoring either

The ratchet is only as durable as the store it lives in, and that store is a
file on the counterparty's own disk. Deleting the directory is cheaper than any
cryptographic attack and leaves nothing inconsistent behind: the next bill takes
the first-bill branch and the set becomes whatever the Hub declares. Restoring
it from an older *coherent* snapshot — state, journal and checkpoint together —
opens clean for the same reason: nothing inside disagrees with anything else
inside, it is simply behind. Whoever can restore a Hub's state can usually reach
this store too, and always can when the Hub operator is also the wallet's owner.

So the memory is anchored a second time, outside itself. `accept_anchored_bill`
takes a mandatory `independent_serial_floor` — the highest serial the caller can
prove the channel reached, from a store this one does not own. Agent Wallet
supplies it from its own encrypted operation state: different key, different
journal, different file, not in the same backup set. A memory that is missing
while that floor is above zero, or behind it, is refused
(`rollback_anchor_memory_behind_wallet`).

That raises the bar from one file to two, and it should be described that way
and not more grandly. An attacker holding the whole wallet's disk can rewind
both. What it does buy: `rm -rf` on the L2 directory alone no longer resets the
ratchet, and a partial restore is caught rather than quietly re-baselined.

#### Every path that accepts a bill has to carry the check

The rule is worth exactly as much as its narrowest gate, and the first build of
it had a second gate with no lock. `HubClient::cosign_*` ran the ratchet; the
reconciliation path did not, and it commits the Hub's `fully_signed_bill` from
the payment status document. Reaching it needed no cryptography: co-sign,
persist, then drop the connection. The wallet's co-sign fails closed, its remedy
is "Reconcile", and reconciling committed the bill the ratchet had refused —
including the counter-went-backwards refusal this ADR relies on to narrow the
"undetectable" case above.

Both paths now run the same check inside the function that produces the bill
(`l2_hub.rs`, `cosign_hvm_*` and `reconcile_hvm_*`), and the raw status readers
are private. The general form, worth stating because it will come up again:
*whoever chooses which path the counterparty takes must not be able to choose a
path with no check on it.*

#### The decision has to reach a person, and closing has to stay real

Zero overlap is a user decision. It is never a silent accept, and never an
automatic halt: an innocent witness rotation and a Hub swapping witnesses in
order to re-sign history are byte-identical from the counterparty's side, and no
amount of protocol can tell them apart. Only the owner knows whether their
operator announced a change.

That means the parked decision must be readable and answerable by a human, or
the rule has no "yes" at all and its refusals pile up against a wall. It is
durable in the channel store, exposed through
`AgentWalletManager::pending_hvm_anchor_decision` /
`resolve_hvm_anchor_decision`, carried on the Tauri surface as
`agent_wallet_hvm_anchor_decision` / `agent_wallet_resolve_hvm_anchor_decision`,
and shown in the HVM operations panel with the two answers and nothing else.
The refusal is its own error value, never `RecoveryRequired`, because
`RecoveryRequired`'s remedy is the reconcile button and pointing a waiting owner
at the control that commits the bill is worse than saying nothing.

Choosing to close latches the channel on its last accepted bill — whose receipt
set is intact — and refuses to advance it further. The close itself runs against
that bill and needs nothing from the Hub's anchor, which is what keeps closing
available no matter how the witness question is answered.

### What this means for the default that ships

There is no public witness address today. Until one exists, the shipped default
is **no witness configured**, which measures `external_rollback_anchor_ready =
false` and keeps full mainnet blocked. That is the truth, and a configuration
file pointing at a hostname that does not answer would be a worse lie than an
empty field. When an address exists, it becomes a documented, copy-and-paste
value in the operator guide and in the example configuration — never a compiled-in
constant, and never a value the Hub reaches for on its own.

### Consequences of this decision

- The witness service must be operable by an ordinary person with an ordinary
  machine, because the design depends on it being easy to leave ours. That is
  what `docs/l2/RUNNING-A-WITNESS.md` is for, and it is load-bearing rather than
  supplementary.
- Whoever operates the project's witness carries an availability obligation to
  every Hub pointed at it, and must publish the posture honestly: for a Hub
  operator we have no other relationship with, it is a neutral third party; for
  anything we also operate a Hub for, it is not.
- Item 5 of the action items above stands unchanged. "Same operator, separate
  infrastructure" is a valid posture; "same operator, same host" is not, and the
  attestation enum has no value that can express it.

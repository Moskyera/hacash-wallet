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

## What this ADR does not decide

Who runs the witness. Whether it is the counterparty, a neutral party or the same
operator on separate infrastructure is a trust decision, not a technical one, and
it changes what the guarantee is worth without changing a line of code. It should
be decided before item 3 and written into the requirements document.

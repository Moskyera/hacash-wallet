# Rollback anchor: witness wire protocol and degradation guard

**Status:** design, written before the code. ADR-001 action items 2 and 5.
**Decision it implements:**
[ADR-001-EXTERNAL-ROLLBACK-ANCHOR.md](ADR-001-EXTERNAL-ROLLBACK-ANCHOR.md).
**Operator procedure:** [ROLLBACK-ANCHOR-RECOVERY.md](ROLLBACK-ANCHOR-RECOVERY.md).
Read that one first; the ADR puts it before this.

The shape here is lifted from `crates/companion-protocol/src/witness.rs`, which
is proven and in production use for the Agent Wallet. Same canonical encoding,
same domain separation, same commitments-only discipline, same fail-closed
verification. What changes is the transport and the liveness model: a Hub is a
server that signs unattended, not a phone with a biometric prompt on a private
LAN.

---

## 1. Scope: which key uses need a receipt

The threat is an *off-chain* signature that can be duplicated at the same ledger
position. Two call sites reach the Hub signing key that way:

- `HubSigner::sign_hvm_bill` — the reviewed per-channel V1 profile, called from
  `crates/l2-fast-pay-hub/src/state/hvm.rs:331`.
- `HubSigner::sign_hvm_registry_bill` — the shared registry V2 profile, called
  from `crates/l2-fast-pay-hub/src/state/hvm_registry.rs:342`.

Both are in scope. A design that covers only V2 leaves V1 fully exposed.

`HubSigner::sign_documents` (the L1 chain-payment envelope) is **out of scope**
and deliberately so: a chain transaction is anchored by the chain. Replaying it
is a double-spend, which consensus already refuses. The gap this protocol closes
is precisely the one the chain does not see.

Nothing in this design touches `require_registry_non_mainnet`. The registry
mainnet refusal stands exactly as written and is evaluated before any witness
traffic, as it is today.

---

## 2. Canonical encoding

Identical to `crates/companion-protocol/src/codec.rs`, reused rather than
re-invented:

- Every message is encoded as a domain-prefixed byte string. The domain is
  written first, as a length-prefixed field, so it is inside the hashed preimage
  and not merely a convention.
- Integers are big-endian, fixed width. Strings and byte strings are prefixed
  with a `u32` big-endian length. Optional fields are a `bool` tag followed by
  the value when present. Enumerations are a `u8` tag with an explicit,
  exhaustive mapping.
- A decoder verifies the domain, decodes exactly, and calls `finish()`, which
  fails if a single trailing byte remains. Trailing bytes are a malformed
  message, not a forward-compatibility mechanism.
- Message commitment is `sha256(canonical_bytes)`. Signature is over that
  commitment.
- Shape validation runs on both encode and decode, so a malformed value cannot
  be produced locally or accepted from the wire.

### Why the Hub's money key may sign these

The Hub signs anchor requests with the same `Account` that signs bills. That is
intentional: a receipt must authorise *the key that will sign the bill*. A
separate anchor key would produce receipts that say nothing about the key
actually used.

This is safe against cross-protocol confusion because the signed preimage is
`sha256(domain || fields)` and the bill signing hash uses a different domain
(`HPAY/HVM-CHANNEL-REGISTRY/V2`, see `HvmRegistryBillV2::signing_hash`). Producing
an anchor request whose signature is also a valid bill signature requires a
SHA-256 collision across two distinct domain prefixes.

---

## 3. Domains

Following the existing convention (`HPAY/COMPANION/ROLLBACK-ANCHOR/V1`,
`HPAY/COMPANION/WITNESS-RECEIPT/V1`):

| Domain | Message | Signed by |
|---|---|---|
| `HPAY/HUB/ROLLBACK-ANCHOR/V1` | `HubAnchorRequestV1` | Hub bill-signing key |
| `HPAY/HUB/WITNESS-RECEIPT/V1` | `HubWitnessReceiptV1` | Witness **receipt** key (online) |
| `HPAY/HUB/WITNESS-REFUSAL/V1` | `HubWitnessRefusalV1` | Witness receipt key (online) |
| `HPAY/HUB/WITNESS-RESYNC/V1` | `WitnessResyncAuthorisationV1` | Witness **authorisation** key (offline) |
| `HPAY/HUB/WITNESS-ATTESTATION/V1` | `WitnessDeploymentAttestationV1` | Witness authorisation key (offline) |

Two witness keys, not one. The **receipt key** is online and signs unattended
thousands of times a day. The **authorisation key** is offline and signs only
incidents and deployment attestations. Collapsing them means compromising the
running witness is enough to forge a resynchronisation, which would make the
authorisation step in the recovery procedure decorative.

Both are pinned in Hub configuration. Trust-on-first-use is not sufficient on
the money path.

---

## 4. `HubAnchorRequestV1`

Sent before the signing key is used. Carries commitments only — no balances, no
signatures, no bill bodies, no keys.

| Field | Type | Purpose |
|---|---|---|
| `request_version` | `u64` | `1`. Anything else is refused. |
| `request_id` | `String` | Unique per `(hub_identity, witness_id)`. Replay identity. |
| `hub_identity` | `String` | The Hub address that will sign the bill. |
| `witness_id` | `String` | The pinned witness this request is for. |
| `witness_epoch` | `u64` | Witness key generation the Hub expects. |
| `settlement_profile` | `String` | `hpay-hvm-shared-registry-v2` or the V1 profile. |
| `network_instance_id` | `String` | Chain binding (mode, chain id, genesis, node profile, tx format). |
| `binding_commitment` | `String` | The exact channel incarnation. `HvmRegistryBindingV2::commitment()`. |
| `channel_id` | `String` | Human-legible channel identity, also inside the binding. |
| `reuse_version` | `u32` | Channel incarnation, also inside the binding. |
| `serial` | `u64` | The bill serial about to be signed. |
| `previous_bill_commitment` | `String` | Commitment of the head this extends. |
| `proposed_bill_commitment` | `String` | Commitment of the exact bill about to be signed. |
| `counter_value` | `u64` | The witness's global counter value the Hub expects to advance to. |
| `hub_journal_sequence` | `u64` | The Hub's authenticated journal position. |
| `hub_journal_head_hash` | `String` | The Hub's journal head. |
| `hub_state_commitment` | `String` | `storage::state_commitment` of the Hub's durable state. |
| `created_at` | `u64` | Unix seconds. |
| `expires_at` | `u64` | Unix seconds. Lifetime bounded to **120 seconds**. |

Plus `signature_hex` on the `SignedHubAnchorRequestV1` wrapper, exactly as
`SignedRollbackAnchor` wraps `RollbackAnchor`.

**On the 120-second lifetime.** The companion anchor allows ten minutes because a
human has to pick up a phone and press a button. Nothing here waits for a human.
A window longer than the signing path needs is a window in which a stockpiled
request is useful.

**Two counters, deliberately.** `serial` is per-channel and catches a rollback on
a channel the Hub still knows about. `counter_value` is global across every
channel this Hub holds and catches a restore that loses an entire channel — the
case where the per-channel check never fires because the Hub has forgotten the
channel exists and never asks about it.

---

## 5. `HubWitnessReceiptV1`

Returned only after the witness has **durably** recorded the reservation.

| Field | Type | Purpose |
|---|---|---|
| `receipt_version` | `u64` | `1`. |
| `request_id` | `String` | Echoes the request. |
| `request_commitment` | `String` | `sha256` of the request's canonical bytes. Binds every request field at once. |
| `witness_id` | `String` | Which witness signed. |
| `witness_epoch` | `u64` | Receipt key generation. |
| `witness_instance_id` | `String` | Identity of the witness's **durable store**, generated once at store creation. |
| `witness_boot_id` | `String` | Identity of the witness **process**, fresh per start. |
| `hub_identity` | `String` | Restated: who this receipt is for. |
| `binding_commitment` | `String` | Restated: which channel. |
| `serial` | `u64` | Restated: which position. |
| `proposed_bill_commitment` | `String` | Restated: which exact bill. |
| `previous_counter_value` | `u64` | The global counter **before** this reservation. |
| `counter_value` | `u64` | The global counter after. Must equal the request's. |
| `accepted_at` | `u64` | Unix seconds. |
| `receipt_expires_at` | `u64` | Unix seconds. Bounded to the request's `expires_at`. |

Plus `signature_hex` on `SignedHubWitnessReceiptV1`.

The fields are restated rather than left implicit in `request_commitment` so a
verifier — including an operator during an incident — can read a receipt on its
own and see what it authorises without reconstructing the request.

**`previous_counter_value` is load-bearing.** If the Hub asks for counter `N+1`
and the witness reports the previous value was `N`, the counter is where the Hub
believed. If it reports `N+5`, five reservations happened that this Hub does not
account for — a second live Hub, or a misconfigured shared counter namespace.
Refuse and emit `rollback_anchor_counter_skipped`.

### What the Hub verifies before it signs

All of it, and any failure refuses:

1. Signature verifies against the **pinned** witness receipt public key.
2. `witness_id` and `witness_epoch` match the pinned configuration.
3. `witness_instance_id` matches the value pinned on first contact. A change
   means a re-created store: `rollback_anchor_witness_instance_changed`.
4. `request_id` and `request_commitment` match the request the Hub **durably
   persisted before sending**. A receipt harvested from the wire matches nothing.
5. `hub_identity`, `binding_commitment`, `serial`, `proposed_bill_commitment` and
   `counter_value` equal the request's.
6. `previous_counter_value + 1 == counter_value`.
7. `accepted_at >= created_at` and `receipt_expires_at > now`, re-read from the
   wall clock immediately before key use — alongside the existing
   `key_use_time` re-validation at `state/hvm_registry.rs:335`, not instead of it.
8. The bill about to be signed re-commits to `proposed_bill_commitment`.

---

## 6. `HubWitnessRefusalV1`

A refusal is **signed**. This matters: it is the primary evidence artefact in the
recovery procedure, and it is what distinguishes "the witness said no" from "the
network dropped the packet". An unreachable witness produces no refusal, and the
Hub must never treat silence as a refusal or a refusal as silence.

| Field | Type | Purpose |
|---|---|---|
| `refusal_version` | `u64` | `1`. |
| `request_id`, `request_commitment` | `String` | Which request was refused. |
| `witness_id`, `witness_epoch`, `witness_instance_id` | `String`/`u64` | Who refused. |
| `hub_identity`, `binding_commitment` | `String` | Scope. |
| `reason` | enum tag | See table below. |
| `observed_counter_value` | `u64` | The witness's current global counter. |
| `observed_serial` | `u64` | The witness's high-water serial for this channel. |
| `observed_bill_commitment` | `String` | The commitment the witness holds at that serial. |
| `refused_at` | `u64` | Unix seconds. |

Reason tags map one-to-one onto the identifiers in the recovery document:
`HubBehindWitness`, `ForkAtSerial`, `CounterSkipped`, `MalformedRequest`,
`UnknownHub`, `UnknownChannel`, `EpochMismatch`, `Expired`, `ReplayMismatch`.

The `observed_*` fields are what let the operator compute the gap without a
second privileged query. They are commitments and positions only; they disclose
no balance.

---

## 7. What each field binds, and what an attacker gains by changing it

| Field | Binds | What changing it buys an attacker |
|---|---|---|
| `hub_identity` | The key that will sign | Without it a receipt is bearer evidence: any Hub could present another Hub's receipt, or spend another Hub's counter. |
| `witness_id` + pinned key | Which witness | Stand up a compliant-looking witness with a counter at zero and get every request approved. This is the amnesia attack from the recovery document. |
| `witness_epoch` | Key generation | Keep using a rotated-out witness key. |
| `network_instance_id` | The chain | Replay a testnet receipt to authorise a mainnet signature. |
| `binding_commitment` | The exact channel incarnation — contract, channel id, reuse version, both parties, deposits | Get a receipt on a dust channel and use it to authorise a signature on a large one; reuse a receipt from a closed incarnation on a reopened one. |
| `channel_id` + `reuse_version` | Channel identity and incarnation, redundantly with the binding | Redundancy is the point: an operator reading a receipt during an incident sees the channel without deriving a commitment. |
| `serial` | The exact ledger position | **The core threat.** A receipt for serial 4 reused to authorise serial 4 again. |
| `proposed_bill_commitment` | The exact balances | **The other half of the core threat.** With the serial bound but not the bill, one receipt at serial 4 would authorise *any* serial-4 bill — two different balance splits, both signed, both valid. This field is what makes the receipt attest to a unique bill rather than a position. |
| `previous_bill_commitment` | The head being extended | Makes the witness's record a chain rather than a set, so a fork at the same serial is visible to the witness and not only to the Hub. |
| `counter_value` / `previous_counter_value` | Global position across all channels | Catches a restore that loses a whole channel, and catches a second live Hub consuming counter values. |
| `hub_journal_sequence`, `hub_journal_head_hash`, `hub_state_commitment` | The Hub's own durable position | Turns the witness into an external log of the Hub's state progression, which is what lets the recovery procedure prove *which* snapshot a Hub was restored from. Attacker gain from lying: none directly — it is evidence, not a gate — but a Hub whose reported journal position moves backwards while its counter moves forwards is a signal worth refusing on. |
| `request_id` | Replay identity at the witness | Reuse one receipt across two requests, or poison the witness's idempotency record. |
| `created_at` / `expires_at` | Freshness | Stockpile receipts before a restore and present them after. |
| `witness_instance_id` | The witness's durable store | Silently re-provision the witness with a fresh counter — the single cheapest way to defeat this whole design. |
| `witness_boot_id` | The witness process | Distinguishes a restarted witness from a re-created store. Evidence, and a weak co-location signal (Section 10). |
| Domain prefix | Message type | Feed a receipt to the resync verifier, or an attestation to the receipt verifier. |

---

## 8. Replay handling

Four layers. The first is the one that actually matters; the rest are defence in
depth and hygiene.

**Layer 1 — the commitment makes replay harmless.** A replayed receipt can only
ever re-authorise the exact `proposed_bill_commitment` it names. That commitment
fixes the serial *and* the balances. So the strongest thing a perfect replay
achieves is re-authorising the bill it already authorised. It cannot produce a
second, different bill at the same serial, which is the entire threat. State this
plainly because it is the property the design rests on.

**Layer 2 — idempotency on the request commitment, at the witness.** Replaying an
identical request returns the identical receipt and does **not** advance the
counter. A request bearing a known `request_id` with a *different*
`request_commitment` is refused hard as `ReplayMismatch` — that is an
equivocation attempt, not a retry.

This is required, not optional. It is what makes the crash window between "the
witness recorded" and "the Hub persisted the receipt" recoverable: the Hub
replays the identical request on restart and gets its receipt back. It mirrors
`receipt_for_accepted_anchor` in the companion protocol, which exists for exactly
this reason.

**Layer 3 — the Hub only accepts a receipt for a request it persisted.** The
request is durable before it goes on the wire. A receipt that does not match a
persisted request matches nothing.

**Layer 4 — freshness and domains.** 120-second lifetime, re-checked against the
wall clock immediately before key use. Domain separation stops a message of one
type being verified as another.

**Retention at the witness.** Accepted `request_id`s are bounded (the companion
protocol caps at 4096; the same discipline applies here, per Hub per channel).
The append-only reservation log is separate and must be retained at least back to
the last cooperative close or the last resynchronisation baseline for that
channel — that log is what produces the gap export the recovery procedure
depends on.

---

## 9. Durable ordering

The ordering is the protocol. Getting it wrong produces signatures nobody has a
record of.

### Per signature

```
1. Hub persists UserProposalPersisted                    (exists today)
2. Hub builds the request from the exact proposed bill,
   persists it with the progression                      (new)
3. Hub sends the request
4. Witness durably advances counter + per-channel serial,
   THEN returns the receipt                              (never the reverse)
5. Hub verifies the receipt and persists it together
   with HubSignatureMayExist, in one write               (extends today's write)
6. Hub re-validates request, binding, expiry and receipt
   freshness against the wall clock                      (extends key_use_time)
7. Hub signs
8. Hub persists FullySigned                              (exists today)
```

Crash between 3 and 5: the witness has advanced, the Hub holds a request and no
receipt. On restart the Hub replays the identical request and Layer 2 returns the
identical receipt. No gap.

Crash between 2 and 3: the witness never saw it. The Hub replays. No gap.

Crash between 5 and 8: this is today's `HubSignatureMayExist` ambiguity, already
handled by the existing reconciliation path — and now the witness also holds a
record of exactly what may have been signed, which is a strict improvement on the
evidence available during that reconciliation.

The witness writing durably **before** it answers is not negotiable. A witness
that answers first and writes after can lose the record of a signature that then
gets made.

### At startup

Before the money path serves anything, for every channel the Hub holds, it
queries the witness's current record and compares. This is the anti-rollback
check proper: it catches a restored Hub immediately, before any traffic, rather
than on the first payment. The per-signature reservation is the
anti-equivocation check and is what actually advances the counter. Both are
required — the startup check alone would miss a state file swapped underneath a
running Hub, and the per-signature check alone would let a restored Hub serve
reads and accept requests before refusing.

---

## 10. The degradation guard

ADR-001 item 5: the witness must not silently become a file on the same host,
because that is Option B, and Option B defends against nothing — it shares the
filesystem, the backup set and the restore with the state it is supposed to
guard.

### The honest framing, first

**No check in this protocol can prove the witness is outside the Hub's failure
domain.** If the witness's durable store was inside the same backup set and both
were restored together, both come back internally consistent at the older
position: same `witness_instance_id`, counter at `N`, Hub asking for `N+1`. Every
signature verifies. Nothing is detectable. A determined operator with root on
both machines can construct that situation on purpose and this design will not
catch them.

So the goal is not to make the weak configuration impossible. It is to make it
**loud and deliberate** — unreachable by accident, unreachable by drift, and
unreachable without a signature from a named person saying they did it.

### Structural: there is no in-process witness

The only witness client is a network client. No embedded witness, no
`file://` store backend, no "local mode", no test double reachable from a
production build. A configuration that would degrade to Option B has to be
*built*, not selected. This is the strongest guard available and it costs
nothing: it is an absence of code.

### Hard refusals

Each of these refuses at startup and on every reconnection. None can be
overridden by configuration.

1. **Endpoint is not this host.** Refuse a witness URL that resolves to loopback,
   to a link-local address, or to any address bound to a local interface of this
   host. Refuse plaintext transport. *Strength: catches accidents and lazy
   configurations. Defeated by a port forward or a container on the same physical
   host with a routable address. This is a configuration lint, not a security
   boundary, and calling it one would be dishonest.*
2. **Distinct key custody.** Refuse if the witness receipt key equals the Hub's
   signing key, if the authorisation key equals the receipt key, or if either
   witness key is derivable from material present in the Hub's own configuration
   or key store. *Strength: catches "the operator reused the key". Defeated by
   generating a second key on the same host. Weak, but the failure it catches is
   a real one that people make.*
3. **Pinned store identity.** `witness_instance_id` is recorded on first contact
   and pinned durably, exactly as `MobileWitnessState` pins `node_profile_id` and
   `genesis_identifier`. Any change refuses with
   `rollback_anchor_witness_instance_changed`. *Strength: this is the good one.
   It does not detect co-location, it detects the effect an attacker actually
   wants — a counter that was reset. Re-provisioning the witness with a fresh
   store is the cheapest attack on this whole design and this closes it.*
4. **Counter never observed to decrease.** Any receipt or probe reporting a
   counter below the highest previously seen for this witness instance refuses.
5. **Deployment attestation present, valid and unexpired.** A
   `WitnessDeploymentAttestationV1`, signed by the witness's offline
   authorisation key, naming the posture and the operator, with a bounded
   validity period. Absent or expired refuses with
   `rollback_anchor_attestation_missing_or_expired`. *Strength: none
   cryptographically — an attestation is a statement, not proof. Its entire value
   is that the weak configuration now requires someone to sign a document saying
   they chose it, and to re-sign it when it expires rather than setting it once
   and forgetting.*

### `WitnessDeploymentAttestationV1`

| Field | Type | Purpose |
|---|---|---|
| `attestation_version` | `u64` | `1`. |
| `witness_id`, `witness_instance_id` | `String` | Which witness store this describes. |
| `hub_identity` | `String` | Which Hub it is issued for. |
| `posture` | enum tag | `Counterparty`, `NeutralThirdParty`, `SameOperatorSeparateInfrastructure`. Any other value refuses. |
| `witness_operator` | `String` | Named operating entity. |
| `separation_statement` | `String` | Free text: what separates the witness's failure domain from the Hub's. Backup sets, hosting, key custody. |
| `attested_at`, `expires_at` | `u64` | Bounded validity. Weeks, not years. |

The three postures are all valid — ADR-001 says who runs the witness is the
owner's trust decision and the code must work for all three. So the posture does
**not** change whether `external_rollback_anchor_ready` may be true. What it
changes is what the Hub *publishes*: `witness_posture` and `witness_operator`
appear in health output, so a wallet deciding whether to trust this Hub with
mainnet funds can see what the anchor is actually worth. A guarantee whose
strength depends on who holds a key should not be reported as a single boolean
with the key holder hidden.

There is no `SameHost` posture. It is not an option in the enum, so a
configuration that wants it cannot express it.

### A soft signal, reported and never enforced

If the witness's `witness_boot_id` changes in lockstep with the Hub's own
restarts, every time, over many restarts, that is weak evidence they share a
host or a lifecycle manager. Report it as a health field. Do **not** gate on it:
it has obvious false positives (a shared maintenance window, a coordinated
deploy) and is trivially defeated by anyone who knows it exists. It is a hint for
a reviewer, labelled as one.

### What the flag becomes

`measure_external_rollback_anchor_ready()` at
`crates/l2-fast-pay-hub/src/readiness.rs:409` currently returns a hardcoded
`false`, correctly, because nothing produces a receipt. It becomes a conjunction,
false if any part is missing:

- a witness is configured with a pinned id, pinned receipt key and pinned
  authorisation key; **and**
- the deployment attestation verifies, names an allowed posture, and has not
  expired; **and**
- every hard refusal in this section passes; **and**
- the startup probe succeeded and the Hub agrees with the witness on every
  channel it holds; **and**
- a receipt verified within the freshness window; **and**
- no channel is latched in anchor refusal.

Never a function of a URL being configured, an operator assertion, a flag, or a
counter file on this host — the existing doc comment at `readiness.rs:392-408`
already rules all three out and it stays. Both directions must be proven by test:
`false` with no witness, an unreachable witness, an expired attestation, a
malformed receipt or a counter behind the state; `true` only with a live witness
returning a valid, fresh receipt.

The false direction is already covered by
`crates/l2-fast-pay-hub/tests/honest_readiness_flags.rs`
(`external_rollback_anchor_flag_is_false_because_no_anchor_exists`,
`production_mainnet_ready_is_false_while_any_part_is_missing`,
`measured_flags_fail_closed_when_the_node_is_unreachable`). Extend that file
rather than starting a new one, and keep those tests passing — when a witness
exists they must keep reading `false` for the no-witness and unreachable-witness
cases, which is exactly what makes the new `true` case mean something.

`HubHardGuarantees::production_mainnet_ready` keeps ANDing this with everything
else, and `health()` keeps reporting conservatively. The contract settled in
`233c470` is not reopened to make this land.

### The optional TPM second factor

ADR-001 item 7. If a TPM NV monotonic counter is added for single-operator
deployments, it is **ANDed** with the witness and never substituted for it. It
cannot make the flag true on its own, it cannot rescue an unreachable witness,
and a TPM failure refuses. It is a second lock on the same door, not a spare key.

---

## 11. Deployment configuration

Who runs the witness is not decided here. It is configuration, and the same code
serves all three postures.

| Setting | Required | Notes |
|---|---|---|
| `witness_url` | yes | HTTPS only. Must not resolve to this host. |
| `witness_id` | yes | Pinned. |
| `witness_receipt_public_key` | yes | Pinned. Online key, verifies receipts and refusals. |
| `witness_authorisation_public_key` | yes | Pinned. Offline key, verifies attestations and resyncs. |
| `witness_attestation` | yes | The signed `WitnessDeploymentAttestationV1`. |
| `witness_request_timeout` | yes | Fail closed on expiry. There is no "proceed on timeout". |
| `witness_startup_probe_required` | — | Not configurable. Always required. |

Absent or malformed configuration reads as *no witness*, which reads as
`external_rollback_anchor_ready = false`. It never reads as "anchor not
required".

---

## 12. Open questions for the owner

1. **Who runs the witness.** Deliberately not decided here, per the ADR. It needs
   to be decided before the witness service is built (ADR item 3) and written
   into `docs/agent-wallet/EXTERNAL_ROLLBACK_ANCHOR_REQUIREMENTS.md`.
2. **One witness for many Hubs.** The ADR flags this. The counter namespace is
   per `hub_identity`, so it is mechanically fine — but if the witness operator
   is also a Hub operator, the trust story changes and `previous_counter_value`
   becomes harder to reason about across tenants.
3. **Witness log retention.** "Back to the last close or resync baseline" is the
   floor. A longer retention makes incidents easier and costs almost nothing;
   someone should pick a number.
4. **Counterparty bill-retention expectation.** Procedure A depends entirely on
   the counterparty holding their bills. That should be an agreed expectation
   before it is needed, not a discovery during an incident.
5. **Attestation validity period.** Long enough not to be a nuisance, short
   enough that nobody sets it and forgets. Weeks.

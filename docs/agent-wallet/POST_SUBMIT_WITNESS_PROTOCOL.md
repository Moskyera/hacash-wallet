# HPAY Agent Wallet Post-Submit Witness Protocol

Status: implemented and automated-test verified for the strict testnet pilot.

## Final lifecycle

The durable payment sequence is:

~~~text
Intent
-> Reservation
-> Unsigned commitment
-> Mobile approval
-> Desktop signing
-> SignedPreBroadcast witness
-> Broadcast
-> Submitted witness
-> Exact-hash reconciliation
-> ReconciledFinal witness
~~~

The three operation anchors are typed protocol phases, not display labels:

- `SignedPreBroadcast` proves what was signed before the first submit.
- `Submitted` proves the local transaction id and the submitted or uncertain
  transaction state after the first submit attempt.
- `ReconciledFinal` proves the exact externally reconciled terminal result.

Each anchor binds wallet and device identities, authorization and witness
epochs, network/genesis and node profile, journal head, materialized-state
commitment, operation id, typed transaction state, policy epoch, sequence,
previous anchor hash, and expiry.

## Operation state transitions

After pre-broadcast witnessing, the desktop persists `BroadcastSubmitted` and
the local transaction hash before the node call. A successful node response
moves to `SubmittedAwaitingFinalWitness`. An ambiguous response moves through
`BroadcastUncertain` to `ReconciliationRequired`; it is never automatically
rebroadcast.

Exact-hash reconciliation produces `ReconciledAwaitingFinalWitness`. Only a
valid `ReconciledFinal` witness receipt can commit the terminal state. The
reservation remains held until the required final witness is durable. In the
strict pilot, any operation awaiting a post-submit or final witness blocks new
Agent Wallet writes.

## Offline and retry behavior

- If the phone is offline after submission, the operation remains awaiting its
  `Submitted` witness. No second broadcast is attempted.
- The same durable proposal is returned for an exact retry while valid.
- A signed receipt advances state once. Exact duplicates return known status.
- A lost response after submit is recovered from the local transaction id and
  durable operation state, not by resubmitting.
- A node timeout is not evidence that the transaction was rejected.
- Reconciliation is always by the exact locally computed transaction hash.

The authenticated witness history is append-only within its 4,096-record
bound. The next payment can begin only after the previous operation has a final
witness and its reservation is released.

## Remaining evidence

Automated mock-node tests prove one-submit idempotency, offline phone behavior,
final reservation release, and a second operation after final witnessing. No
physical Android device or live testnet transaction was available for this
checkpoint, so no real-device or live-network completion claim is made.

On 2026-08-02 the isolated node capability contract was verified, but the node
remained at height 0 without block one. Therefore no SignedPreBroadcast,
Submitted, or ReconciledFinal receipt was created on a live network, and no
reservation was opened or released.

## Network binding

New pilot approvals and witness anchors use `local_pilot_v1` as the wire network ID. Their block 1 field and node profile commitment bind the exact Local Pilot instance. Legacy `testnet` records remain decodable only for fail-closed recovery and cannot authorize new writes against the Local Pilot node.

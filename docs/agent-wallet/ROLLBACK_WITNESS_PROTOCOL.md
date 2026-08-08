# HPAY Rollback Witness Protocol

Status: strict Testnet Pilot protocol. It is not a complete backup, disaster-recovery, or mainnet protocol.

## Why an external mobile witness exists

An encrypted desktop vault and authenticated local journal can detect tampering inside the current filesystem, but a complete machine snapshot may restore an older vault and its matching older journal together. The Android companion therefore stores an independent, monotonic public checkpoint for the Agent Wallet.

The phone does not receive the blockchain private key. It verifies state commitments and signs a witness receipt using a separate Android companion identity. A compromised or lost phone must not gain authority to send HAC or export desktop secrets.

## Authorities and durable state

Desktop owns:

- the Agent Wallet blockchain key and transaction signer;
- encrypted materialized wallet state;
- authenticated journal sequence and head;
- the paired-device registry and authorization epochs;
- the current witness epoch, last anchor sequence/hash, pending proposal/receipt, and last completed receipt.

Android owns:

- a hardware-backed, non-exportable companion identity;
- paired desktop/mobile public records and wallet scope;
- replay high-water marks and used nonces;
- monotonic approval sequence and pending approval metadata;
- MobileWitnessState, including last anchor sequence/hash, last journal sequence/head, accepted anchor ids, and the last public receipt payload.

Neither side stores the other side's private key.

## Anchor contract

RollbackAnchor version 1 is canonical and signed by the authorized desktop companion identity. It binds:

- Agent Wallet id;
- desktop and mobile device ids;
- both authorization epochs;
- testnet network id and block-one fingerprint;
- node profile id and transaction format version;
- signer, journal, witness, policy, and capability epochs;
- monotonic anchor sequence and previous anchor hash;
- journal sequence and head;
- materialized-state commitment;
- operation id and phase;
- creation and expiry times.

The desktop Pilot creates an operation anchor only in SignedAwaitingWitness. Its lifetime is five minutes. The general protocol rejects anchors longer than ten minutes.

WitnessReceipt version 1 binds the anchor id/hash, wallet and devices, mobile authorization epoch, witness epoch, anchor sequence, and acceptance time. It is signed by a mobile device holding WitnessRollbackAnchor.

## Exact lifecycle

| Step | Durable transition | Network side effect allowed |
|---|---|---|
| 1 | Android stores the exact approval decision and approval sequence. | None |
| 2 | Desktop stores approval, signs the transaction once, and enters SignedAwaitingWitness. | None |
| 3 | Desktop initializes witness state if needed and persists one pending signed proposal. | None |
| 4 | Android verifies desktop signature, wallet/device scope, approval/network binding, epochs, sequence, previous hash, journal monotonicity, and expiry. | None |
| 5 | Android advances and persists MobileWitnessState before biometric receipt signing. | None |
| 6 | Desktop verifies the signed receipt, advances its high-water sequence/hash, stores the receipt, and enters WitnessedAwaitingBroadcast. | None |
| 7 | Desktop persists BroadcastSubmitted and the exact local tx hash. | One submit may now occur |
| 8 | Submit success or uncertainty enters a post-submit state that requires a `Submitted` anchor. | No automatic retry |
| 9 | Android advances and witnesses the post-submit state; desktop persists `SubmittedAwaitingFinalWitness` or `ReconciliationRequired`. | None |
| 10 | Exact-hash external reconciliation enters `ReconciledAwaitingFinalWitness`. | Query only |
| 11 | Android witnesses `ReconciledFinal`; desktop commits the terminal state and releases the reservation. | None |
| 12 | Desktop retains authenticated witness and rotation history and clears only the completed pending slot. | None |

The high-water sequence/hash is never cleared when the pending slot is archived.

## Retry and idempotency rules

- Repeating pending_rollback_anchor for the same operation returns the exact durable proposal while it is valid.
- A different operation cannot replace an existing pending proposal.
- An expired pending proposal returns RecoveryRequired; it is not silently reissued at the same sequence.
- From SignedAwaitingWitness, only a valid mobile receipt can advance the operation.
- From WitnessedAwaitingBroadcast, only the receipt stored for that pending proposal can resume submission.
- From BroadcastSubmitted, BroadcastUncertain, post-submit, reconciliation, or final states, the matching receipt returns or advances only the known durable status. It must not submit again.
- resume_payment never automatically rebroadcasts a submitted or uncertain operation.
- A lost response after desktop archival can be answered from last_completed without another submit.
- Archival allows the next operation to create anchor_sequence + 1.

Automated focused tests verify these desktop-core properties, including a submit counter that remains one after a lost acknowledgement.

### Android retry caveat

The Android durable witness currently retains the receipt payload through MobileWitnessState, while signing is performed again when sending a witness. The desktop's completed/pending retry paths compare the full SignedWitnessReceipt. Automated tests reuse the exact signed object; a real Android Keystore retry after response loss has not yet proven that the exact signed bytes are retained or reproduced.

This is a real-device evidence blocker. A production design should either durably retain the exact signed receipt bytes or define idempotency by a verified canonical receipt identity rather than relying on signature-byte equality.

## Fail-closed invariants

Desktop authenticated state rejects:

- invalid witness version or epoch;
- zero/nonzero sequence and hash contradictions;
- malformed hash encodings;
- a pending sequence that decreases, skips, or does not extend the previous hash;
- a received receipt whose anchor hash differs;
- a completed record outside the desktop high-water range;
- wallet, mobile-device, anchor-id, or anchor-hash scope mismatch.

The general state loader invokes witness-state validation and maps failure to RecoveryRequired. Workflow entry points also require the expected operation state.

Android rejects:

- stale, duplicate, skipped, or forked anchor sequences;
- decreasing journal sequence;
- changed journal head at the same sequence;
- wrong wallet, desktop, mobile, network, genesis, signer epoch, journal epoch, or witness epoch;
- unknown/revoked devices or missing witness permission;
- expired proposals and replayed transport messages.

## Detected rollback

With the phone state intact, the protocol detects a desktop rollback that presents:

- an older anchor sequence;
- a fork from the stored previous anchor hash;
- a lower journal sequence;
- a different journal head for the same sequence;
- older authorization or witness epochs;
- a proposal for another wallet, network, node binding, or operation.

With desktop authenticated state intact, malformed or decreasing desktop witness checkpoints fail on load.

## Rollback not detected

The current two-party protocol cannot detect simultaneous restoration of both desktop state and Android durable witness state to the same earlier mutually consistent checkpoint. It now creates `Submitted` and `ReconciledFinal` mobile-witnessed anchors, but they cannot detect a coordinated rollback of both parties.

Mitigation before mainnet requires a third independent witness, a non-rollbackable platform counter, a remote transparency service, or another reviewed terminal-checkpoint design.

## Device loss and rotation

Android reset is blocked after a Pilot approval is pending or a witness sequence has been initialized. Controlled normal and lost-phone rotation are implemented and described in [WITNESS_ROTATION_PROTOCOL.md](WITNESS_ROTATION_PROTOCOL.md). Rotation preserves the high-water anchor, increments the witness epoch exactly once, revokes the old phone, and requires a final new-phone completion anchor.

Real two-phone rotation and the operator procedure for clearing the revoked old phone are not yet verified. Do not use the Pilot with value that cannot be abandoned.

## SLIP-39 evaluation

SLIP-39 is not part of this protocol and is not implemented. It may be evaluated later for backup of an appropriate recovery secret, but it cannot replace monotonic rollback witnessing by itself. Any future use needs a separate threat model, authenticated share metadata, restore and rotation tests, and a rule preventing shares from granting the phone generic transaction-signing authority.

## Verified automated coverage

Current verified commands include:

- cargo test -p agent-wallet-core --features agent-wallet-testnet-pilot: 128 passed, 0 failed.
- focused witness and rotation tests: 10 passed, 0 failed.
- strict feature Clippy with -D warnings: passed.

These are automated/simulated results. Real Windows plus Android witness recovery has not been executed.

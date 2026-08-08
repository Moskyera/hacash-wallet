# HPAY Agent Wallet Witness Rotation Protocol

Status: implemented and automated-test verified for the strict Windows plus
Android testnet pilot. This is not a mainnet recovery protocol.

## Security objective

Witness rotation replaces the Android rollback-witness authority without
copying the Agent Wallet blockchain key to the phone or resetting the witness
high-water mark. Agent Wallet writes are suspended for every non-terminal
rotation phase. Personal Wallet state and locks are not involved.

The canonical `WitnessRotationRecord` binds the Agent Wallet, desktop, old and
expected replacement mobile identities, network and genesis identity, signer
and journal epochs, old and new witness epochs, both mobile authorization
epochs, last accepted anchor, journal head, policy epoch, mode, reason,
creation time, and expiry. The record is encoded under
`HPAY/COMPANION/WITNESS-ROTATION/V1`; the new-phone baseline uses
`HPAY/COMPANION/WITNESS-ROTATION-BASELINE/V1`. Raw JSON is not a signing
contract.

## Durable phases

The protocol uses the typed `WitnessRotationPhase` state machine:

- `Stable`
- `RotationRequired`
- `RotationPrepared`
- `RotationRequested`
- `AwaitingOldWitnessAuthorization`
- `RotationTicketIssued`
- `AwaitingCandidatePairing`
- `CandidatePairedRestricted`
- `CandidateBaselineVerified`
- `AwaitingOldDeviceRevocation`
- `AwaitingCompletionAnchor`
- `AwaitingNewDevicePairing`
- `AwaitingNewWitnessBaseline`
- `AwaitingRotationCompletionAnchor`
- `Completed`
- `BlockedByPendingApproval`
- `BlockedByUnresolvedSignedOperation`
- `BlockedByBroadcastUncertainty`
- `RecoveryRotationRequired`
- `RotationRecoveryRequired`

Only `Stable` and `Completed` permit Agent Wallet writes. The current
implementation enters the applicable awaiting phase directly after all
preconditions pass; the additional enum values remain explicit fail-closed
states for durable recovery and UI reporting.

## Preconditions shared by both modes

Rotation is rejected unless:

- the local Agent Wallet session is unlocked and testnet-bound;
- the authenticated journal and materialized state validate;
- the existing rollback witness validates and has no pending proposal;
- no operation retains a reservation or is signed, submitted, uncertain,
  awaiting a final witness, awaiting reconciliation, or in recovery;
- the old phone is the active rollback witness for normal replacement;
- the expected replacement identity is distinct from the old phone;
- no other non-completed rotation exists;
- the rotation lifetime and every signed payload are valid.

The replacement phone does not need prior normal pairing. It joins through a
rotation-specific, one-time `RotationPairingTicket` and remains outside the
general `DeviceRegistry` until final completion.

## Rotation candidate pairing

The desktop signs a canonical ticket bound to the rotation, Agent Wallet,
desktop, old mobile, exact candidate identity and fingerprint, network,
genesis identifier, witness and authorization epochs, last anchor, journal
head, policy epoch, issue/expiry times, and a single-use nonce. Normal
replacement also binds the old-mobile authorization commitment.

The candidate signs a canonical `RotationCandidateAcceptance`. A successful
acceptance consumes the ticket durably. Reuse, expiry, cross-wallet,
cross-network, desktop substitution, candidate-key substitution, and
concurrent second-candidate scans fail closed.

While restricted, the candidate may only poll its rotation, submit its exact
baseline, submit the exact completion witness, or disconnect. It cannot
approve or reject payments, send emergency/admin commands, read general Agent
Wallet activity, open a general companion session, or act as a financial
witness.

## Normal replacement

1. The desktop verifies all preconditions and persists the rotation.
2. The old phone polls the private LAN session, verifies the current anchor and
   replacement-device identity, requires biometric authorization, and signs
   the exact rotation record.
3. The desktop verifies and durably stores the old-phone authorization.
4. The desktop issues a signed, expiring, one-time rotation QR ticket.
5. The unpaired replacement phone accepts the ticket and becomes a restricted
   `RotationCandidate`, not a normal paired device.
6. The candidate verifies the record and durably stores a new
   `MobileWitnessState` baseline before signing its baseline receipt.
7. The desktop first persists the accepted baseline as an authenticated
   checkpoint. It then revokes the old device, increments the witness and
   mobile-authorization epochs, and persists a second checkpoint. A crash
   between these writes resumes idempotently from the durable baseline.
8. The desktop creates a `WalletState` completion anchor using the candidate
   and live verified node binding.
9. The candidate persists the completion witness before signing it.
10. The desktop advances the witness high-water mark, admits the new phone to
    the normal registry, and persists `Completed`.

The old phone cannot authorize later approvals or witness anchors after step
7. The new phone is not authoritative before step 10. Duplicate messages are
idempotent only when they exactly match the durable
record or signed artifact.

## Lost-phone recovery

Lost-phone mode skips old-phone authorization, but it is allowed only for a
clean financial state and after a live verification of the pinned custom node,
the stored testnet block-one fingerprint, and the required capability
contract. It uses the same unpaired, restricted candidate ticket. The
replacement baseline and final `WalletState` completion anchor are still
mandatory. The old device is revoked at the baseline authority transition.

This mode does not prove absence of a transaction outside HPAY state. The Pilot
therefore permits it only when no operation/reservation is unresolved and must
still be treated as a controlled recovery ceremony with disposable testnet
value.

## History, concurrency, and residual risk

Completed rotations are authenticated and retained in order. The history is
bounded at 4,096 records; reaching the bound fails closed rather than deleting
history. A second rotation archives the previous completed record and must
continue device identity and witness epochs exactly.

The Agent Wallet process lock prevents two desktop processes from signing the
same wallet. Rotation, payment, witness reset, emergency stop, and revocation
are serialized through authenticated state transitions. Emergency stop and
revocation win over pending work.

The protocol still cannot detect simultaneous rollback of both desktop and
replacement-phone state to the same earlier consistent checkpoint. Real
two-phone biometric/Keystore/LAN evidence is also pending.

The 2026-08-02 isolated-node preflight does not change this evidence boundary.
No physical witness or rotation receipt was created. The third independent
rollback-anchor requirement remains an explicit mainnet blocker.

Safe cancellation is available only before a candidate baseline has been
accepted. It invalidates the ticket and restricted candidate while preserving
the old witness. At or after the baseline authority transition, cancellation
fails closed and the controlled rotation must be completed or recovered.

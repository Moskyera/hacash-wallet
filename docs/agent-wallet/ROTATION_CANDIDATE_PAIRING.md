# HPAY Rotation Candidate Pairing

Status: automated-test verified for the Windows plus Android testnet Pilot.
Physical two-phone verification is pending.

## Purpose

A replacement Android phone does not need prior normal companion pairing. It
joins one active witness rotation as a restricted `RotationCandidate`.
Candidate status is not payment, admin, emergency, or general witness
authority.

## Ticket and acceptance

The desktop signs a canonical, short-lived `RotationPairingTicket` that binds:

- ticket, pairing, rotation, Agent Wallet, desktop, old-mobile, and candidate
  identities;
- the candidate identity fingerprint;
- network and genesis identity;
- current and next witness/mobile-authorization epochs;
- last anchor, journal head, and policy epoch;
- issue/expiry times and a single-use nonce;
- the old-mobile authorization commitment for normal replacement.

The candidate signs a canonical `RotationCandidateAcceptance`. The desktop
checks every binding and consumes the ticket durably. Raw JSON is never the
signing contract. Replay, expiry, wrong wallet/network/desktop, key
substitution, and a concurrent second candidate fail closed.

## Restricted authority

Before final completion the candidate can only:

- poll the exact active rotation;
- submit the exact candidate baseline;
- submit the exact completion witness;
- disconnect.

It cannot approve/reject payments, provide ordinary witness receipts, invoke
emergency/admin commands, read general activity, or obtain a general companion
session. It remains outside the normal device registry.

## Authority transition and recovery

The candidate baseline is persisted first. Old-device revocation and the epoch
transition are persisted in a second authenticated checkpoint. If the process
stops between them, replaying the identical baseline resumes the revocation
exactly once. The old phone is no longer authoritative after that transition;
the candidate is not authoritative until the final completion receipt.

Cancellation is allowed only before the baseline transition. It invalidates
the ticket and candidate and retains the old witness. Later cancellation fails
closed.

## Evidence boundary

Unit/integration tests cover restart, replay, concurrent scans, cancellation,
normal and lost-phone flows, ACL restrictions, and final registry admission.
No physical Android device was available on 2026-08-01, so biometric,
hardware-backed Keystore, same-LAN, and two-phone claims remain unverified.

### Physical-pilot status, 2026-08-02

No physical Android device was detected and ADB was unavailable. Candidate
pairing, hardware-backed identity, biometric authorization, and two-phone
rotation were not executed. The live isolated node also lacks block one, so
lost-phone rotation remains blocked by the node-binding precondition.

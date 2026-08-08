# HPAY Agent Wallet Testnet Pilot Limitations

Status: known limitations and release blockers as of 2026-08-01.

## Safety classification

The current implementation is suitable only for a controlled, low-value, disposable testnet evaluation after local build gates pass. It is not approved for mainnet, large balances, unattended payments, or replacement of a hardware wallet.

## Supported surface

| Area | Pilot status | Consequence |
|---|---|---|
| Windows desktop signer | Implemented and automated-test covered | Real Windows runtime evidence is still required. |
| Android companion | Implemented and contract-test covered | Real Android, biometric, Keystore, and same-LAN evidence is still required. |
| Linux desktop | Blocked | Pilot feature build fails intentionally because of the glib 0.18.5 blocker. |
| iOS companion | Unsupported | No Pilot approval/witness claim is allowed. |
| Hacash testnet | Required | New Agent Wallet mainnet spending is blocked. |
| Custom fullnode 1.0.10 | Required | No automatic fallback or discovery is allowed. |
| HAC Type 2/action 1 | Required | Other formats/actions are outside the Pilot. |
| HIP-20 | Disabled | No HIP-20/native-asset Agent Wallet send. |
| L2/Fast Pay | Unsupported in Agent Wallet Pilot | Personal Wallet L2 remains separate and unchanged. |
| Autonomous payments | Unsupported | Every decision requires explicit trusted-device action. |
| Completing a payment approval | Implemented, desktop-approved and phone-witnessed | The owner approves on the desktop; the payment reaches the network only after the paired phone witnesses it. See "Completing a payment approval" below. |
| Agent wallet fee | Zero | Only the network fee is included. |

## Completing a payment approval

An agent proposes a payment, the owner reviews the exact transaction on the
desktop and approves it, and the paired phone witnesses it. That path is
implemented and executed end to end in
`crates/agent-wallet-core/src/service/companion/tests/desktop_witness_flow.rs`:
a real agent intent, a real node-built unsigned body, a real desktop approval, a
real signature by the wallet's own signer, discovery through the least-privilege
witness disclosure, a real rollback anchor, a real witness receipt, and exactly
one submission.

This replaces the previous limitation, in which the desktop refused every
approval. That refusal was a fail-closed stub: completing an approval signs into
`SignedAwaitingWitness`, and at the time the phone signed a witness receipt only
for an operation it had approved itself and was never told a desktop-approved
operation existed. Both halves are closed - the phone can witness an operation
it did not approve, and the snapshot discloses at most one witness-pending
operation id to a phone holding `WitnessRollbackAnchor`.

What still constrains it, and is enforced rather than documented:

- **A payment reaches the network only with a real witness.** No change here.
  `resume_payment` refuses a `SignedAwaitingWitness` operation, and
  `apply_mobile_witness_and_broadcast` requires a signature from the phone the
  anchor names, over that exact anchor. Pinned by
  `a_desktop_approved_payment_still_reaches_no_node_without_a_real_phone_witness`.
- **A desktop approval needs a phone that can witness, before it signs.**
  `approve_desktop_and_broadcast` refuses with
  `WitnessPhoneRequiredForApproval` when no registered, unrevoked device holds
  `WitnessRollbackAnchor`. Without that check a desktop approval on an unpaired
  wallet would sign into a status no sweep can expire, holding its reservation
  and refusing every later payment an anchor. The refusal happens before
  anything is written and names the control that resolves it. Pinned by
  `a_desktop_approval_with_no_phone_that_can_witness_is_refused_unsigned`.
- **It must be the phone the anchor is bound to, not just any paired phone.**
  `rollback_witness.mobile_device_id` is pinned to the first phone that ever
  fetched an anchor and is moved only by `complete_witness_rotation`, so an
  ordinary revoke-and-re-pair leaves a registry containing an active witness
  phone that `pending_rollback_anchor` will still refuse with
  `RollbackDetected`. The prerequisite therefore asks about that exact device.
  Pinned by
  `a_phone_paired_after_the_witness_was_bound_does_not_unlock_the_approval` and
  `a_revoked_phone_does_not_satisfy_the_witness_prerequisite`.
- **The approval mode still decides which device may approve.**
  `ApprovalMode::DesktopManual` is the only mode this desktop writes, and under
  it the desktop approves and the phone is refused
  (`apply_mobile_approval_and_broadcast` admits only the mobile modes). A
  mobile mode moves that authority to the phone. Pinned by
  `the_shipping_desktop_manual_policy_is_approved_by_the_desktop_and_not_the_phone`
  and `a_mobile_approval_mode_is_what_lets_the_phone_decide_the_same_payment`.
- **A wrong approval still gets its own reason.** A throwaway probe clone
  validates the commitment before the witness-phone refusal is reached, so a
  malformed, expired, mismatched or wrong-epoch approval is refused with its own
  error and writes nothing.

The desktop reflects this: the Approve control is rendered again, the notice
beside it says that approving signs and then stops for the phone rather than
paying anyone, and the message after a successful press is derived from the
status the wallet returned - `signed_awaiting_witness` reads as "nothing has
been sent to the network yet", never as "submitted".

### Known unrecovered state: an anchor that expires before its receipt arrives

**This is a real, reachable, currently unrecoverable state on the path above.**
It is not caused by the desktop approval and is not new - the phone-approved
path reaches the same place - but the desktop approval makes it routine, so it
is written down rather than left to be discovered.

A rollback anchor lives for five minutes (`ANCHOR_LIFETIME_SECS`). Once
`pending_rollback_anchor` has issued one, the desktop holds it in
`rollback_witness.pending`, and nothing retires it: only
`complete_witness_rotation` ever clears that slot. If the phone's reply does not
reach the desktop inside those five minutes - a slow LAN reconnect is enough,
and the owner may have confirmed and signed well within the window - then, all
executed:

| Attempt | Result |
| --- | --- |
| Deliver the genuine receipt | `RollbackDetected` (the anchor is expired) |
| Fetch a fresh anchor | `RecoveryRequired` |
| `resume_payment` | `RollbackWitnessRequired` |
| `reject_payment` | `InvalidOperationState` |
| `confirm_broadcast` | `ApprovalCommitmentMismatch` |
| `prepare_witness_rotation` | `RecoveryRequired` (a signed operation exists) |
| A new `create_payment_intent` | `RecoveryRequired` |
| Restart the desktop | unchanged |

The operation stays in `SignedAwaitingWitness` holding its reservation, no
submission ever happens, and the Agent Wallet cannot make another payment. The
desktop additionally refuses to pair a phone while
`unresolved_signed_operations > 0`, so that route is closed too.

Nothing is lost to an attacker and nothing is spent - the failure is
fail-closed - but the wallet's agent-payment feature is permanently disabled
with no in-app recovery. **Do not enable the Approve control for anyone but a
disposable pilot wallet until this has a way out.** The missing piece is an
owner-driven way to abandon a signed-but-unwitnessed operation, or a way to
reissue an anchor whose receipt never arrived; both need the phone's own
`MobileWitnessState` sequence to be reconciled, so neither is a local change.

### Known unrecovered state: a revoked witness phone

`prepare_witness_rotation` requires the OLD phone to still be a registered,
unrevoked `WitnessRollbackAnchor` device. Revoking the lost phone first and
pairing a replacement the ordinary way therefore makes the rotation itself
impossible, and the anchor pin can never move. Every later desktop approval is
refused with `WitnessPhoneRequiredForApproval` - fail-closed, nothing signed,
reservations released - but the wallet cannot make agent payments again.
Replace a phone with **Replace the paired phone** before revoking the old one.

## Node limitations

- The Pilot requires a reported capability API. A missing endpoint cannot downgrade to legacy Type 2.
- The node must identify as hacash-fullnode 1.0.10 on a non-mainnet chain and enable Type 2 plus action 1.
- The block-one fingerprint is pinned per Agent Wallet.
- A node-profile change after approval invalidates the approval.
- The node profile hash currently binds identity, chain, enabled transaction types, and enabled action kinds. It does not directly hash every feature boolean or limit. NodeCapabilities validation checks internal consistency, but the approval commitment is not a complete hash of the full JSON document.
- The custom node reports HIP-20 false. HIP-20 primitives are a separate capability and do not activate HIP-20 send.
- The exact official eae78afb source is not available in the local object database, so drop-in compatibility is not verified.
- A live local 1.0.10 capability response was captured on 2026-08-01, but that
  node reported `mainnet=true` and was rejected for the testnet Pilot. A
  separate testnet data directory and live transaction-status reconciliation
  exercise have not been verified.

## Rollback-witness limitations

The phone detects a desktop-only rollback when its own high-water state remains current. The protocol does not detect simultaneous rollback of both desktop and phone to the same earlier consistent checkpoint.

Other limitations:

- only one pending witness proposal is allowed;
- a proposal expires after five minutes;
- an expired proposal enters RecoveryRequired and has no completed operator recovery flow;
- authenticated witness and completed-rotation histories are bounded at 4,096 entries and fail closed at the bound;
- post-submit and final reconciliation anchors are implemented but have no real-device/live-network evidence;
- BroadcastUncertain requires exact-hash reconciliation and is never auto-rebroadcast;
- a third independent witness or non-rollbackable counter is not implemented;
- Android reset is blocked after approval/witness initialization; controlled replacement-device rotation is implemented but unverified on two real phones;
- the replacement phone can enter through a rotation-only one-time ticket
  without prior normal pairing, but the flow is not yet verified on two
  physical phones;
- the revoked old phone can remain locally rotation-blocked until a controlled cleanup procedure is executed.

### Signed receipt retry evidence gap

Desktop automated tests prove that retrying the exact stored SignedWitnessReceipt does not submit twice. Android durable state stores the public receipt payload and high-water state, then calls the Keystore signer when sending. Real-device evidence has not shown that a retry after process restart or lost acknowledgement preserves the exact signed receipt bytes expected by desktop equality checks.

This must be resolved or explicitly redesigned before production use.

## Recovery limitations

Implemented:

- authenticated journal verification;
- fail-closed state validation;
- exact recovery of one interrupted pending-state/journal transition;
- exact-hash confirmation for submitted/uncertain transactions;
- durable emergency-stop markers;
- recovery status instead of unsafe automatic retry.

Not implemented as a complete operator workflow:

- expired-anchor recovery/rotation;
- guided BroadcastUncertain reconciliation UI;
- independent recovery package tested across desktop and Android;
- SLIP-39.

The presence of RecoveryRequired means stop and preserve evidence. It does not mean the wallet can automatically repair the state.

## Real-device limitations

The following are not yet verified in this workspace:

- real Windows Named Pipe companion runtime;
- real Android device;
- biometric confirmation;
- hardware-backed per-use Android identity behavior;
- same-LAN discovery/session/reconnect;
- real custom testnet fullnode;
- funded testnet Agent Wallet;
- real node submission and external tx status reconciliation;
- power loss and process-kill timing at every durable boundary;
- phone loss and replacement on two physical devices;
- Android signed-receipt retry after a lost acknowledgement.

Automated or mock-node tests must be labeled Automated verified or Simulated integration verified, never Real-device verified.

## Operational limitations

- There is no node fallback. An unavailable pinned node pauses spending.
- There is no public agent HTTP/TCP API.
- There is no generic signing, raw transaction, private-key export, or arbitrary channel operation available to the agent.
- The Personal Wallet is outside the Agent Wallet security boundary and must not be used as a recovery shortcut.
- Emergency stop prevents new signing but cannot undo a transaction already accepted by the network.
- The Pilot must use disposable testnet value.
- No release artifact is approved by these documents.

## SLIP-39 future evaluation

SLIP-39 is not implemented or enabled. A future evaluation may consider it for recovery of a narrowly defined Agent Wallet recovery secret. It must not:

- copy the Personal Wallet key into the Agent Wallet domain;
- give Android generic blockchain-signing authority;
- replace the rollback-witness high-water protocol;
- be introduced without authenticated share metadata, restore tests, rotation, revocation, and loss procedures.

No current Pilot screen, command, vault format, or test proves SLIP-39 support.

## Mainnet blockers

All of the following are required before considering mainnet:

1. complete real-device evidence;
2. external audit of desktop, Android, protocol, node, and recovery code;
3. physical verification and external review of controlled witness/device rotation;
4. live testnet verification and external review of terminal/final anchors;
5. mitigation for simultaneous desktop/mobile rollback;
6. external review and real-session evidence for diagnostic export and secret redaction;
7. complete recovery and uncertain-broadcast runbook implemented in product;
8. verified fullnode source and deployment provenance;
9. limits appropriate for mainnet and incident response;
10. a separate explicit mainnet enablement review.

Passing mock tests does not remove these blockers.

## 2026-08-02 status refinement

The real custom testnet fullnode gap is partially closed: an isolated chain 7
node and explicit API capability contract were verified live. Synchronization,
canonical block one, transaction readiness, physical Android, funding, and a
live transaction remain open. Startup alone is not synchronization evidence.

## 2026-08-02 network identity clarification

No authoritative public Hacash Testnet V3 identity, block 1 fingerprint, bootstrap peer set or verified snapshot was found. The active development path is therefore the explicitly private `HPAY Local Pilot Chain V1`. Chain ID 7 alone is never accepted as identity. Agent payments remain blocked until the exact block 1, network instance, API contract and funded Agent address all verify.

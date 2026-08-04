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
| Agent wallet fee | Zero | Only the network fee is included. |

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

# HPAY Agent Wallet Testnet Pilot Architecture

Status: implementation and automated-test architecture, not a production or mainnet approval.

No real-device verification was performed for this documentation checkpoint.

## Purpose and security boundary

The Pilot evaluates manually approved, low-value Agent Wallet payments on Hacash testnet. It is deliberately narrower than the Personal Wallet and uses a separate Agent Wallet address, vault, state directory, policy, journal, signing session, and companion registry.

The paired phone is an external rollback witness. It does not hold the Agent Wallet blockchain private key. The desktop constructs and signs the Hacash transaction only after a typed user approval. Android holds a separate, non-exportable companion identity used for approval decisions and witness receipts.

The Pilot does not modify or authorize Personal Wallet signing, backup, settings, L2, DUST, updater, or release behavior.

## Supported deployment

| Role | Supported Pilot platform | Boundary |
|---|---|---|
| Agent Wallet and blockchain signer | Windows desktop | Pilot feature builds are compile-time blocked on non-Windows desktop targets. |
| Approval and rollback witness | Android | Pilot commands return unsupported outside Android. The companion identity is required to be hardware-backed, non-exportable, and protected per use. |
| Linux desktop | Blocked | `agent-wallet-testnet-pilot` triggers a compile error until the Linux `glib 0.18.5` blocker is resolved. Linux may build without the Pilot feature. |
| iOS | Not supported | No verified Pilot approval or witness implementation is enabled. |

This is therefore a Windows plus Android Pilot, not a general desktop/mobile feature.

## Components

1. `agent-wallet-core` owns the independent Agent Wallet vault, policies, payment state machine, authenticated state, journal, node binding, and rollback-witness state.
2. `companion-protocol` defines canonical pairing, approvals, replay protection, rollback anchors, witness receipts, and the mobile high-water state.
3. The Windows Tauri shell exposes the trusted Agent Wallet administration surface and the desktop companion runtime.
4. The Android Tauri shell exposes a restricted companion surface. It cannot export an Agent Wallet key or invoke generic sends.
5. The custom Hacash fullnode exposes the network and transaction contract used by the Pilot.

## Node trust contract

The Pilot is pinned to the custom `hacash-fullnode` version string `1.0.10`. Before any Pilot signing or resume path, the desktop verifies:

- the configured block-one fingerprint;
- a reported `/query/capabilities` response with API version 1;
- node name `hacash-fullnode` and version `1.0.10`;
- a non-mainnet, nonzero chain id;
- enabled transaction type 2;
- enabled action kind 1.

Missing, malformed, unsupported, wrong-version, wrong-network, or incomplete capability responses fail closed. A 404 legacy Type 2 fallback produced by the generic node client is rejected because the Pilot requires `source = reported`. There is no Pilot fallback to another public or discovered node.

The node profile commitment binds the capability API version, node name/version, chain id/mainnet bit, enabled transaction types, and enabled action kinds. Approval version 3 carries this profile, the testnet genesis identifier, chain id, and transaction format version 2. The binding is checked again before anchoring and before signing or resuming.

The custom node reports HIP-20 as disabled. HIP-20 transfer is not an active Pilot feature. `hip20_primitives` is a separate reported capability and does not enable Agent Wallet HIP-20 send.

## Payment and witness sequence

The implemented sequence is:

1. An authorized local agent requests a typed HAC payment intent.
2. Desktop checks policy, recipient, budgets, node identity, balance, and transaction binding. Wallet fee is fixed at zero; only the network fee is included.
3. Android durably records the exact approval decision and monotonic approval sequence before biometric signing or transport.
4. Desktop durably accepts the exact decision, signs once, and enters `SignedAwaitingWitness`.
5. Desktop creates a five-minute `SignedPreBroadcast` rollback-anchor proposal bound to the wallet, devices, authorization epochs, node profile, journal head, materialized-state commitment, operation, transaction state, and policy epoch.
6. Android verifies the proposal and the pending approval binding, advances and durably stores its independent witness high-water mark, then signs the witness receipt.
7. Desktop verifies the receipt, durably advances its witness sequence/hash, and enters `WitnessedAwaitingBroadcast`.
8. Desktop persists `BroadcastSubmitted` and the exact local transaction hash before the first node submission.
9. A successful or ambiguous submit requires a `Submitted` post-submit anchor. Neither outcome is automatically rebroadcast.
10. Ambiguous outcomes enter `ReconciliationRequired` and may advance only after exact-hash node reconciliation.
11. Reconciled state enters `ReconciledAwaitingFinalWitness` and requires a `ReconciledFinal` anchor.
12. Only the final receipt releases the reservation and allows another Agent Wallet write.

Authenticated witness history is retained while the pending slot is cleared, so later operations and rotations continue the monotonic anchor sequence. See [ROLLBACK_WITNESS_PROTOCOL.md](ROLLBACK_WITNESS_PROTOCOL.md), [POST_SUBMIT_WITNESS_PROTOCOL.md](POST_SUBMIT_WITNESS_PROTOCOL.md), and [WITNESS_ROTATION_PROTOCOL.md](WITNESS_ROTATION_PROTOCOL.md).

## Durability and key separation

Desktop state is encrypted and bound to an authenticated append-only journal. One interrupted state/journal transition can be recovered only when the durable pending state exactly matches the next authenticated journal record. Other inconsistencies fail closed.

Android durable state contains public wallet and device scope, endpoint records, replay high-water marks/nonces, approval metadata, and the public witness checkpoint. It must not contain:

- the Agent Wallet blockchain private key;
- a Personal Wallet key;
- the desktop vault encryption key;
- a reusable signing token;
- a raw desktop session secret.

The Android companion identity is independent of the blockchain key and has no private-key export method in the Rust or Android contract.

## Explicit exclusions

The Pilot provides no:

- mainnet Agent Wallet send;
- autonomous approval or payment;
- L2/Fast Pay Agent Wallet payment;
- HIP-20 send;
- public TCP/HTTP agent API;
- generic signing or arbitrary transaction surface;
- node discovery or capability downgrade;
- Linux or iOS Pilot;
- SLIP-39 backup or recovery.

SLIP-39 is a future evaluation item only. It must not be described as enabled until a separate design specifies share generation, authenticated metadata, restore validation, rotation, and device-loss handling, followed by implementation and testing.

## Remaining gates

Automated and simulated tests do not complete the Pilot. The following remain required:

- real Windows Named Pipe and Android same-LAN evidence;
- real Android biometric and non-exportable Keystore evidence;
- a real testnet fullnode and funded low-value transaction;
- an operator-visible recovery flow for expired pending anchors and uncertain broadcast outcomes;
- physical two-phone verification of normal and lost-phone rotation;
- a real post-submit and final reconciliation anchor over a live testnet transaction;
- verification of the exact official `eae78afb` source before any compatibility claim;
- external security review before any mainnet consideration.

The residual risk is simultaneous rollback of both desktop authenticated state and the Android witness state to the same earlier consistent checkpoint. The current two-party design cannot detect that without a third independent witness or another non-rollbackable checkpoint.

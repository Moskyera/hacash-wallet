# HPAY Local Pilot Chain V1 evidence

Date: 2026-08-02

## Decision

No canonical public Hacash Testnet V3 identity contract, canonical block 1,
peer bootstrap or snapshot was available from the inspected official fullnode
source and public documentation. A private Local Pilot chain was therefore
created. It must never be represented as an official Hacash testnet.

Final classification: `No safe transaction-ready chain available`.

## Real chain evidence

| Field | Value |
|---|---|
| Evidence category | `LOCAL_PRIVATE_CHAIN` |
| Node | `hacash-fullnode 1.0.10` |
| Network kind | `local_pilot_v1` |
| Profile | `hpay-local-pilot-chain-v1` |
| Chain ID | `7` |
| Mainnet | `false` |
| Endpoint | `http://127.0.0.1:8197` |
| Current height | `12` |
| Block 1 | `000087f67e55660eaefed72e0b9499147556a33a34f18fa48900f4a2fa30cd29` |
| Network instance | `9ebd8657a72faed35ed4d6e309fab2ef259f054e4820684fab6c6b848e4438f3` |
| Real mining | Passed |
| Agent funding confirmed | `false` |
| Transaction ready | `false` |
| HPAY Agent wallet fee | `0` |

The bootstrap mining reward went only to the previously public Treasury
address. No private key, seed, passphrase, vault, pairing token or signature
was read or recorded. Mining was stopped after chain verification.

## Identity and fail-closed contract

The fullnode exposes network kind, profile, canonical block 1, deterministic
network instance ID, confirmed pilot-funding state and transaction readiness.
The wallet independently recomputes the instance ID and requires the exact
block 1 fingerprint. Chain ID 7 by itself never enables Agent payments.
Legacy nodes without this identity remain available only for Personal Wallet
read-only compatibility and legacy Type 2 behavior.

Adversarial tests reject height zero, height one, missing funding, missing
identity, a spoofed instance ID and the same chain ID with a different block 1.

## Automated gates

| Gate | Result |
|---|---|
| Fullnode basis and capability tests | 30 passed |
| Personal Wallet core | 401 passed |
| Agent Core Pilot | 137 passed |
| Agent Core non-Pilot | 110 passed |
| Companion protocol | 95 passed |
| Agent connector | 49 passed |
| Agent runtime | 11 passed |
| Private-LAN runtime | 17 passed |
| Tauri IPC/security Pilot | 66 passed |
| Tauri IPC/security non-Pilot | 51 passed |
| Mobile Rust Pilot | 30 passed |
| Mobile Rust non-Pilot | 30 passed |
| Fast Pay L2 | 38 passed |
| Dust Whisper | 8 passed, 1 live-relay test ignored |
| Desktop UI | 23 passed |
| Mobile UI | 130 passed |
| Desktop and mobile production builds | Passed |
| Desktop and mobile production dependency audit | 0 known vulnerabilities |
| Strict Clippy, Pilot and non-Pilot | Passed |
| Scoped Rust formatting | Passed |
| Android ARM64 Rust compile | Passed |
| Android generated-project validator | Passed |
| RustSec | Exit 0, 18 allowed upstream warnings |

This represents 1,226 successful automated test executions across the listed
feature variants. Targeted reruns used during implementation are not added to
that total.

RustSec warnings are upstream maintenance or soundness notices, principally
GTK3 bindings and the Hacash fullnode dependency on `libsecp256k1 0.7.2`.
They were not hidden and no lockfile or dependency was changed in this task.

## Not executed

- Agent Wallet creation and funding
- Agent payment preparation, signing or broadcast
- Post-submit and final reconciliation witnesses
- Physical Android installation, Keystore and biometric validation
- Same-LAN physical witness flow
- Two-phone rotation
- Mainnet, HIP-20 Agent send, Agent L2 or autonomous approval

The next safe step is for the user to create an Agent Wallet locally and share
only its public Hacash address. The Local Pilot node can then be restarted with
that public address as both reward and pilot-funding address, and a real funding
block can be mined before any physical Android flow begins.

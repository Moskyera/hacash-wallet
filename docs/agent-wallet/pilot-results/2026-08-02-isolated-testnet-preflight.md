# Isolated Testnet Preflight Evidence

- Session ID: `2026-08-02-isolated-testnet-preflight`
- Evidence category: `LIVE_CUSTOM_TESTNET_NODE`
- Application version: `1.0.2`
- Desktop source HEAD: `26ae4c5` plus unstaged scoped changes
- Mobile APK SHA-256: `148EC6B7C8FAC20E041A6E75F18BC716A616D8179B7AB04F7B60852C97F7715B`
- Network identity: Agent `testnet`, approval V3
- Chain identity: chain 7, mainnet false, block one unavailable
- Custom node: `hacash-fullnode 1.0.10`, build `2026/7/10 #1`
- Profile: `hpay-custom-1.0.10-testnet`
- Capability API: version 1
- Transaction API contract: all four required fields reported true
- Height: 0
- Peers/sync: peer count not reported; discovery/inbound disabled; not
  synchronized or transaction-ready
- Agent/mobile/desktop identifiers: not created or collected
- Executed: launcher guards, runtime identity, capability, latest-height query
- Passed: isolated path/ports, mainnet false, chain 7, node/API contract
- Failed: none
- Not executed: Android, pairing, funding, signing, broadcast, reconciliation,
  witness lifecycle, rotation, diagnostics export
- Transaction ID: not executed
- Journal/anchor/witness sequences: not created
- Rotation/reconciliation: not executed
- Known limitations: no block one, no physical Android, no funded Agent Wallet,
  no third rollback anchor

No private key, seed, passphrase, pairing/session token, raw transaction,
signature, vault, prompt, or full user data path is stored in this evidence.

## Automated and build gates

All counts below are from the 2026-08-02 rerun:

| Gate | Result |
|---|---|
| Personal Wallet core | 399 passed |
| Agent Core Pilot | 135 passed |
| Agent Core non-Pilot | 110 passed |
| Companion protocol with software test identity | 95 passed |
| Agent connector | 49 passed |
| Agent runtime | 11 passed |
| Private-LAN runtime | 17 passed |
| Tauri IPC/security Pilot | 66 passed |
| Tauri IPC/security non-Pilot | 51 passed |
| Mobile Rust Pilot | 30 passed |
| Mobile Rust non-Pilot | 30 passed |
| Fast Pay L2 | 38 passed |
| Dust Whisper | 8 passed, 1 local-relay test ignored |
| Custom fullnode capability tests | 4 passed |
| Desktop UI | 23 passed |
| Mobile UI | 130 passed |
| Desktop/mobile production builds | passed |
| Desktop/mobile production dependency audit | 0 vulnerabilities |
| PostCSS | 8.5.25 in both apps |
| Wallet workspace strict Clippy | Pilot and non-Pilot passed |
| Scoped Rust formatting | passed |
| Windows native release-mode compile | Pilot and non-Pilot passed |
| Android ARM64 release-mode native compile | Pilot and non-Pilot passed |
| Android generated-project/frontend validator | passed |
| RustSec | exit 0; 18 allowed warnings |

The fullnode-wide `-D warnings` Clippy gate remains pre-existing-fail. It stops
in unrelated `sys`, `field`, mining, and efficiency code. The scoped
`app/src/node_api.rs` formatting and capability tests pass; no unrelated
fullnode lint cleanup was attempted.

The existing debug APK was not rebuilt because no mobile code changed. Its
package/version/ABI/v2 signature, strict frontend validation, size, SHA-256,
and Android Debug certificate were reverified. No install was attempted.

## Final evidence classification

- `AUTOMATED`: verified for the suites above.
- `LIVE_CUSTOM_TESTNET_NODE`: verified for startup, isolation, runtime chain
  identity, capability contract, balance query, and exact-hash query.
- `PHYSICAL_ANDROID`: not executed.
- `TWO_PHYSICAL_ANDROID`: not executed.
- `LIVE_TESTNET_TRANSACTION`: not executed.
- Diagnostic export: not executed because there was no pilot session and no
  explicit export confirmation.

Readiness: `Automated hardening complete; physical Android pending`.

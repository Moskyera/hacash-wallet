# HPAY Agent Wallet Physical Pilot Scope

Status: frozen change boundary for RotationCandidate pairing and controlled
physical Android testnet verification.

## Initial checkpoint (2026-08-01)

- Branch: `codex/how-it-works-hacd-fidelity`
- Head: `26ae4c5`
- Modified entries: 201
- Untracked entries: 155
- Deleted entries: 5,513
- Staged entries: 0
- Existing deleted entries under `releases/`: 5,513
- Existing debug ARM64 APK SHA-256:
  `8D87D7732FE196A1C0B0FB419D592CAE246D0AD0A961AFC190920043A69380D2`

No reset, restore, clean, staging, commit, push, tag, or release is authorized.

## Allowed implementation files

- Rotation-only types in `crates/companion-protocol/`
- Rotation-only state and service modules in `crates/agent-wallet-core/`
- Rotation-only private-LAN handlers in `crates/wallet-tauri-common/`
- Rotation-only desktop UI/API under `apps/desktop/src/agent/`
- Rotation-only Android companion modules under
  `apps/mobile/src-tauri/src/agent_companion/`
- Rotation-only mobile UI/API under `apps/mobile/src/agent/`
- Narrow command, handler, capability, and permission inventories required for
  those rotation surfaces

## Allowed test files

- Rotation, pairing-ticket, candidate-authority, replay, crash-recovery, ACL,
  Android identity, and UI contract tests in the same packages
- Existing regression tests may be executed but not rewritten unless a real
  RotationCandidate regression requires it

## Allowed documentation files

- `docs/agent-wallet/WITNESS_ROTATION_PROTOCOL.md`
- `docs/agent-wallet/REAL_DEVICE_TEST_REPORT.md`
- `docs/agent-wallet/TESTNET_PILOT_RUNBOOK.md`
- `docs/agent-wallet/TESTNET_PILOT_LIMITATIONS.md`
- `docs/agent-wallet/ROTATION_CANDIDATE_PAIRING.md`
- `docs/agent-wallet/EXTERNAL_ROLLBACK_ANCHOR_REQUIREMENTS.md`
- `docs/agent-wallet/pilot-results/`
- this scope manifest

## Generated artifacts

- `target/`
- desktop/mobile `dist/`
- generated Android sources/resources/build outputs
- Android JNI libraries and ARM64 debug APK

Generated artifacts are evidence only, must not be staged, and must not be
published as releases.

## Read-only checkpoint files

- Personal Wallet implementation and vault/storage formats
- completed witness lifecycle and diagnostic-export code unless a candidate
  authority invariant directly requires a narrow check
- `Cargo.lock` and JavaScript lockfiles unless a new Critical/High blocker is
  proven; no dependency update is currently authorized
- pinned custom fullnode source, revision, configuration, and data directories

## Pre-existing unrelated modifications

All dirty paths outside the allowed sections are user-owned. They must not be
formatted, reverted, staged, deleted, or rewritten.

## Existing `releases/` deletions

The 5,513 tracked deletions under `releases/` are pre-existing. Their count and
paths must remain unchanged.

## Strictly forbidden paths and behavior

- Personal Wallet keys, addresses, send, backup, DUST, Fast Pay, updater, or
  settings behavior
- mainnet Agent Wallet send, HIP-20 Agent send, Agent L2, automatic approval,
  autonomous payments, SLIP-39, production relay, or external rollback anchor
- official-node fallback or migration
- Linux Pilot enablement or Tauri/GTK migration
- application identifiers, Android signer/package/version, Windows upgrade
  code, release filenames, signing secrets, or release configuration
- destructive Android actions including uninstall, app-data clear, or factory
  reset
- whole-workspace formatting or mass dependency updates

## Stage-control rule

After every stage, inspect scoped status and diffs, confirm staged count is
zero, and confirm the `releases/` deletion count remains 5,513.

## Verified evidence update (2026-08-01)

- Rotation candidate protocol and restricted backend path implemented.
- Replacement phone no longer requires prior normal pairing.
- Crash after durable baseline and before old-device revocation has a
  deterministic, idempotent recovery test.
- Agent Core Pilot: 132 passed, 0 failed.
- Agent Core non-pilot: 110 passed, 0 failed.
- Personal Wallet core: 399 passed, 0 failed.
- Fast Pay L2: 38 passed, 0 failed.
- Dust Whisper: 8 passed, 0 failed, 1 live-relay test ignored.
- ARM64 debug APK: 622,962,774 bytes; SHA-256
  `148EC6B7C8FAC20E041A6E75F18BC716A616D8179B7AB04F7B60852C97F7715B`.
- Android package/version/signer remain
  `org.hacash.wallet.mobile` / `1.0.2` / Android Debug.
- Physical Android: not detected.
- Live local node preflight: endpoint reported `hacash-fullnode 1.0.10` and a
  valid capability contract, but also `mainnet=true`; the testnet Pilot
  stopped fail closed.
- Separate testnet node/data directory, biometric, Keystore, same-LAN, funded
  transaction, and two-phone rotation: not executed.
- Staged entries remain zero and the 5,513 `releases/` deletions remain
  unchanged.

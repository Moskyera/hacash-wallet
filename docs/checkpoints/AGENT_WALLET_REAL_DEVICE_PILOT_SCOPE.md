# HPAY Agent Wallet Real-Device Pilot Scope

Status: frozen change boundary for witness lifecycle completion and controlled
Windows plus Android testnet verification. This manifest does not claim
ownership of the repository's pre-existing dirty worktree.

## Initial checkpoint (2026-08-01)

- Branch: `codex/how-it-works-hacd-fidelity`
- Head: `26ae4c5`
- Modified entries: 201
- Deleted entries: 5,513
- Untracked entries: 152
- Staged entries: 0
- Existing deleted entries under `releases/`: 5,513
- Existing Android ARM64 debug APK SHA-256:
  `6AD924F3135080705804CC08942C2EF449784902C8A19C95C495FCF4F36452EE`

No reset, restore, clean, mass staging, commit, push, tag, or release is
authorized by this task.

## A. Files allowed to change

Only the following source and documentation areas may change when required by
the reviewed witness-lifecycle invariants:

- `crates/agent-wallet-core/`
- `crates/companion-protocol/`
- `crates/agent-wallet-runtime/`
- `crates/agent-connector/`
- `crates/companion-lan-runtime/`
- Agent Wallet-only modules under `crates/wallet-tauri-common/`
- `apps/desktop/src/agent/`
- `apps/mobile/src/agent/`
- `apps/mobile/src-tauri/src/agent_companion/`
- `apps/mobile/src-tauri/src/agent_companion_identity.rs`
- narrowly scoped Agent Wallet command, handler, permission, and feature
  registration points in the desktop and mobile shells
- `docs/agent-wallet/TESTNET_PILOT_ARCHITECTURE.md`
- `docs/agent-wallet/ROLLBACK_WITNESS_PROTOCOL.md`
- `docs/agent-wallet/TESTNET_PILOT_LIMITATIONS.md`
- `docs/agent-wallet/TESTNET_PILOT_RUNBOOK.md`
- `docs/agent-wallet/WITNESS_ROTATION_PROTOCOL.md`
- `docs/agent-wallet/POST_SUBMIT_WITNESS_PROTOCOL.md`
- `docs/agent-wallet/DIAGNOSTIC_EXPORT.md`
- `docs/agent-wallet/REAL_DEVICE_TEST_REPORT.md`
- `docs/agent-wallet/pilot-results/`
- this scope manifest

## B. Existing pilot files read-only unless required

Existing Pilot code remains read-only unless a concrete rotation,
post-submit-anchor, diagnostic-export, cross-target build, or adversarial-test
invariant requires a change. Existing V3 network binding, zero wallet fee,
pending-witness recovery, Android identity, Personal Wallet isolation, and
custom-node pinning must be preserved.

## C. Dependency lockfiles allowed for exact security update

`Cargo.lock` may change only for the exact `event-listener 5.4.1` to `5.4.2`
security update, its checksum, and strictly necessary transitive lock entries
introduced by that exact package version. A general dependency update is not
allowed. Any unrelated churn must be rejected without reverting pre-existing
lockfile changes.

The existing untracked desktop/mobile `pnpm-lock.yaml` and
`pnpm-workspace.yaml` files may be used only to satisfy the explicit build
gates: PostCSS 8.5.25 and the `esbuild` allow-build entry. No other lifecycle
script or JavaScript dependency update is allowed.

## D. Generated build artifacts

The following may be regenerated as build evidence but are not source changes
and must never be staged:

- `target/`
- application `dist/` directories
- `apps/mobile/src-tauri/gen/android/**/build/`
- Android JNI libraries and debug APK outputs
- generated Tauri schemas and Android sources

Generated artifacts may be inspected for package identity, signing identity,
bundled frontend, ABI, size, and SHA-256. They must not be published or called
release artifacts.

## E. Pre-existing unrelated modifications

All dirty paths outside sections A through D are user-owned or belong to prior
work. They must not be reformatted, reverted, staged, or rewritten. Whole-
workspace formatting failures from unrelated fullnode, pool, branding,
Personal Wallet, update, or release work are recorded separately.

## F. Existing `releases/` deletions

The 5,513 deleted tracked entries under `releases/` are pre-existing. This task
must not restore, delete further, rewrite, stage, or otherwise alter them.

## G. Paths that must remain untouched

- Personal Wallet vault, private keys, addresses, signing, send, backup,
  settings, updater, DUST, and L2 behavior
- HPAY custom L2 extensions and Official ChannelPay boundaries
- pinned custom fullnode source, revision, binary, adapter, and configuration
- official-fullnode migration or fallback behavior
- application and Android package identities
- Android and Windows release signing configuration
- Windows updater and release filenames
- Linux GUI dependency migration
- SLIP-39 implementation or recovery shares
- Agent Wallet mainnet, HIP-20 send, autonomous approval, Agent L2, public LAN
  APIs, internet relays, telemetry, and cloud upload

## Stage-control rule

After each implementation stage:

1. inspect only scoped status and diffs;
2. verify staged count remains zero;
3. verify the 5,513 `releases/` deletions remain unchanged;
4. format only packages/files in section A;
5. treat generated outputs as evidence, never source;
6. stop before any change outside this manifest.

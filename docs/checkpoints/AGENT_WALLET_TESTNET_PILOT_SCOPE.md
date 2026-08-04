# HPAY Agent Wallet Testnet Pilot Scope

This manifest freezes the allowed change surface for the testnet-pilot and
mobile rollback-witness task. It does not assign ownership of the repository's
pre-existing dirty worktree.

## Initial worktree checkpoint

- Branch: `codex/how-it-works-hacd-fidelity`
- Total status entries: 8,884
- Modified: 201
- Deleted: 5,513
- Untracked: 3,170
- Staged: 0
- Existing `releases/` deletions: 5,513
- Generated/build entries detected by path classification: 9

The existing `releases/` deletions and unrelated changes are preserved exactly
as found. No reset, restore, clean, mass staging, commit, push, tag, or release
is allowed by this task.

## A. Files owned by this pilot task

Production and test files may be added or changed only under these paths when
required by a reviewed pilot invariant:

- `crates/agent-wallet-core/`
- `crates/agent-wallet-runtime/`
- `crates/agent-connector/`
- `crates/agent-types/`
- `crates/companion-protocol/`
- `crates/companion-lan-runtime/`
- `crates/wallet-tauri-common/src/agent_commands.rs`
- `crates/wallet-tauri-common/src/agent_runtime.rs`
- `crates/wallet-tauri-common/src/companion_backend.rs`
- `crates/wallet-tauri-common/src/companion_runtime.rs`
- `crates/wallet-tauri-common/tests/agent_feature_boundary.rs`
- `apps/desktop/src/agent/`
- `apps/mobile/src/agent/`
- `apps/mobile/src-tauri/src/agent_companion/`
- `apps/mobile/src-tauri/src/agent_companion_identity.rs`
- narrowly scoped Agent Wallet registration points in app/Tauri manifests
- the pilot documentation listed in section 34 of the task

Any required change outside this list must stop for an explicit scope review
before implementation.

## B. Existing Agent Wallet implementation files

The Agent Wallet, connector, companion protocol, LAN runtime, and their Tauri
adapters were already present as modified or untracked work when this task
started. They are not assumed to have been created by this pilot task. Their
pre-task behavior must be audited before modification.

The Personal Wallet remains a separate security domain. Its vault, signing,
send, backup, settings, update, L2, DUST, and release behavior are out of scope.

## C. Pre-existing unrelated changes

All dirty files outside section A are treated as user-owned or from earlier
work. In particular this includes branding, icons, Personal Wallet screens,
general update code, release infrastructure, `.audit/`, and unrelated
documentation. They must not be reformatted, reverted, staged, or rewritten.

The existing PostCSS/Vite lockfile security changes predate this pilot task and
remain outside the rollback-witness implementation scope.

## D. Generated and build outputs

The following are evidence or build products, never source-of-truth edits:

- `target/`
- app `dist/` directories
- `node_modules/`
- `apps/mobile/src-tauri/gen/android/**/build/`
- Android APK outputs
- generated Tauri schemas
- generated Android assets and native libraries

Build tools may regenerate these during validation. They must not be manually
edited and must not be staged by this task.

## E. Existing `releases/` deletions

The initial checkpoint contains 5,513 deleted tracked entries under
`releases/`, plus other pre-existing release-area status entries. This task
must not restore, delete further, rewrite, stage, or otherwise alter any of
them.

## F. Files that must remain untouched

- Personal Wallet vault and private-key code except read-only audit
- Personal Wallet transaction behavior
- existing L2 Fast Pay and HPAY custom L2 extensions
- pinned fullnode source, revision, binary, adapter, and configuration
- `releases/`
- application identifiers and platform package identities
- Windows upgrade code
- Android signer and release signing configuration
- release filenames and version `1.0.2`

## Stage-control rule

Before and after every implementation stage:

1. inspect only the scoped status/diff;
2. compare changed paths with section A;
3. stop if an unrelated or uncertain file is required;
4. run package-scoped formatting and tests only;
5. record generated output separately from source changes.
## G. Verified documentation checkpoint (2026-08-01)

This checkpoint update is documentation-only. It does not claim a build,
real-device run, live-node run, release, or production readiness.

The following Pilot documents now record the inspected architecture and
evidence boundaries:

- `docs/agent-wallet/TESTNET_PILOT_ARCHITECTURE.md`
- `docs/agent-wallet/ROLLBACK_WITNESS_PROTOCOL.md`
- `docs/agent-wallet/TESTNET_PILOT_RUNBOOK.md`
- `docs/agent-wallet/TESTNET_PILOT_LIMITATIONS.md`
- `docs/agent-wallet/TESTNET_PILOT_RESULTS_TEMPLATE.md`
- `docs/fullnode/OFFICIAL_EAE78AFB_COMPATIBILITY.md`

Verified implementation facts recorded by those documents:

- the Pilot deployment is Windows desktop plus Android companion;
- the Pilot feature is compile-time blocked on non-Windows desktop while the
  Linux `glib 0.18.5` blocker remains unresolved;
- unsupported mobile targets do not become Agent Wallet companions;
- the Android companion is an approval and external rollback witness and does
  not receive the Agent Wallet blockchain private key;
- Agent Wallet wallet fee is fixed at zero; only the Hacash network fee is
  included in a payment;
- real Agent payments are testnet-only, Type 2, action kind 1, manually
  approved, policy-limited, and bound to an exact recipient, amount, fee,
  transaction commitment, network identity, and expiry;
- `/query/capabilities` must report `hacash-fullnode` version `1.0.10`, a
  non-mainnet chain, enabled transaction type 2, and enabled action kind 1;
- missing, malformed, legacy-derived, unsupported-version, wrong-network, or
  incomplete capability responses fail closed;
- existing HPAY L2 extensions are preserved and remain outside this Pilot;
- autonomous payments, mainnet, HIP-20 payments, HVM/contract operations, and
  arbitrary signing remain outside this Pilot;
- SLIP-39 is not implemented or enabled and is documented only as a future
  security/recovery evaluation.

Recorded automated evidence:

- 2026-07-30: Agent Wallet Pilot suite, 123 passed and 0 failed;
- 2026-07-30: focused rollback-witness suite, 7 passed and 0 failed;
- 2026-07-30: strict Agent Wallet feature Clippy, passed;
- 2026-08-01: custom full-node capability suite, 4 passed and 0 failed, with
  two unrelated benchmark dead-code warnings.

The full-node compatibility report distinguishes the locally inspected custom
node from the requested official revision:

- custom source inspected at
  `ec26c006dc981003a139a7294f541947836fd34c`, branch
  `feat/pool-directory-cuda-ptx-panel`, reported version `1.0.10`;
- the official object `eae78afb` was not present in the local object database;
- therefore no official-node compatibility row is marked verified and that
  revision remains disabled as an Agent Wallet backend.

Evidence still not verified:

- Windows desktop Pilot build and runtime;
- Android Pilot build on a physical device;
- same-LAN pairing and the Windows Named Pipe path on real hardware;
- hardware-backed, non-exportable, per-use Android identity behavior;
- biometric denial/cancellation and process-restart behavior;
- exact signed-receipt retry after a lost acknowledgement on Android;
- live custom-node capability, balance, submit, and transaction-query calls;
- recovery from all interruption points on real devices;
- controlled replacement/rotation of an initialized Android witness;
- an independently witnessed final post-submit/commit anchor;
- detection of simultaneous rollback of both desktop and Android to the same
  older mutually consistent checkpoint;
- a redacted diagnostic export suitable for operators.

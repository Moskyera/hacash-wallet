# HPAY Agent Wallet Physical Testnet Pilot Scope

Date: 2026-08-02

Branch: `codex/how-it-works-hacd-fidelity`

Starting HEAD: `26ae4c5`

Starting worktree: 201 modified, 155 untracked, 5,513 deleted, 0 staged.
All 5,513 pre-existing `releases/` deletions are outside this scope and must
remain untouched.

## A. Allowed pilot configuration files

- `scripts/agent-testnet/node.ini.template`

The rendered configuration, marker, PID, logs, identity record, block database,
state database, and peer database must live under the user-scoped runtime root,
outside every Git repository.

## B. Allowed node launcher/profile files

- `scripts/start-agent-testnet-node.ps1`
- `C:/Users/KQHEX/Documents/hacash-fullnodedev/app/src/node_api.rs`

The fullnode source change is limited to reporting the transaction API routes
that the same binary actually registers. No consensus, P2P, pool, miner, HVM,
Harbor, or L2 behavior is in scope.

## C. Allowed Agent Wallet test files

- `crates/agent-wallet-core/src/node_binding.rs`
- `crates/wallet-core/src/node_capabilities.rs`

Only the Pilot node contract, exact testnet chain binding, profile commitment,
and focused negative tests are allowed. Personal Wallet transaction behavior is
not in scope.

## D. Allowed Android test-support files

None were needed. No mobile source changed, because no physical Android device
or ADB executable was available.

## E. Allowed documentation files

- this file;
- `docs/agent-wallet/ISOLATED_TESTNET_NODE.md`;
- `docs/agent-wallet/PHYSICAL_ANDROID_PILOT.md`;
- `docs/agent-wallet/LIVE_TESTNET_TRANSACTION_REPORT.md`;
- `docs/agent-wallet/REAL_DEVICE_TEST_REPORT.md`;
- `docs/agent-wallet/TESTNET_PILOT_RUNBOOK.md`;
- `docs/agent-wallet/TESTNET_PILOT_LIMITATIONS.md`;
- `docs/agent-wallet/ROTATION_CANDIDATE_PAIRING.md`;
- `docs/agent-wallet/WITNESS_ROTATION_PROTOCOL.md`;
- `docs/agent-wallet/POST_SUBMIT_WITNESS_PROTOCOL.md`;
- one redacted record under `docs/agent-wallet/pilot-results/`.

## F. Generated artifacts

Allowed only outside Git:

- `%LOCALAPPDATA%/HPAY/agent-testnet-v3/data/`;
- `%LOCALAPPDATA%/HPAY/agent-testnet-v3/runtime/node.ini`;
- testnet marker, PID, logs, and redacted runtime identity in that runtime
  directory;
- normal Rust and frontend build output in already ignored build directories.

No generated node database or runtime log may be added to the repository.

## G. Existing unrelated modifications

The dirty checkpoint predates this pilot. Existing unrelated product, UI,
Android, desktop, L2, wallet, and documentation changes are preserved and are
not reformatted or reverted.

## H. Existing releases deletions

The 5,513 deleted paths under `releases/` are pre-existing. This pilot does not
stage, restore, recreate, inspect for publication, or otherwise modify them.

## I. Strictly forbidden paths and actions

- any existing mainnet node configuration, database, state, peer data, log, or
  process;
- Personal Wallet vaults, keys, addresses, settings, and transaction paths;
- Harbor, pool, official ChannelPay, Fast Pay/L2, HIP-20 Agent send, and SLIP-39;
- Android app data deletion, uninstall, signer/package/version changes;
- mainnet or official-node fallback;
- mainnet funds, autonomous approval, generic signing, or a second broadcast;
- Git staging, commit, push, tag, release, or public artifact publication;
- whole-workspace formatting and mass dependency updates.

## Scoped implementation result

The isolated custom node is bound to the existing local-chain `chain_id=7`, a
new user-scoped data directory, ports 3099/8099, loopback-only HTTP API, and an
exact marker. Runtime capability verification passed at height 0. Because no
block one exists and no physical Android device was present, Agent signing,
funding, and transaction execution remain blocked.

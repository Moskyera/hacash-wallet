# Agent Wallet chain bootstrap scope

Date: 2026-08-02

This checkpoint is limited to a private Agent Wallet pilot chain and its fail-closed identity contract. It does not authorize a public artifact, mainnet Agent payments, or changes to Personal Wallet behavior.

## Allowed paths

- Node profile files: `scripts/agent-local-pilot/`.
- Node launchers: `scripts/start-agent-local-pilot-node.ps1` and `scripts/get-agent-local-pilot-status.ps1`.
- Local mining launcher: `scripts/start-agent-local-pilot-miner.ps1`.
- Agent network contract: `crates/wallet-core/src/node_capabilities.rs`, `crates/agent-wallet-core/src/node_binding.rs`, payment, diagnostics, companion witness and rotation modules.
- Companion wire validation: approval, witness and rotation records under `crates/companion-protocol/src/`.
- Frontend capability typing: `packages/wallet-ui/src/istanbul.ts`.
- Tests directly covering those contracts.
- Documentation under `docs/agent-wallet/` and this checkpoint file.
- Fullnode identity contract: `basis/src/config/engine.rs` and `app/src/node_api.rs` in the separate fullnode worktree.

## Generated runtime data

All chain databases, logs, PID files and rendered configuration live outside both repositories:

```text
%LOCALAPPDATA%\HPAY\agent-local-pilot-v1\data
%LOCALAPPDATA%\HPAY\agent-local-pilot-v1\runtime
```

The dedicated binaries are generated under the fullnode ignored build directory:

```text
hacash-fullnodedev\target\hpay-local-pilot\release
```

## Protected existing state

- The existing node on port 8099 and its `agent-testnet-v3` data remain untouched.
- Mainnet node processes, configuration, ports, peers, funds and data remain untouched.
- Existing unrelated wallet and fullnode worktree changes remain untouched.
- The 5,513 pre-existing `releases/` deletions remain untouched.

## Forbidden paths and actions

- Mainnet data directories and funds.
- Direct database balance or block mutation.
- Unverified snapshots or peers.
- LAN or internet exposure of the node API.
- Personal Wallet transaction behavior.
- HIP-20 Agent send, Agent L2, autonomous approval, SLIP-39 and production relay.
- Staging, commit, push, tag, release or public artifacts.

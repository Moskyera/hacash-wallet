# Isolated HPAY Agent Wallet Testnet Node

Status: live custom-node preflight verified; chain not transaction-ready.

## Identity and isolation

The Pilot uses the HPAY custom fullnode `1.0.10` built from
`C:/Users/KQHEX/Documents/hacash-fullnodedev`. It does not replace or migrate
the official fullnode and never opens an existing mainnet database.

| Property | Pilot value |
|---|---|
| Profile | `hpay-custom-1.0.10-testnet` |
| Agent network id | `testnet` |
| Approval contract | V3 |
| Fullnode chain id | `7` |
| Mainnet | `false` |
| Data root | `%LOCALAPPDATA%/HPAY/agent-testnet-v3/data` |
| Runtime root | `%LOCALAPPDATA%/HPAY/agent-testnet-v3/runtime` |
| P2P port | `3099`, peer discovery and inbound peers disabled |
| HTTP API | `http://127.0.0.1:8099` |
| Mining | disabled by the guarded profile |
| Fallback | none |

`testnet V3` is the Pilot approval/network-binding profile. The fullnode does
not expose a separate textual V3 network identifier. Runtime identity is the
combination of `network_id=testnet`, exact `chain_id=7`, `mainnet=false`, exact
block-one hash, node profile commitment, transaction format 2, and approval
version 3. A user-editable label is never accepted as identity evidence.

## Safe launcher

Run a non-writing guard first:

~~~powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\start-agent-testnet-node.ps1 -ValidateOnly
~~~

Start only after it passes:

~~~powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\start-agent-testnet-node.ps1
~~~

The launcher rejects repository-local data, mainnet-like or reparse-point
paths, nested data/runtime paths, mismatched markers, occupied ports, live
duplicate PIDs, wrong node/version/chain, missing Type 2/action 1, and an
incomplete transaction API contract. It never deletes,
copies, migrates, or resynchronizes data and stops only the process it created
when runtime verification fails.

## Capability contract

The custom node reports these registered APIs:

- balance query;
- transaction submission;
- transaction query;
- reconciliation by exact transaction hash.

The Agent Wallet Pilot requires all four. Missing fields safely default to
false. It also requires reported capabilities from `hacash-fullnode 1.0.10`,
API version 1, chain 7, `mainnet=false`, Type 2, and action kind 1. These fields
are committed into the node profile used by V3 approvals.

## Current runtime result

On 2026-08-02 the isolated node started on the expected ports and reported all
required contract fields. Height was 0. The API does not report a peer count;
peer discovery and inbound peers are disabled by configuration. There was no
block one. Consequently:

- synchronization/readiness: not achieved;
- canonical block-one fingerprint: unavailable;
- balance/submission/query lifecycle: not executed;
- transaction-ready: no;
- Agent Wallet writes: blocked.

The profile intentionally does not mine or manufacture test funds. A later
controlled operator session must provide a testnet-only reward/funding plan,
produce a real block one, pin its lowercase hash, and repeat all preflight gates.

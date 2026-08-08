# Full-node compatibility for the Agent Wallet Testnet Pilot

Status: source and targeted-test assessment, 2026-08-01  
Scope: HPAY Agent Wallet Testnet Pilot only

## Decision

The official full-node revision identified as `eae78afb` is not a drop-in backend for the Agent Wallet Testnet Pilot on the evidence currently available. That object is not present in the local full-node repository, so its source and behavior were not inspected or tested here. It must remain disabled as an Agent Wallet backend until the exact revision is obtained and the strict contract below is verified.

The locally available custom full node is a different target:

- repository: `C:\Users\KQHEX\Documents\hacash-fullnodedev`
- branch: `feat/pool-directory-cuda-ptx-panel`
- commit: `ec26c006dc981003a139a7294f541947836fd34c`
- reported application version: `1.0.10`
- reported build time: `2026/7/10 #1`

This report does not migrate, modify, or certify either node. Source presence is not live-node proof.

## Evidence labels

Every compatibility result uses exactly one of these labels:

- **Verified by source inspection**: the implementation and route were inspected, but no live/local node call was executed.
- **Verified by test**: a targeted automated test exercised the contract.
- **Verified by live/local node**: an actual node process answered the relevant request successfully.
- **Not verified**: the available evidence is insufficient.
- **Unsupported**: the inspected target explicitly does not provide the capability as defined.

No row in this report is classified as **Verified by live/local node**.

## Compatibility matrix

| Capability | Required by current Agent Pilot | Custom full node `ec26c006` | Evidence | Official `eae78afb` | Evidence |
| --- | --- | --- | --- | --- | --- |
| Balance query | Yes | **Verified by source inspection** | `/query/balance` is registered and reads address balances from node state. | **Not verified** | The exact source object is unavailable locally; no live call was made. |
| HACD metadata | No, not in the Agent HAC send path | **Verified by source inspection** | `/query/diamond` returns the diamond name, inscriptions, inscription items, life gene, and visual gene. | **Not verified** | The exact source object is unavailable locally; no live call was made. |
| Block query | Yes, for the block-one network anchor | **Verified by source inspection** | `/query/block/intro` accepts a height and returns the stored block hash and height. | **Not verified** | The exact source object is unavailable locally; no live call was made. |
| Channel query | No, L2 is excluded from this Pilot | **Verified by source inspection** | `/query/channel` is registered and reads channel state by channel id. | **Not verified** | The exact source object is unavailable locally; no live call was made. |
| Transaction submission | Yes | **Verified by source inspection** | `/submit/transaction` parses the submitted transaction package and delegates to node submission. | **Not verified** | The exact source object is unavailable locally; no live call was made. |
| Transaction status/query | Required for a complete operational reconciliation contract | **Verified by source inspection** | `/query/transaction` is registered and looks up a transaction by hash. The current Pilot still requires operator-controlled exact-hash reconciliation after an ambiguous submit. | **Not verified** | The exact source object is unavailable locally; no live call was made. |
| `/query/capabilities` | Yes, no legacy downgrade | **Verified by test** | `cargo test -p app node_capabilities_tests` passed 4 tests on 2026-08-01. The route reports API version, node/network identity, enabled transaction types and action kinds, features, and limits. | **Not verified** | The exact source object is unavailable locally; endpoint existence must not be assumed. |
| Generic action decoder | Yes, at minimum for enabled action kind 1 | **Verified by source inspection** | `/create/transaction` passes each JSON action through the generic action decoder and returns structured action-decode failures. | **Not verified** | The exact source object is unavailable locally; no test or source inspection was possible. |
| HIP-20 kind 17 builder | No while HIP-20 is disabled | **Unsupported** | Action kind 17 exists as a primitive and may be handled through generic action decoding, but the capability document explicitly reports `features.hip20: false`; there is no enabled, dedicated HIP-20 builder contract for the Pilot. | **Not verified** | The exact source object is unavailable locally; no capability response or builder test exists in this assessment. |
| HPAY L2 extensions | No, L2 is excluded from this Pilot | **Unsupported** | These extensions belong to the separately evolved HPAY L2/hub protocol, not to the inspected full-node HTTP contract. This result does not remove or downgrade the existing HPAY L2 work. | **Not verified** | The exact source object is unavailable locally; no L2 compatibility test was run. |

## Strict Agent Wallet node contract

The Pilot accepts a node only when all of the following are true:

1. `/query/capabilities` returns a valid reported capability document. A missing, malformed, unsupported-version, or legacy-derived response is rejected.
2. `source` is `reported`.
3. node name is `hacash-fullnode` and version is exactly `1.0.10`.
4. the chain is testnet, its chain id is non-zero, and block 1 matches the wallet's stored testnet fingerprint.
5. transaction type 2 is enabled.
6. action kind 1 is enabled.
7. the balance query succeeds for the Agent Wallet address before constructing a payment.
8. HPAY constructs and validates the Type 2 transaction locally. The agent cannot supply raw transaction bytes, actions, destinations, or fees.
9. the exact signed transaction hash is persisted before submission.
10. an absent or ambiguous submission result does not become success; exact-hash reconciliation is required.

The node-profile commitment currently binds capability API version, node name/version, chain id/mainnet flag, enabled transaction types, and enabled action kinds. Feature booleans and limits are validated only where the Pilot explicitly requires them; they are not all independently committed. This limitation must be considered before expanding the Pilot to HIP-20, HVM, account abstraction, Intent, or other Istanbul functionality.

## Istanbul capability interpretation

The custom node's capability route contains explicit fields for ActionGuard, TxBlob, AST, TEX, native assets, HIP-20 primitives, HIP-20, HVM, P2SH, account abstraction, Intent, contract state leasing, IR decompilation, ReqSignList, Type 4 mainnet, and exact unsigned simulation.

Presence of a JSON field is not proof that a feature is enabled or operational. The response derives most values from the active protocol setup; `hip20`, `ir_decompilation`, and `exact_unsigned_simulation` are explicitly reported as false in the inspected implementation. A wallet feature must stay disabled unless its required capability is true and its concrete builder, decoder, signing, submission, query, and recovery paths have their own tests.

## Required work before enabling the official node

1. Obtain and pin the exact `eae78afb` source object or a cryptographically identified replacement.
2. Inspect the nine compatibility areas above and record exact route/response contracts.
3. Run the capability contract tests against that exact source.
4. Start a disposable testnet node from that revision and verify block 1, capabilities, balance, Type 2/action 1 construction, submission, and transaction lookup.
5. Test all fail-closed cases: missing route, malformed JSON, unsupported API version, wrong node name/version, mainnet, wrong chain id, wrong block 1, missing Type 2, missing action 1, and missing transaction after an ambiguous submit.
6. Record hashes, logs, and redacted results using the Testnet Pilot results template.

Until all mandatory rows are verified against the exact official revision, HPAY must show the node as incompatible for Agent Wallet payments. Personal Wallet node behavior is outside this report and must not be changed by this decision.

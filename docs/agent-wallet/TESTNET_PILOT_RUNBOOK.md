# HPAY Agent Wallet Testnet Pilot Runbook

Status: operator checklist for a controlled Windows plus Android testnet exercise. It is not a release or mainnet procedure.

## Stop conditions

Stop immediately if any of the following is true:

- the desktop is not Windows;
- the companion is not a supported Android device;
- the custom fullnode does not report hacash-fullnode 1.0.10;
- the capability endpoint is missing, malformed, unsupported, or reports mainnet;
- block one differs from the wallet's pinned testnet fingerprint;
- transaction type 2 or action kind 1 is not enabled;
- the phone cannot provide a hardware-backed, non-exportable, per-use protected identity;
- the Android companion state reports invalid durable state or controlled rotation required;
- a previous operation is BroadcastUncertain or RecoveryRequired;
- the operator cannot afford to abandon all testnet funds in the Agent Wallet.

Do not switch nodes, reset the phone, recreate witness state, or rebroadcast to bypass a stop condition.

## Scope

Allowed:

- one Windows desktop Pilot build;
- one Android companion;
- custom fullnode 1.0.10 on testnet;
- HAC Type 2 payment using action kind 1;
- explicit human approval;
- network fee only, with wallet fee equal to zero;
- small testnet amounts.

Not allowed:

- mainnet;
- autonomous payments;
- L2/Fast Pay;
- HIP-20;
- Linux or iOS Pilot;
- node fallback/discovery;
- release publication;
- Personal Wallet changes.

## 1. Record source and environment

Record before building:

- HPAY repository commit and dirty-state summary;
- custom fullnode repository commit and dirty-state summary;
- fullnode version/build time;
- Windows version and machine id alias;
- Android model, OS/API level, security-patch date, and hardware-backed identity status;
- network topology and firewall configuration;
- testnet chain id and block-one fingerprint;
- the date, operator, and evidence directory.

Do not place passwords, pairing codes, private keys, session keys, raw vaults, or Android Keystore material in evidence.

## 2. Automated gates

Run from the HPAY repository:

~~~text
cargo test -p agent-wallet-core --features agent-wallet-testnet-pilot
cargo clippy -p agent-wallet-core --features agent-wallet-testnet-pilot --all-targets -- -D warnings
~~~

Verified baseline on 2026-08-01:

- Agent Wallet Pilot tests: 132 passed, 0 failed.
- Agent Wallet non-pilot tests: 110 passed, 0 failed.
- Focused restart-after-durable-baseline test: 1 passed, 0 failed.
- Strict feature Clippy: passed.

Run from the custom fullnode repository:

~~~text
cargo test -p app node_capabilities_tests
~~~

Verified baseline on 2026-08-01:

- capability tests: 4 passed, 0 failed;
- two unrelated dead-code warnings were emitted by benchmark constants.

A new run must record its own output. Do not reuse the baseline as current build evidence.

## 3. Build gates

Windows desktop must be built with the agent-wallet-testnet-pilot feature. The source contains a compile-time rejection for Pilot builds on non-Windows desktop targets.

Android must be built with the same Pilot protocol feature and the generated native identity implementation must match the checked source contract.

Required build evidence:

- exact command;
- exit code;
- artifact path, size, and SHA-256;
- compiler and Rust versions;
- Android Gradle/JDK/NDK versions;
- feature list;
- confirmation that no release signing secret was printed.

Build status for the 2026-08-01 checkpoint: Windows pilot/non-pilot native builds and Android ARM64 debug packaging passed. See [REAL_DEVICE_TEST_REPORT.md](REAL_DEVICE_TEST_REPORT.md). This does not count as runtime device evidence.

## 4. Node preflight

Query the selected node and retain a redacted response.

Required contract:

| Check | Required result |
|---|---|
| Block one | Exact configured testnet fingerprint |
| Capability source | Reported by the node, not legacy fallback |
| API version | 1 |
| Node identity | hacash-fullnode |
| Node version | 1.0.10 |
| Chain | mainnet false, nonzero chain id |
| Transactions | Type 2 enabled |
| Actions | Kind 1 enabled |
| HIP-20 | Disabled for this Pilot |
| Submit path | Available and verified in the controlled node deployment |
| Status/query | Operator must have an exact tx-hash reconciliation method |

The wallet computes a node profile from node identity, chain, enabled transaction types, and enabled action kinds. Record the profile id shown by diagnostics if and when a safe diagnostic export exists.

Live node preflight status for this documentation checkpoint: not executed.

## 5. Create and pair

1. Create a new testnet Agent Wallet. Do not import a Personal Wallet key.
2. Confirm the Agent Wallet address differs from every Personal Wallet address.
3. Confirm payments start paused.
4. Pair exactly one Android companion using the typed pairing flow.
5. On Android, verify hardware-backed, non-exportable, per-use protected identity status.
6. Verify the desktop registry contains the expected Android device id and permissions.
7. Confirm the Android has no Agent Wallet blockchain key or generic signing surface.
8. Enable Agent Wallet payments locally only after all prior checks pass.

Do not reset companion state after approval or witness initialization. Use only the controlled procedure in [WITNESS_ROTATION_PROTOCOL.md](WITNESS_ROTATION_PROTOCOL.md).

## 6. Low-value payment exercise

1. Create one HAC payment request to an explicitly allowed testnet recipient.
2. Verify the desktop shows amount, recipient, network fee, total debit, reason, expiry, and node binding.
3. Verify wallet fee is zero.
4. Approve on Android using biometric confirmation.
5. Record the approval operation id and approval sequence without recording secrets.
6. Verify desktop reaches SignedAwaitingWitness before any submit.
7. Verify Android receives a rollback-anchor proposal for the same operation and network binding.
8. Verify Android durably advances its witness state before returning a signed receipt.
9. Verify desktop reaches WitnessedAwaitingBroadcast.
10. Verify desktop persists BroadcastSubmitted before the first node request.
11. Record the exact local tx hash and node response.
12. Complete the `Submitted` post-submit witness. Keep the reservation held.
13. Reconcile the exact tx hash externally.
14. Complete the `ReconciledFinal` witness before marking the operation terminal and releasing the reservation.

Expected submit count: one.

## 7. Required failure exercises

Execute only with disposable testnet state.

| Case | Expected result |
|---|---|
| Missing capability endpoint | Signing disabled, no fallback |
| Malformed capability response | Signing disabled |
| API version other than 1 | Signing disabled |
| Node version other than 1.0.10 | Signing disabled |
| Wrong block one or mainnet response | Signing disabled |
| Missing Type 2 | Signing disabled |
| Missing action kind 1 | Signing disabled |
| Node profile changes after approval | Approval commitment mismatch |
| Expired pending anchor | RecoveryRequired, no silent replacement |
| Exact receipt retry from WitnessedAwaitingBroadcast | At most one submit |
| Lost witness acknowledgement after BroadcastSubmitted | Return known status, no second submit |
| Android durable-state corruption | Companion disabled |
| Desktop malformed/decreasing witness checkpoint | RecoveryRequired on load |
| Emergency stop during request | No new signing; ambiguous submit requires reconciliation |

Do not intentionally simulate simultaneous desktop and phone rollback on valuable state.

## 8. Restart and lost-response checks

Required but not yet real-device verified:

- restart desktop after durable SignedAwaitingWitness and recover the exact pending proposal;
- restart Android after durable pending approval and recover only the exact operation proposal;
- retry the exact witness after a lost acknowledgement;
- prove that Android Keystore retry uses a desktop-acceptable exact receipt identity without a second submit;
- restart in BroadcastSubmitted and BroadcastUncertain and prove no automatic rebroadcast;
- reconcile only the exact local hash and require the final witness before release.

If an expired proposal is reached, stop. For phone replacement, follow the controlled rotation protocol; do not improvise reset or re-pair actions.

## 9. Evidence classification

Every result must use one category:

- Automated verified
- Build verified
- Simulated integration verified
- Real-device verified
- Not yet verified

For every non-executed test record:

- command or procedure;
- reason not executed;
- unverified property;
- required environment/device.

Mock tests never count as real-device evidence.

## 10. Completion decision

The Pilot can be marked ready for a limited real-device test only when automated and build gates pass and all known blockers are accepted for disposable testnet use.

It cannot be marked mainnet ready until:

- real-device results are complete;
- controlled mobile-loss rotation has real two-phone evidence and external review;
- final anchors have live-transaction evidence and external review;
- redacted diagnostics have real-session evidence and operator recovery is complete;
- the official fullnode compatibility boundary is resolved;
- the simultaneous rollback risk has an accepted mitigation;
- an external security review approves the complete system.

Use [TESTNET_PILOT_RESULTS_TEMPLATE.md](TESTNET_PILOT_RESULTS_TEMPLATE.md) for the record.

## Isolated node profile added on 2026-08-02

The guarded profile is documented in
[ISOLATED_TESTNET_NODE.md](ISOLATED_TESTNET_NODE.md). Run its validation mode
before start. The Pilot contract now additionally requires chain 7 and the
reported balance-query, transaction-submit, transaction-query, and exact-hash
reconciliation fields. A missing field defaults to unavailable and blocks
signing. The first live start reached height 0 only; do not enter a block-one
fingerprint or create/fund an Agent Wallet until a real block one exists.

## Local Pilot Chain V1 commands

Validate without creating files or starting a process:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/start-agent-local-pilot-node.ps1 -ValidateOnly
```

Start the isolated node without mining:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/start-agent-local-pilot-node.ps1
```

Mining requires an explicit public reward address. After a user-created Agent Wallet exists, pass only its public address. Never pass its private key or passphrase.

Use `scripts/get-agent-local-pilot-status.ps1` to refresh and verify the runtime identity. A `transaction_ready: false` result is a hard stop, not a warning that can be bypassed.

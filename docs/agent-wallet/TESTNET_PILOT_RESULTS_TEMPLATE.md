# HPAY Agent Wallet Testnet Pilot Results Template

Use one copy per Pilot run. Never record private keys, passwords, pairing codes, session secrets, raw vaults, Keystore secrets, or unredacted LAN credentials.

## 1. Run identity

| Field | Value |
|---|---|
| Run id | TBD |
| Date/time/timezone | TBD |
| Operator | TBD |
| Reviewer | TBD |
| HPAY repository commit | TBD |
| HPAY worktree clean | Yes / No, attach scoped status |
| Custom fullnode commit | TBD |
| Fullnode branch | TBD |
| Fullnode version/build time | TBD |
| Official eae78afb source available | Yes / No |
| Evidence directory | TBD |
| Decision | PASS / FAIL / BLOCKED |

## 2. Environment

| Component | Evidence |
|---|---|
| Windows edition/build | TBD |
| CPU/architecture | TBD |
| Rust/cargo version | TBD |
| Node/package-manager version | TBD |
| Android model | TBD |
| Android OS/API | TBD |
| Android security patch | TBD |
| Keystore hardware-backed | Verified / Failed / Not run |
| Keystore protected per use | Verified / Failed / Not run |
| Same-LAN topology | TBD |
| Firewall rules | TBD |
| Testnet chain id | TBD |
| Block-one fingerprint | TBD |
| Testnet node URL alias | TBD, do not record credentials |
| Testnet Agent Wallet address | TBD, public |
| Testnet recipient | TBD, public |
| Test amount | TBD |

## 3. Evidence classification

Use only:

- Automated verified
- Build verified
- Simulated integration verified
- Real-device verified
- Not yet verified

Do not classify mock-node or source-contract tests as real-device evidence.

## 4. Automated checks

| Command | Result | Classification | Evidence file |
|---|---|---|---|
| cargo test -p agent-wallet-core --features agent-wallet-testnet-pilot | TBD | Automated verified / Failed | TBD |
| Focused rollback witness tests | TBD | Automated verified / Failed | TBD |
| cargo clippy -p agent-wallet-core --features agent-wallet-testnet-pilot --all-targets -- -D warnings | TBD | Automated verified / Failed | TBD |
| cargo test -p app node_capabilities_tests | TBD | Automated verified / Failed | TBD |
| Desktop tests/typecheck/build | TBD | TBD | TBD |
| Mobile tests/typecheck/build | TBD | TBD | TBD |
| Android contract tests | TBD | TBD | TBD |
| Dependency/security checks | TBD | TBD | TBD |
| PostCSS exact version 8.5.25 | TBD | TBD | TBD |

Known local automated baseline, not a substitute for this run:

| Date | Check | Result |
|---|---|---|
| 2026-07-30 | Agent Wallet Pilot suite | 123 passed, 0 failed |
| 2026-07-30 | Focused witness suite | 7 passed, 0 failed |
| 2026-07-30 | Agent Wallet strict Clippy | Passed |
| 2026-08-01 | Custom fullnode capability suite | 4 passed, 0 failed; two unrelated benchmark dead-code warnings |

## 5. Build artifacts

| Artifact | Feature set | Size | SHA-256 | Signature | Result |
|---|---|---:|---|---|---|
| Windows desktop Pilot | TBD | TBD | TBD | TBD | Not run |
| Android companion Pilot | TBD | TBD | TBD | TBD | Not run |

Linux Pilot must remain blocked. Do not enter a Linux Pilot artifact unless the compile gate is intentionally changed in a separately reviewed task.

## 6. Node contract

Attach a redacted /query/capabilities response and block-one result.

| Check | Expected | Observed | Evidence level | Result |
|---|---|---|---|---|
| Capability source | Reported | TBD | TBD | TBD |
| API version | 1 | TBD | TBD | TBD |
| Node name | hacash-fullnode | TBD | TBD | TBD |
| Node version | 1.0.10 | TBD | TBD | TBD |
| Mainnet | false | TBD | TBD | TBD |
| Chain id | nonzero | TBD | TBD | TBD |
| Block one | exact wallet fingerprint | TBD | TBD | TBD |
| Type 2 | enabled | TBD | TBD | TBD |
| Action 1 | enabled | TBD | TBD | TBD |
| HIP-20 | false/disabled for Pilot | TBD | TBD | TBD |
| Balance query | real response | TBD | TBD | TBD |
| Transaction creation | exact Type 2/action 1 body | TBD | TBD | TBD |
| Submission | one request | TBD | TBD | TBD |
| Tx status/query | exact-hash reconciliation | TBD | TBD | TBD |

Node profile id: TBD

## 7. Pairing and key boundary

| Check | Result | Evidence |
|---|---|---|
| Desktop and Android device ids match pairing transcript | TBD | TBD |
| Android registry role is Mobile | TBD | TBD |
| Required approval/witness permissions only | TBD | TBD |
| Android identity non-exportable | Not run | TBD |
| Android identity hardware-backed | Not run | TBD |
| Per-use biometric protection | Not run | TBD |
| Agent Wallet blockchain key absent from Android | Not run | TBD |
| Personal Wallet key never used | TBD | TBD |
| Raw session secrets absent from diagnostics | TBD | TBD |

## 8. Successful low-value flow

| Stage | Operation status | Durable evidence | Result |
|---|---|---|---|
| Intent created | TBD | TBD | TBD |
| Funds reserved | TBD | TBD | TBD |
| Approval requested | TBD | TBD | TBD |
| Android decision persisted | TBD | TBD | TBD |
| Desktop signed | SignedAwaitingWitness | TBD | TBD |
| Anchor proposed | SignedAwaitingWitness | TBD | TBD |
| Android high-water persisted | TBD | TBD | TBD |
| Receipt accepted | WitnessedAwaitingBroadcast | TBD | TBD |
| Pre-submit state persisted | BroadcastSubmitted | TBD | TBD |
| Node submit count | exactly 1 | TBD | TBD |
| Exact tx hash reconciled | TBD | TBD | TBD |
| Final operation | Committed / unresolved | TBD | TBD |

Amount: TBD  
Network fee: TBD  
Wallet fee: expected 0, observed TBD  
Total debit: TBD  
Transaction hash: TBD

## 9. Failure injection

| Scenario | Expected | Observed | Classification | Result |
|---|---|---|---|---|
| Capability endpoint missing | Signing blocked, no fallback | TBD | TBD | TBD |
| Malformed capability JSON | Signing blocked | TBD | TBD | TBD |
| Unsupported API version | Signing blocked | TBD | TBD | TBD |
| Node version mismatch | Signing blocked | TBD | TBD | TBD |
| Wrong network/block one | Signing blocked | TBD | TBD | TBD |
| Missing Type 2 | Signing blocked | TBD | TBD | TBD |
| Missing action 1 | Signing blocked | TBD | TBD | TBD |
| Node profile changed after approval | Commitment mismatch | TBD | TBD | TBD |
| Expired pending proposal | RecoveryRequired | TBD | TBD | TBD |
| Malformed desktop witness state | RecoveryRequired on load | TBD | TBD | TBD |
| Decreasing desktop checkpoint | RecoveryRequired on load | TBD | TBD | TBD |
| Lost approval response | Recover exact proposal only | TBD | TBD | TBD |
| Lost witness acknowledgement | Known status, no second submit | TBD | TBD | TBD |
| Restart at WitnessedAwaitingBroadcast | Exact receipt resumes once | TBD | TBD | TBD |
| Restart at BroadcastSubmitted | No automatic rebroadcast | TBD | TBD | TBD |
| Node error after submit | BroadcastUncertain | TBD | TBD | TBD |
| Emergency stop race | No new signing; reconcile ambiguous hash | TBD | TBD | TBD |
| Android durable-state corruption | Companion disabled | TBD | TBD | TBD |
| Phone loss after first witness | Controlled rotation required, currently blocked | TBD | TBD | TBD |

## 10. Real-device matrix

| Property | Status | Evidence |
|---|---|---|
| Windows Named Pipe runtime | Not yet verified | TBD |
| Android app on physical device | Not yet verified | TBD |
| Biometric prompt and cancellation | Not yet verified | TBD |
| Hardware-backed Keystore | Not yet verified | TBD |
| Same-LAN pairing/session/reconnect | Not yet verified | TBD |
| Real custom testnet fullnode | Not yet verified | TBD |
| Funded testnet transaction | Not yet verified | TBD |
| Power loss/process kill at durable boundaries | Not yet verified | TBD |
| Re-signed receipt after lost acknowledgement | Not yet verified | TBD |
| Phone-loss/replacement recovery | Not implemented | N/A |

Do not change Not yet verified to verified without attached real-device evidence.

## 11. Outstanding blockers

Mark each Open or Resolved with evidence:

- [ ] Linux glib 0.18.5 Pilot blocker
- [ ] Exact official eae78afb source/contract verification
- [ ] Redacted diagnostic export
- [ ] Final post-submit/commit anchor
- [ ] Controlled Android witness rotation after phone loss
- [ ] Expired-anchor operator recovery
- [ ] BroadcastUncertain operator UI/runbook exercised
- [ ] Simultaneous desktop/mobile rollback mitigation
- [ ] Android exact signed-receipt retry evidence
- [ ] Full real-device matrix
- [ ] External security audit
- [ ] Mainnet-specific design and approval
- [ ] SLIP-39 evaluation, if pursued; not an active feature

## 12. Non-executed test records

Repeat for each item:

| Field | Value |
|---|---|
| Command/procedure | TBD |
| Reason not executed | TBD |
| Unverified property | TBD |
| Required environment/device | TBD |
| Owner/next step | TBD |

## 13. Final assessment

Automated verified: TBD

Build verified: TBD

Simulated integration verified: TBD

Real-device verified: TBD

Not yet verified: TBD

Decision rationale: TBD

Reviewer sign-off: TBD
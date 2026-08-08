# HPAY Pilot Result: Witness Lifecycle Automated Hardening

- Evidence category: `AUTOMATED`
- Pilot session id: `HPAY-AUTOMATED-20260801-WITNESS-LIFECYCLE-01`
- Source checkpoint: `26ae4c5` plus an unstaged dirty worktree
- Application version: `1.0.2`
- Desktop platform: Windows build verified
- Mobile artifact SHA-256: `8D87D7732FE196A1C0B0FB419D592CAE246D0AD0A961AFC190920043A69380D2`
- Network identity: not verified live
- Custom node identity: required `hacash-fullnode 1.0.10`, not verified live
- Capability contract: version 1 required, automated mock-node verified only
- Wallet/device/agent ids: not recorded; no real session was executed

## Automated scenarios

- canonical controlled rotation records and domain-separated signatures;
- normal replacement with old-phone authorization;
- lost-phone recovery blocked by unresolved financial state;
- lost-phone clean-state path with mock live node contract;
- old-device revocation and exact witness epoch increment;
- durable new-phone baseline before authority transfer;
- final rotation completion anchor;
- multiple sequential rotations with authenticated history;
- `SignedPreBroadcast`, `Submitted`, and `ReconciledFinal` witnesses;
- no second broadcast after lost response or offline phone;
- reservation release only after final witness;
- redacted diagnostic preview/export and secret-marker rejection;
- pilot and non-pilot IPC/ACL isolation;
- zero HPAY Agent Wallet fee and disabled mainnet/HIP-20/L2 paths.

All executed automated scenarios passed. No `PHYSICAL_ANDROID` or
`LIVE_TESTNET` session was run. There are no transaction ids, and no real
journal/anchor/witness before-or-after values to report.

## Verification matrix

- companion protocol: 94 passed;
- Agent Wallet core pilot: 128 passed;
- Agent Wallet core non-pilot: 110 passed;
- agent connector: 49 passed;
- agent runtime: 11 passed;
- private LAN runtime: 17 passed;
- common IPC/security: 65 passed in pilot and 65 passed in non-pilot;
- Personal Wallet core: 215 unit tests plus 184 integration/regression tests,
  all passed;
- Dust Whisper: 8 passed, 1 local live-relay test ignored because no relay was
  running;
- Fast Pay L2: 38 passed;
- mobile Rust: 30 passed in pilot and 30 passed in non-pilot;
- desktop UI: 23 passed;
- mobile UI: 130 passed;
- scoped rustfmt: 124 files passed;
- strict Clippy: pilot/non-pilot core, IPC, desktop, and mobile passed;
- Windows desktop native pilot/non-pilot builds passed;
- Android ARM64 Rust, Kotlin/Gradle packaging, and strict validator passed;
- desktop and mobile JavaScript audits: no known vulnerabilities;
- PostCSS: 8.5.25 on desktop and mobile.

`event-listener` was changed exactly from 5.4.1 to 5.4.2. Reconstructing only
the old package block from the final lockfile reproduces the recorded pre-update
SHA-256 `AE7AE7E8BE11A5FDEAE94A027B0B6948B14CC81AB9AE4A6D78514374FE63A82E`;
the final lockfile SHA-256 is
`7D5A9354A361F4913870C883149CE485C498C63D47194F85E9F247EE794C18CC`.
RustSec no longer reports the `event-listener` advisory. It reports 18 allowed
warnings, including the target-specific Linux GTK/glib warning documented
below.

## Known limitations

- replacement phone must already be paired before rotation preparation;
- old-phone local state may remain rotation-blocked after the desktop revokes
  it; clearing that phone requires a controlled operator procedure;
- lost-phone mode proves clean authenticated HPAY state plus live node binding,
  not absence of an unknown external transaction;
- simultaneous rollback of desktop and mobile to the same consistent snapshot
  remains outside the two-party protocol's detection ability;
- Linux Agent Wallet pilot remains disabled because of the target-specific
  `glib 0.18.5` RustSec warning;
- physical Keystore, biometric, LAN, reconnect, and real testnet evidence are
  pending.

Readiness: `Automated hardening complete; real-device pilot pending`.

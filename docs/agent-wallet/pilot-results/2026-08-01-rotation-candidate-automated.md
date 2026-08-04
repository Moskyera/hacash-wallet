# Rotation Candidate Automated Evidence

- Session ID: `2026-08-01-rotation-candidate-automated`
- Evidence category: `AUTOMATED`
- Application version: `1.0.2`
- Desktop build SHA-256:
  `5A011BB6FB08C51808B6EEA3119CD9D4D5B86BC9C4495286A971296CC36FB4B4`
- Mobile APK SHA-256:
  `148EC6B7C8FAC20E041A6E75F18BC716A616D8179B7AB04F7B60852C97F7715B`
- Network ID: `testnet` in automated mock-node tests
- Custom node identity: not part of this `AUTOMATED` session; see the separate
  live-node preflight evidence
- Capability contract: automated mock response only
- Wallet/device/agent IDs: test-generated and not retained
- Transaction ID: not executed
- Journal/anchor/witness sequences: test-generated and not retained
- Rotation ID: test-generated and not retained

## Executed

- Companion protocol, candidate ticket, acceptance, replay, expiry, binding,
  and substitution tests.
- Normal and lost-phone unpaired replacement.
- Restricted-candidate backend ACL tests.
- Restart before baseline and safe cancellation.
- Restart after durable baseline before old-device revocation.
- Final completion, registry admission, and old-device rejection.
- Agent Core Pilot: 132 passed.
- Agent Core non-pilot: 110 passed.
- Personal Wallet core: 399 passed.
- Fast Pay L2: 38 passed.
- Dust Whisper: 8 passed; 1 live-relay test ignored.
- ARM64 Rust compile, Gradle debug package, Android strict validation, ABI,
  package/version, and debug signer verification.

## Regression matrix

- Companion protocol with software test identity: 95 passed.
- Agent Core Pilot: 132 passed.
- Agent Core non-pilot: 110 passed.
- Connector: 49 passed.
- Agent runtime: 11 passed.
- Private-LAN runtime: 17 passed.
- Tauri IPC/security Pilot: 66 passed.
- Tauri IPC/security non-pilot: 51 passed.
- Mobile Rust Pilot: 30 passed.
- Mobile Rust non-pilot: 30 passed.
- Desktop UI: 23 passed.
- Mobile UI: 130 passed.
- Personal Wallet core: 399 passed.
- Fast Pay L2: 38 passed.
- Dust Whisper: 8 passed; 1 live-relay test ignored because no relay was
  running at `127.0.0.1:8787`.
- Strict workspace Clippy, Pilot and non-pilot: passed with
  `-D warnings`.
- Scoped Rust formatting: passed.
- Whole-workspace formatting: not clean because of pre-existing files,
  including the separate fullnode workspace; those files were not rewritten.
- Windows native desktop Pilot and non-pilot builds: passed.
- Mobile and desktop TypeScript tests/type-check/production builds: passed.
- Desktop and mobile JavaScript production audits: 0 vulnerabilities.
- RustSec: exit 0, no blocking vulnerability; 18 allowed warnings remain,
  including the known Linux GTK3/glib blocker and unmaintained
  `libsecp256k1`.

Principal rerun commands:

```text
cargo test -p hacash-wallet-core --quiet
cargo test -p l2-fast-pay-hub --quiet
cargo test -p dust-whisper --quiet
cargo test -p agent-wallet-core --features agent-wallet-testnet-pilot --quiet
cargo test -p agent-wallet-core --quiet
cargo clippy --workspace --all-targets --features agent-wallet-testnet-pilot -- -D warnings
cargo clippy --workspace --all-targets -- -D warnings
cargo audit
```

## Not executed

- `PHYSICAL_ANDROID`
- `LIVE_CUSTOM_NODE`
- `LIVE_TESTNET_TRANSACTION`
- `TWO_PHYSICAL_DEVICE_ROTATION`
- physical Keystore and biometric verification
- same-LAN physical pairing and reconnect

## Result and limitations

Automated rotation-candidate hardening passed. No physical device was visible
to ADB and no pilot-compatible testnet node or funded Agent Wallet was
available. The
simultaneous desktop/mobile rollback limitation and absence of an independent
third anchor remain mainnet blockers. HIP-20 Agent send, Agent L2, autonomous
payments, automatic approval, SLIP-39, Linux Pilot, iOS, and official-node
migration remain outside this checkpoint.

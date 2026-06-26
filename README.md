# Hacash Wallet

Modern, secure desktop wallet for Hacash with encrypted on-device keys, local signing, L1 payments, and L2 Fast Pay routing.

## Security model

| Layer | Technology |
|-------|------------|
| Vault encryption | Argon2id profile KDF + AES-256-GCM v2 (AAD-bound metadata) |
| Unlock speed | Balanced: m=32K,t=2 (~2× faster than legacy); Paranoid: m=128K,t=4 |
| Brute-force guard | Exponential unlock backoff (1s → 5min cap) |
| I/O | Atomic secure writes (0o600), in-memory vault cache, 12s balance cache |
| Key handling | Local sign only — private key never sent to node API |
| Memory | `zeroize` on decrypted secrets |
| Auto-lock | Configurable timeout (balanced 180s / paranoid 60s) |
| WebAuthn | YubiKey / Windows Hello — challenge, rpIdHash, ES256 signature verify |
| Native biometric | Windows Hello `UserConsentVerifier` — OS-bound 2FA (not spoofable from UI) |
| Hardware modes | Software · WebAuthn-gate (all signs) · Watch-only (Sparrow-style) |
| Memory lock | `mlock` / `VirtualLock` on passphrase during KDF |
| HIP-23 | Pre-sign checks for L1 sends + Type3 pattern validators (Advanced tab) |
| Air-gap QR | L1 coordinator/signer flow — unsigned QR → offline sign → broadcast |
| Privacy | Hide balances/addresses, screen blur, optional history, clipboard clear |

## Architecture

```
React UI (Tauri WebView)
    ↓ invoke
Rust Tauri shell
    ↓
hacash-wallet-core
  ├── vault (encrypted storage, import/backup/passphrase change)
  ├── account + protocol signing
  ├── quantum (PQC/hybrid keystore v3, Type 4 send)
  ├── node client (balance, build, submit)
  ├── payment router (L2 hub → L1 fallback)
  ├── channel (L1 open/close)
  ├── l2_hub (Hub API v1 client)
  ├── bills (L2 settlement proof backup)
  ├── history (local tx log)
  ├── hip23 (pre-sign validation)
  ├── webauthn (ceremony coordinator)
  └── settings (persisted preferences)
```

Quantum IPC lives in `apps/desktop/src-tauri/src/commands.rs` (additive; legacy commands stay in `lib.rs`).

## Development

### Prerequisites

- Rust stable
- Yarn
- [Tauri prerequisites](https://v2.tauri.app/start/prerequisites/) (Windows: WebView2, VS Build Tools)
- `hacash-fullnodedev` cloned as sibling: `../hacash-fullnodedev` (PQC branch required)

```bash
git clone --branch feature/pqc-phases-1-3 https://github.com/Moskyera/fullnodedev.git ../hacash-fullnodedev
```

### Run

```bash
cd apps/desktop
yarn install
yarn tauri dev
```

### Test core

```bash
cargo test -p hacash-wallet-core --lib
cargo test -p hacash-wallet-core audit_quantum_
```

### Security audit gates (enterprise-style)

```bash
cargo test -p hacash-wallet-core audit_ -- --test-threads=1
cargo test -p hacash-wallet-core prop_
```

### Stress gates (volume / lifecycle; Argon2-heavy, run serially)

```bash
cargo test -p hacash-wallet-core stress_ -- --test-threads=1
```

### Tier-0 elite adversarial gates (hardest tier; session-bound 2FA, mutation matrix, fuzz)

```bash
cargo test -p hacash-wallet-core tier0_ -- --test-threads=1
```

See `../hacash-wallet-integration/AUDIT.md` for threat model, STRIDE, requirements traceability, stress matrix, and tier-0 elite gates (35 + 256 proptest cases).

### Integration tests (separate repo, per maintainer guidance)

```bash
cd ../hacash-wallet-integration
cargo test
```

## Features (v0.4 — quantum)

- [x] PQC account (v6, ML-DSA) — create / import / export keystore v3
- [x] Hybrid account (v7, ML-DSA + secp256k1) — recommended for Type 4 txs
- [x] Keystore v3 modal — paste JSON, password verify on export
- [x] Type 4 on-chain send (auto-fee `40:244`) via local fullnode
- [x] Quantum tab UI — address badges (Legacy / PQC / Hybrid), node metrics
- [x] Settings persistence — `quantum_mode`, encrypted keystore JSON blob
- [x] Quantum unit + audit smoke tests; E2E in `hacash-wallet-integration`

Requires sibling `hacash-fullnodedev` with PQC/Hybrid support (Phases 1–3).

| Account kind | Version | Signing |
|--------------|---------|---------|
| PQC (`pqckey`) | v6 | ML-DSA only |
| Hybrid (`hybrid`) | v7 | ML-DSA + secp (Type 4) |

Funding: send legacy Type 1 HAC **to** the quantum address (not from Create). One active quantum account at a time; Create replaces the stored keystore — export backup before switching.

## Features (v0.3)

- [x] Create / import / unlock wallet
- [x] Encrypted backup export + passphrase change
- [x] L1 balance, send with HIP-23 preview
- [x] L2 hub config, health check, channel open/close
- [x] WebAuthn register + auth (ES256 when public key stored)
- [x] Security profiles (balanced / paranoid) persisted
- [x] Tx history, L2 bill list
- [x] HIP-23 Advanced pattern validator (universal, P2, P3)
- [x] Air-gapped QR L1 send (coordinator + offline signer)
- [x] Privacy controls (masking, screen privacy, history opt-out)
- [x] Watch-only, hardware signing modes, native Windows Hello
- [x] Audit + stress + tier-0 adversarial test suites
- [ ] Live L2 off-chain wire (requires public CSP hub)
- [ ] Mobile (shared `wallet-core`)

## Repository layout (jojoin model)

| Repo | Contents |
|------|----------|
| `Moskyera/hacash-wallet` | App + core + unit tests only |
| `hacash-wallet-integration` | E2E / integration tests |
| `hacash/doc` | Normative wallet/HIP docs (separate PR) |

Do not bulk docs or integration tests into `hacash/fullnodedev`.
# Hacash Wallet — Mobile (planned)

Mobile shares **`hacash-wallet-core`** with the desktop app. No duplicate wallet logic.

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    hacash-wallet-core                    │
│  vault · signing · payment · l2_hub · quantum · bills   │
└──────────────────────────┬──────────────────────────────┘
                           │
         ┌─────────────────┼─────────────────┐
         ▼                 ▼                 ▼
  apps/desktop/      apps/mobile/      (future CLI)
  Tauri + React      Tauri Mobile      hacash-wallet
```

Desktop already builds the core as a native library:

```toml
# apps/desktop/src-tauri/Cargo.toml
crate-type = ["lib", "cdylib", "staticlib"]
```

Mobile will link the same crate.

## Target platforms

| Phase | Platform | Stack |
|-------|----------|-------|
| 1 | Android | Tauri 2 Mobile + shared core |
| 2 | iOS | Tauri 2 Mobile + shared core |
| 3 | Optional | UniFFI / JNI if non-Tauri embed needed |

## Phase 1 checklist (not started)

- [ ] `tauri init` mobile targets under `apps/mobile/`
- [ ] Share `invoke` command surface from desktop `lib.rs` (or thin `wallet-mobile` crate)
- [ ] React Native or reuse React web UI with mobile layout
- [ ] Biometric unlock (platform APIs via Tauri plugins)
- [ ] Fast Pay tab parity (hub URL, bills export)
- [ ] App store signing pipelines

## What works today on desktop (reuse as-is)

| Module | Mobile-ready? |
|--------|---------------|
| `wallet-core` | Yes — pure Rust, no UI |
| `l2_hub` client | Yes — HTTP only |
| `l2_bill` export | Yes |
| Vault / KDF | Yes — platform secure storage TBD |
| WebAuthn | Partial — platform ceremonies differ |
| Air-gap QR | Yes — camera plugin on mobile |

## Dev prerequisites (when started)

- Rust stable + Android NDK / Xcode
- [Tauri mobile prerequisites](https://v2.tauri.app/start/prerequisites/)
- Sibling fullnode for integration tests (same as desktop)

## Suggested first milestone

**Read-only mobile wallet:**

1. Import vault, unlock, show balance
2. Tx history
3. No send (reduces signing surface for v1)

**Second milestone:** L1 send + Fast Pay (same `payment.rs` router).

## Directory layout (future)

```
apps/mobile/
├── README.md          ← this file
├── src-tauri/         ← Tauri mobile shell (to be created)
├── src/               ← React UI (shared components from desktop where possible)
└── package.json
```

## Related docs

- Desktop: `apps/desktop/`
- CSP operators: `docs/HUB-OPERATOR.md`
- Core tests: `cargo test -p hacash-wallet-core`
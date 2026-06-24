# Hacash Wallet

Modern, secure desktop wallet for Hacash with encrypted on-device keys, local signing, L1 payments, and L2 Fast Pay architecture (hub integration phase 2).

## Security model

| Layer | Technology |
|-------|------------|
| Vault encryption | Argon2id (64 MiB) + AES-256-GCM |
| Key handling | Local sign only — private key never sent to node API |
| Memory | `zeroize` on decrypted secrets |
| Auto-lock | Configurable timeout (default 180s) |
| Phase 2 | Windows Hello / Touch ID, YubiKey WebAuthn |

## Architecture

```
React UI (Tauri WebView)
    ↓ invoke
Rust Tauri shell
    ↓
hacash-wallet-core
  ├── vault (encrypted storage)
  ├── account + protocol signing
  ├── node client (balance, build, submit)
  └── payment router (L2 hub → L1 fallback)
```

## Development

### Prerequisites

- Rust stable
- Yarn
- [Tauri prerequisites](https://v2.tauri.app/start/prerequisites/) (Windows: WebView2, VS Build Tools)

### Run

```bash
cd apps/desktop
yarn install
yarn tauri dev
```

### Test core only

```bash
cargo test -p hacash-wallet-core
```

## Roadmap

- [x] MVP: create/unlock wallet, balance, L1 send with preview
- [ ] L2 Fast Pay hub client
- [ ] Biometric unlock (platform APIs)
- [ ] YubiKey WebAuthn for high-value sends
- [ ] Mobile (shared `wallet-core` crate)
- [ ] HIP-23 DeFi patterns (Advanced tab)
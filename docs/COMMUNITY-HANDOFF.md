# Hacash Wallet — Community Handoff Guide

This document describes how the **Hacash Wallet** (`Moskyera/hacash-wallet`) is released and operated by the community while Moskyera continues active development and prepares **Hacash Quantum Wallet** as a separate product (see [`hacash-quantum-wallet-design.md`](./hacash-quantum-wallet-design.md)).

---

## Product scope (legacy wallet)

| Feature | Status |
|---------|--------|
| secp256k1 wallet (create / import / unlock) | Stable |
| L1 send (Types 1–3) | Stable |
| L2 Fast Pay + hub discovery | Active development |
| HACD / BTC send | Desktop |
| Optional Quantum tab (Type 4) | Experimental — requires PQC fullnode |
| Mobile (Android) | Active development |

**Hacash Quantum Wallet** will be a **separate app** (PQ-first). This repo remains the legacy + Fast Pay wallet.

---

## Downloads

| Platform | Source |
|----------|--------|
| Desktop (Windows, Linux) | [GitHub Releases](https://github.com/Moskyera/hacash-wallet/releases) — tags `v*-desktop` |
| Mobile (Android) | GitHub Releases — tags `v*-mobile` |
| Landing page | [moskyera.github.io](https://moskyera.github.io/) |

---

## Roles

### Wallet users

1. Download the latest release for your platform.
2. Create or import a wallet; back up the encrypted JSON export.
3. Configure node URL (default public node or your own).
4. Enable Fast Pay from the Fast Pay tab (hub discovery or manual hub URL).

### Hub operators (Fast Pay CSP)

- Read [`HUB-OPERATOR.md`](./HUB-OPERATOR.md)
- Run the hub binary from `crates/l2-fast-pay-hub` (or published release artifact)
- Expose Hub API v1 over HTTPS; register in hub discovery list when upstream accepts community hubs

### Node runners

- Clone `hacash-fullnodedev` (main branch for legacy Types 1–3)
- For Quantum tab / Type 4: branch `feature/pqc-phases-1-3`
- Point wallet **Settings → Node API URL** to your node

### Maintainers

- Merge PRs to `main`; keep CI green (`cargo test`, desktop `yarn build`, mobile build)
- Tag releases: `vX.Y.Z-desktop`, `vX.Y.Z-mobile`
- Attach unsigned binaries to GitHub Releases (code signing optional future work)
- Update [moskyera.github.io](https://moskyera.github.io/) download links after each release

---

## Development setup

```bash
git clone https://github.com/Moskyera/hacash-wallet.git
cd hacash-wallet/apps/desktop
yarn install
yarn tauri dev
```

Full stack (local node + poworker): run `scripts/START-DEV-STACK.bat` on Windows.

PQC / Type 4 (optional):

```bash
git clone --branch feature/pqc-phases-1-3 https://github.com/Moskyera/fullnodedev.git ../hacash-fullnodedev
```

---

## Release checklist

- [ ] `cargo test -p hacash-wallet-core --lib`
- [ ] `cargo test -p hacash-wallet-core audit_ -- --test-threads=1`
- [ ] Desktop: `yarn build` + `yarn tauri build`
- [ ] Mobile: `yarn tauri android build`
- [ ] Write release notes under `releases/`
- [ ] Tag and publish GitHub Release
- [ ] Update moskyera.github.io download section

---

## Security

- Keys are encrypted on device (Argon2id + AES-256-GCM).
- Private keys are never sent to the node API.
- Export encrypted backups before passphrase changes or wallet deletion.
- Unsigned Windows binaries may trigger SmartScreen — verify SHA256 from release notes.

---

## Governance (proposed)

| Decision | Process |
|----------|---------|
| Release tags | Maintainer consensus on `main` |
| Hub allowlist / discovery | Community PR to wallet-core hub list |
| Breaking API changes | Design note + minor/major version bump |
| Security issues | Private report to maintainers; coordinated disclosure |

Open question: formal maintainer roster — track in design doc OQ-8.

---

## Related documents

- [`hacash-quantum-wallet-design.md`](./hacash-quantum-wallet-design.md) — quantum fork plan (deferred implementation)
- [`hacash-quantum-wallet-design-summary.md`](./hacash-quantum-wallet-design-summary.md) — executive summary
- [`HUB-OPERATOR.md`](./HUB-OPERATOR.md) — Fast Pay hub operations
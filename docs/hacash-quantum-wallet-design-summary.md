# Hacash Quantum Wallet - Design Summary

**Document:** `DESIGN-HQW-001` · **Status:** Phase 0 (design only) · **Date:** 2026-07-12
**Full design:** [`hacash-quantum-wallet-design.md`](./hacash-quantum-wallet-design.md)

---

## What we're building

**Hacash Quantum Wallet** is a **new, separate product** (`Moskyera/hacash-quantum-wallet`) forked from [Hacash Wallet](https://github.com/Moskyera/hacash-wallet). It is **PQ-first**: welcome screen creates/imports **PQC v6 (ML-DSA-65)** or **Hybrid v7** keystore v3 accounts; **Type 4** send is the default rail.

**Hacash Wallet stays as-is** - legacy secp256k1, Fast Pay, optional Quantum tab - and moves to **community operation** while Moskyera continues completing it as primary work. Quantum fork **implementation is deferred**; this pass delivers design + fork plan only.

---

## Why separate products (not dual-mode)

| Legacy (`hacash-wallet`) | Quantum (`hacash-quantum-wallet`) |
|--------------------------|-----------------------------------|
| secp256k1 vault primary | PQC keystore primary |
| Types 1–3 + L2 Fast Pay | Type 4 only (v1) |
| Quantum = optional tab | Entire app is quantum |
| `org.hacash.wallet` | `org.hacash.quantum.wallet` |
| `%APPDATA%\HacashWallet` | `%APPDATA%\HacashQuantumWallet` |

Side-by-side install without overwriting funds or settings.

---

## What already exists in the codebase

The fork reuses a mature quantum stack (no rewrite):

- **Core:** `crates/wallet-core/src/quantum.rs`, `quantum_vault.rs`, `type4_fee.rs`
- **IPC:** `crates/wallet-tauri-common/src/quantum_commands.rs`
- **UI:** Desktop Quantum tab components; mobile `QuantumScreen.tsx`
- **Tests:** `audit_quantum_smoke.rs`, E2E `e2e_fund_quantum.rs`
- **Node:** `hacash-fullnodedev` branch `feature/pqc-phases-1-3`

**Gap today:** quantum is **secondary** to legacy vault unlock (`wallet.rs`). Fork requires **PQ-primary vault** (recommended: wrapper `pq-vault.json` reusing existing encryption).

---

## Bridge: legacy → quantum funding

No new on-chain bridge contract. Proven flow:

1. Create PQC address in quantum wallet (or legacy Quantum tab).
2. In **legacy Hacash Wallet**, Send **Type 1 HAC** to that address.
3. Quantum wallet shows balance; user sends **Type 4**.

Documented today in `QuantumFundingCard.tsx` and `e2e_fund_quantum.rs`.

---

## Community handoff (legacy wallet)

| Area | Community operates |
|------|-------------------|
| Releases | Tags `v*-desktop`, `v*-mobile`; GitHub Releases |
| CSP hubs | `docs/HUB-OPERATOR.md`, `fast-pay-hub` binary |
| Nodes | `hacash-fullnodedev`, public `nodeapi.hacash.org` |
| Docs | [moskyera.github.io](https://moskyera.github.io/) |

**Gates before handoff:** reproducible CI releases, hub operator docs, integration tests green, mobile Phase 2, security audit gates, governance charter.

---

## Fork timing

**Recommended:** Q4 2026 - after legacy mobile Phase 2 + first community release.
**Do not fork before:** PQ-primary vault design locked (OQ-1).

---

## Rollout phases (abbreviated)

| Phase | Deliverable |
|-------|-------------|
| 0 | This design (now) |
| 1 | Repo scaffold, branding, CI, data paths |
| 2 | PQ-default desktop + mobile UX |
| 3 | PQ-primary vault |
| 4–6 | Bridge docs, desktop/mobile alpha releases |
| 7–8 | Legacy handoff + quantum beta/stable |

---

## Shared crates strategy

1. **Phase 1:** Copy `wallet-core` into quantum repo (fast fork).
2. **Phase 2:** Extract shared quantum crate or git-dep sync (72h security SLA).
3. **Phase 3:** Optional crates.io with `legacy` / `quantum-product` features.

---

## Quantum v1 scope cuts

**Remove:** Fast Pay, HACD/BTC send, Messenger, Dust Whisper, hub discovery, `quantum_mode` toggle.
**Keep:** Type 4 send, air-gap QR, keystore v3, WebAuthn/biometric gates, node health, security profiles.

---

## PR plan (12 ordered PRs)

1. Monorepo scaffold
2. Branding + bundle IDs
3. `HacashQuantumWallet` data path
4. `quantum-product` feature flag
5. PQ-primary vault
6. Trim Tauri IPC
7. Desktop PQ-first UI
8. Mobile PQ-first UI
9. CI / quantum release workflows
10. Bridge + node docs
11. E2E integration tests
12. Audit gate verification

See full PR details in [design doc §13](./hacash-quantum-wallet-design.md#13-pr-plan-ordered-fork-prs).

---

## Key decisions

1. Separate repo and product - not dual-mode in one app.
2. Legacy wallet unchanged; community handoff planned.
3. Legacy remains primary active work until handoff gates met.
4. Quantum implementation deferred; design + PR plan now.
5. Reuse existing quantum modules and audit tests.
6. Distinct data dir and package IDs for side-by-side install.
7. Bridge funding via legacy Type 1 HAC (existing on-chain pattern).
8. Omit Fast Pay and multi-asset sends in quantum v1.
9. Pin PQC fullnode branch `feature/pqc-phases-1-3`.

---

## Open questions (top 5)

| ID | Question |
|----|----------|
| OQ-1 | PQ-primary vault: keystore-only vs wrapper vault vs dual unlock? |
| OQ-2 | Ship Hybrid v7 in v1 or PQC-only? |
| OQ-5 | Public PQC node URL for alpha? |
| OQ-8 | Community maintainer roster? |
| OQ-9 | Quantum product icon / visual identity? |

---

## References

- Legacy repo: https://github.com/Moskyera/hacash-wallet
- Community site: https://moskyera.github.io/
- Hub operators: `docs/HUB-OPERATOR.md`
- Full design: `docs/hacash-quantum-wallet-design.md`
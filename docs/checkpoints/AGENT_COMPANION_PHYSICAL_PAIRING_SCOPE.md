# Agent companion physical pairing: change scope

Checkpoint: 2026-08-03
Branch: codex/how-it-works-hacd-fidelity
HEAD: 26ae4c5d0367aa7a59aab17abd8a8a8a15293e90
Source manifest: docs/agent-wallet/pilot-results/2026-08-03-source-manifest.json
Manifest SHA-256: 3d9d77f2ef3db2c3a4f3890f8ef726ab5fd6e2b9dd64a4af608fde19a226883e

## Index truth

```text
Modified files: 207
Untracked files: 171
Deleted files: 5513 (all under releases/, pre-existing)
Staged file contents: 0
Pre-existing intent-to-add index entries: present (empty blob e69de29)
git add executed in this session: no
```

The intent-to-add entries were not created here and are left untouched. No
`git reset`, `restore`, `checkout --`, `clean` or `add` was run.

## A. Allowed mobile source

```text
apps/mobile/src/agent/AgentCompanionApp.tsx
apps/mobile/src/agent/CompanionReadOnlyPages.tsx
apps/mobile/src/agent/useCompanionSession.ts
apps/mobile/src/agent/agent-wallet.css
```

## B. Allowed desktop companion source

```text
apps/desktop/src/agent/AgentWalletApp.tsx
apps/desktop/src/agent/AgentAdminPages.tsx
apps/desktop/src/agent/MobileCompanionPanel.tsx
apps/desktop/src/agent/agent-wallet.css
```

## C. Allowed shared UI

```text
packages/wallet-ui/src/securityPolicy.ts
```

Copied into each app by `pnpm install`, because `@hacash/wallet-ui` is a `file:`
dependency that pnpm materializes as a copy and not a symlink. A shared package
edit is invisible to both apps until that install is re-run.

## D. Allowed protocol and transport

```text
crates/companion-lan-runtime/src/error.rs
crates/companion-lan-runtime/src/mobile.rs
```

Local error classification only. `PROTOCOL_VERSION` stays 3. No frame format,
handshake, device identity, approval commitment, witness or network binding
change. No new wire message.

## E. Allowed tests

```text
apps/mobile/src/agent/companionUi.test.ts
crates/companion-lan-runtime/src/mobile.rs (test module)
```

## F. Allowed documentation and evidence

```text
docs/agent-wallet/HOW-THE-AGENT-WALLET-WORKS.md
docs/agent-wallet/pilot-results/2026-08-03-physical-pairing-fix.md
docs/agent-wallet/pilot-results/2026-08-03-source-manifest.json
docs/checkpoints/AGENT_COMPANION_PHYSICAL_PAIRING_SCOPE.md
```

## G. Generated artifacts

```text
apps/mobile/dist/**
apps/mobile/src-tauri/gen/android/app/build/outputs/apk/**
target-android/**
target-ci/**
```

Debug signing only. No release APK, AAB or Play artifact.

## H. Pre-existing Agent Wallet untracked source

The `crates/agent-wallet-core`, `crates/agent-connector`, `crates/agent-types`,
`crates/companion-protocol`, `crates/companion-lan-runtime` trees and much of
`apps/desktop/src/agent` are untracked on this branch. They are production
source, not disposable, and were inventoried rather than cleaned.

## I. Pre-existing unrelated modifications

Personal Wallet, fullnode, pool, mining, Harbor and L2 files carry
modifications that predate this work. None were touched.

## J. Existing releases/ deletions

5513 deletions under `releases/` predate this work and remain unchanged.

## K. Strictly forbidden

```text
crates/companion-protocol/src/message.rs PROTOCOL_VERSION
any new wire message or frame format change
crates/wallet-tauri-common/src/companion_backend.rs snapshot privacy filter
release signing material and ANDROID_* signing environment
releases/**
fullnode, pool, mining, Harbor, L2 sources
git add, staging, commit, push, tag, release
```

# HPAY physical Android Local Pilot transaction evidence

Date: 2026-08-02

Current classification: `Agent Wallet funded; verified Pilot APK installed on physical Android; Keystore, biometric and payment gates pending`.

This is an incremental, redacted record. It must not be classified as a
physical payment until every physical, Keystore, biometric, pairing, signing,
broadcast and final-witness gate is supported by direct evidence.

## Worktree checkpoint

| Field | Value |
|---|---|
| Branch | `codex/how-it-works-hacd-fidelity` |
| HEAD | `26ae4c5` |
| Modified summary entries | `203` |
| Deleted entries | `5,513` |
| Deleted entries under `releases/` | `5,513` |
| Staged | `0` |
| Commit, push, tag or release | None |

Per-file untracked enumeration reports more entries than normal directory
summary mode because it expands every file inside untracked directories. No
cleanup, restore or staging operation was performed.

## Local Pilot runtime

| Field | Value |
|---|---|
| Node process | Dedicated `target/hpay-local-pilot/release/fullnode.exe` |
| Configuration | `%LOCALAPPDATA%/HPAY/agent-local-pilot-v1/runtime/node.ini` |
| Chain data | `%LOCALAPPDATA%/HPAY/agent-local-pilot-v1/data` |
| Node | `hacash-fullnode 1.0.10` |
| API | `http://127.0.0.1:8197` |
| Network kind | `local_pilot_v1` |
| Profile | `hpay-local-pilot-chain-v1` |
| Chain ID | `7` |
| Mainnet | `false` |
| Height | `20` |
| Block 1 | `000087f67e55660eaefed72e0b9499147556a33a34f18fa48900f4a2fa30cd29` |
| Network instance | `9ebd8657a72faed35ed4d6e309fab2ef259f054e4820684fab6c6b848e4438f3` |
| Type 2 / action 1 | Enabled |
| Balance, submit, query and reconciliation APIs | Enabled |
| Funding confirmed | `true` |
| Transaction ready | `true` |
| Miner | Stopped |

## Agent balance

| Field | Value |
|---|---|
| Public address | `1QGpzAdoDJoCYewETU6mNZmaFfd1By4wD2` |
| Backend confirmed HAC | `8` |
| UI displayed HAC | `8`, directly confirmed by the user |
| HPAY Agent wallet fee | `0` |

No private key, seed, mnemonic, passphrase, vault plaintext, recovery material,
pairing token, raw transaction or signature was requested, read or recorded.

## Fresh ARM64 Pilot APK

| Field | Value |
|---|---|
| Path | `apps/mobile/src-tauri/gen/android/app/build/outputs/apk/arm64/debug/app-arm64-debug.apk` |
| Build mode | Android Debug; Pilot feature enabled |
| ABI | `arm64-v8a` only |
| Package | `org.hacash.wallet.mobile` |
| Version | `1.0.2` (`versionCode 10002`) |
| Size | `320,920,996` bytes |
| SHA-256 | `299b9964f630a9110c9d6e432a9b7d0204e48a0d117b6950a55ce7a9a20d4372` |
| Signer | Android Debug |
| Signer certificate SHA-256 | `9cadd5204a0aa3b00066c3c7c2b4bc7197c6c4096d53b5ff28850058957c7712` |
| APK Signature Scheme v2 | Verified |
| Strict generated-project validator | Passed |
| Bundled frontend | Present and validator passed |
| Embedded native library | Exact SHA-256 match with the fresh ARM64 Pilot build output |
| Release status | Debug only; not published |

The Tauri Windows symlink step was unavailable. The documented safe copy
fallback packaged the exact freshly built ARM64 debug library and skipped a
second Rust build. The embedded library hash equals the source build artifact
hash `593285a79ac0189cf3369107936bc964371b638c417a82350fc64554e40f7241`.

## Physical Android status

| Field | Result |
|---|---|
| Official ADB | `Android Debug Bridge 1.0.41`, platform-tools `36.0.2-14143358` |
| ADB path | `%LOCALAPPDATA%/Android/Sdk/platform-tools/adb.exe` |
| Physical device connected to Windows | Yes; Honor 90 (`REA-NX9`) |
| Physical device detected by ADB | Yes, through user-enabled Wireless debugging |
| ADB authorization | Authorized by the user through one-time pairing |
| Emulator substituted | No |
| APK installed | Yes; fresh verified ARM64 Pilot APK |
| Old test HPAY data | Deleted after explicit user confirmation |
| Other applications or device settings changed | No |
| Physical Keystore verified | Not executed |
| Physical biometric verified | Not executed |
| Same-LAN pairing | Not executed |
| Local reference agent paired | Not executed |
| Local Pilot transaction | Not executed |

## Safe-install preflight

The Honor 90 was paired through Wireless ADB and verified as an authorized
physical ARM64 device running Android 15 with security patch `2026-07-01`,
green Verified Boot, locked bootloader and file-based encryption.

The existing HPAY package is version `1.0.2` (`versionCode 10002`). Its signer
certificate SHA-256 is
`1a879fa236a53e9f6517507b3662019d2a5ed92df81f555bcf18fe33b4eb002d`.
The fresh debug Pilot APK signer is
`9cadd5204a0aa3b00066c3c7c2b4bc7197c6c4096d53b5ff28850058957c7712`.

Result: signer mismatch prevented an in-place update. The user explicitly
confirmed that the old test HPAY and its data were not needed and authorized
removal of only `org.hacash.wallet.mobile`, followed by installation of the
fresh Pilot APK. No other application or device setting was changed.

Post-install verification read the installed package back from the physical
device. It reports version `1.0.2` (`versionCode 10002`), signer certificate
SHA-256
`9cadd5204a0aa3b00066c3c7c2b4bc7197c6c4096d53b5ff28850058957c7712`,
and installed APK SHA-256
`299b9964f630a9110c9d6e432a9b7d0204e48a0d117b6950a55ce7a9a20d4372`.
Both values exactly match the pre-install verified Pilot artifact. The app was
not launched automatically.

The Desktop UI and backend balances remain synchronized at 8 HAC. The Pilot
transaction is still stopped before Keystore creation, biometric approval,
agent pairing, signing or broadcast. No private or recovery material was read
or recorded.

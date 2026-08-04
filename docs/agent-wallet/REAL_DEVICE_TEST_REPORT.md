# HPAY Agent Wallet Real-Device Test Report

Date: 2026-08-01

Classification: automated/build evidence plus a read-only live local-node
preflight; no physical-device or live testnet transaction evidence.

## Device status

| Check | Result |
|---|---|
| Physical Android detected | No (`adb devices -l` returned no devices) |
| Keystore verified on physical device | Not executed |
| Biometric verified on physical device | Not executed |
| Same-LAN pairing verified | Not executed |
| Witness approval verified on physical device | Not executed |
| Rotation verified with two physical devices | Not executed |

The Kotlin implementation compiled and its static contracts passed, but this
does not count as physical-device verification.

## Live testnet status

| Check | Result |
|---|---|
| Live fullnode 1.0.10 endpoint verified | Yes, at the explicit local preflight endpoint |
| Separate testnet chain verified | No; the node reported `mainnet=true`, `chain.id=0` |
| Testnet V3 verified live | No; stopped on the mainnet network binding |
| Capabilities verified live | Yes; API version 1 parsed successfully |
| Funded Agent Wallet available | No |
| Actual testnet transaction executed | No |
| Transaction id | Not executed |
| Post-submit witness completed live | Not executed |
| Final reconciliation anchor completed live | Not executed |

No node was started by this checkpoint, no wallet was funded, and no
transaction was broadcast. A read-only preflight of the already-running local
endpoint returned `hacash-fullnode 1.0.10`, build
`2026/7/10 #1`, Istanbul active, and the required Type 2/action 1 entries.
It also returned `mainnet=true`; the Pilot therefore stopped before wallet
connection. Transaction lifecycle results remain automated mock-node evidence.

### 2026-08-02 isolated-node update

A separate custom node now runs from a dedicated profile and user-scoped data
directory. Its runtime response is `hacash-fullnode 1.0.10`, chain 7,
`mainnet=false`, capability API 1, with the required typed transaction API
contract. It is at height 0 and has no block-one anchor, so it is not
transaction-ready. ADB remains unavailable; every physical Android, Keystore,
biometric, LAN, funding, and live-transaction result remains not executed.

## Debug APK evidence

| Field | Value |
|---|---|
| Path | `apps/mobile/src-tauri/gen/android/app/build/outputs/apk/arm64/debug/app-arm64-debug.apk` |
| ABI | `arm64-v8a` only |
| Package | `org.hacash.wallet.mobile` |
| Version | `1.0.2` (`versionCode 10002`) |
| Status | Debug, not release |
| Size | 622,962,774 bytes |
| SHA-256 | `148EC6B7C8FAC20E041A6E75F18BC716A616D8179B7AB04F7B60852C97F7715B` |
| Signer | Android Debug, certificate SHA-256 `9cadd5204a0aa3b00066c3c7c2b4bc7197c6c4096d53b5ff28850058957c7712` |
| Bundled frontend | Strict validator passed |

This APK must not be published or described as a distribution or release
artifact.

The 2026-08-01 recheck used Android build-tools 36.1.0. `aapt` reported only
`arm64-v8a`, `apksigner` verified the Android Debug certificate, the strict
Android validator passed, and `adb devices -l` returned no devices.

## Readiness

`Automated hardening complete; real-device pilot pending`

The active local fullnode is mainnet, so it cannot satisfy the Pilot's
separate-testnet requirement. Mainnet Agent send remains disabled.

## 2026-08-02 final status

Physical Android execution remains not executed. The private Local Pilot chain
reached real height 12 and has block 1
`000087f67e55660eaefed72e0b9499147556a33a34f18fa48900f4a2fa30cd29`
with network instance
`9ebd8657a72faed35ed4d6e309fab2ef259f054e4820684fab6c6b848e4438f3`.
No user-created funded Agent Wallet is present, so the chain correctly reports
`transaction_ready: false`. Android installation, Keystore, biometric,
same-LAN witness and two-phone rotation claims remain unverified. The existing
debug APK is stale relative to the current node-binding source and is not pilot
evidence.

Final classification: `No safe transaction-ready chain available`.

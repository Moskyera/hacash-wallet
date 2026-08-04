# HPAY Physical Android Pilot

Date: 2026-08-02

Status: not executed.

`adb` was not available in PATH, but the official SDK binary was found at
`%LOCALAPPDATA%\Android\Sdk\platform-tools\adb.exe`. It enumerated no physical
Android device. No emulator result is substituted for physical evidence.

## Preflight result

| Check | Result |
|---|---|
| Official Android SDK ADB available | Yes, outside PATH |
| Physical Android detected | No |
| ADB authorized | Not executed |
| ABI and Android version | Not executed |
| Existing app data inventory | Not executed |
| Safe APK install/update | Not executed |
| Android Keystore security level | Not executed |
| Non-exportable per-use key | Not executed |
| Strong biometric prompt | Not executed |
| Same-LAN pairing | Not executed |
| Authenticated reconnect | Not executed |
| Mobile witness | Not executed |
| Two-phone RotationCandidate | Not executed |

The existing ARM64 debug APK was verified read-only: package
`org.hacash.wallet.mobile`, version `1.0.2`, size 622,962,774 bytes, SHA-256
`148EC6B7C8FAC20E041A6E75F18BC716A616D8179B7AB04F7B60852C97F7715B`,
Android Debug signer. It predates the current node-binding changes and is not
accepted as pilot evidence. No replacement APK was built because the Local
Pilot chain is not transaction-ready.

## Procedure when a physical device is available

1. Install ADB/platform-tools and enumerate with `adb devices -l`.
2. Reject emulators and unauthorized/offline devices.
3. Record package/version/signer before installation; never uninstall or clear
   app data.
4. Install only with the update-preserving path after signer/package match.
5. Verify StrongBox/TEE security level from the native plugin response.
6. Complete a real biometric prompt; simulated callbacks do not qualify.
7. Pair over the authenticated same-LAN companion transport. The phone never
   connects directly to the fullnode API.
8. Repeat reconnect, witness, and negative pairing tests.
9. Execute two-phone rotation only when two distinct physical devices exist.

Until the Local Pilot funding prerequisite is satisfied, the correct readiness
classification is `No safe transaction-ready chain available`.

## Local Pilot prerequisite

Physical Android checks must not begin until `scripts/get-agent-local-pilot-status.ps1` reports `transaction_ready: true` and the Agent Wallet has a positive confirmed balance. A mined chain without a funded Agent address is insufficient.

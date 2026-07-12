# Hacash Wallet — Releases

## Latest downloads

### Desktop (Windows x64) — v0.1.12

| File | Link |
|------|------|
| **Setup (recommended)** | [hacash-wallet-desktop-v0.1.12-x64-setup.exe](https://github.com/Moskyera/hacash-wallet/releases/download/v0.1.12-desktop/hacash-wallet-desktop-v0.1.12-x64-setup.exe) |
| MSI installer | [hacash-wallet-desktop-v0.1.12-x64.msi](https://github.com/Moskyera/hacash-wallet/releases/download/v0.1.12-desktop/hacash-wallet-desktop-v0.1.12-x64.msi) |
| Portable EXE | [hacash-wallet-desktop-v0.1.12-x64-portable.exe](https://github.com/Moskyera/hacash-wallet/releases/download/v0.1.12-desktop/hacash-wallet-desktop-v0.1.12-x64-portable.exe) |

### Mobile (Android arm64) — v0.1.13

| File | Link |
|------|------|
| APK | [hacash-wallet-mobile-v0.1.13-arm64.apk](https://github.com/Moskyera/hacash-wallet/releases/download/v0.1.13-mobile/hacash-wallet-mobile-v0.1.13-arm64.apk) |

> App display name is **Hacash Wallet** (was "Hacash Wallet Mobile" in v0.1.12 and earlier).

## Install — Desktop

1. Download `hacash-wallet-desktop-v0.1.12-x64-setup.exe`
2. Run installer → open **Hacash Wallet** from Start menu

## Install — Mobile (GrapheneOS / Android)

1. Download APK in browser
2. Files → Downloads → tap APK
3. Allow install from browser/Files if prompted
4. Open **Hacash Wallet**

Or via adb:

```bash
adb install hacash-wallet-mobile-v0.1.13-arm64.apk
```

## Verify checksum (optional)

```powershell
Get-FileHash releases\hacash-wallet-desktop-v0.1.12-x64-setup.exe -Algorithm SHA256
```

Expected: `ABF0B5624E0CD81E06A5F22C7A04C8C2299F7D0303D060F55E92503963ECEBC0`

## Release notes

- Desktop: `v0.1.12-desktop-notes.md`
- Mobile: `v0.1.13-mobile-notes.md`
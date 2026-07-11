# Hacash Wallet — Android releases

## Latest mobile APK

**File:** `hacash-wallet-mobile-v0.1.1-arm64.apk`  
**Target:** Android arm64 (most phones, including GrapheneOS)  
**Signed:** yes (release keystore)  
**Backup:** disabled (`allowBackup=false`)  
**Fix in v0.1.1:** vault writes to app-internal storage (fixes "read only file system error 30")

### Direct download (GitHub)

```
https://github.com/Moskyera/hacash-wallet/releases/download/v0.1.1-mobile/hacash-wallet-mobile-v0.1.1-arm64.apk
```

### Install on GrapheneOS

1. Download the APK in **Vanadium** (or any browser) from the link above.
2. Open **Files** → Downloads → tap the APK.
3. If prompted, allow **Install unknown apps** for your browser or Files app (Settings → Apps → … → Install unknown apps).
4. Confirm install → open **Hacash Wallet Mobile**.

Or via `adb` from a PC:

```bash
adb install hacash-wallet-mobile-v0.1.0-arm64.apk
```

### Verify checksum (optional)

```powershell
Get-FileHash releases\hacash-wallet-mobile-v0.1.1-arm64.apk -Algorithm SHA256
```
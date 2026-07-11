# Hacash Wallet — Android releases

## Latest mobile APK

**File:** `hacash-wallet-mobile-v0.1.3-arm64.apk`  
**Target:** Android arm64 (most phones, including GrapheneOS)  
**Signed:** yes (release keystore)  
**Backup:** disabled (`allowBackup=false`)  
**Fixes in v0.1.3:**
- Bundles UI inside APK (fixes `127.0.0.1:1421` dev-server error on phone)
- Branded Hacash launcher icon (v0.1.2)
- Vault app-internal storage fix (v0.1.1)

### Direct download (GitHub)

```
https://github.com/Moskyera/hacash-wallet/releases/download/v0.1.3-mobile/hacash-wallet-mobile-v0.1.3-arm64.apk
```

### Install on GrapheneOS

1. Download the APK in **Vanadium** (or any browser) from the link above.
2. Open **Files** → Downloads → tap the APK.
3. If prompted, allow **Install unknown apps** for your browser or Files app (Settings → Apps → … → Install unknown apps).
4. Confirm install → open **Hacash Wallet Mobile**.

Or via `adb` from a PC:

```bash
adb install hacash-wallet-mobile-v0.1.2-arm64.apk
```

### Verify checksum (optional)

```powershell
Get-FileHash releases\hacash-wallet-mobile-v0.1.3-arm64.apk -Algorithm SHA256
```

Expected SHA256: `4AAA57F654C23D061546648969C695E51769B24A728D2696DAA7FCEBC54FD4D5`
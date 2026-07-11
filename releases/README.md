# Hacash Wallet — Android releases

## Latest mobile APK

**File:** `hacash-wallet-mobile-v0.1.5-arm64.apk`  
**Target:** Android arm64 (most phones, including GrapheneOS)  
**Signed:** yes (release keystore)  
**Backup:** disabled (`allowBackup=false`)  
**Fixes in v0.1.5:**
- Allow cleartext HTTP to Hacash node API on Android (`network_security_config` base-config + `usesCleartextTraffic=true` in release)
- Graceful wallet data load: `Promise.allSettled` so partial node/hub failures do not block the UI
- Enable Tauri `custom-protocol` feature in mobile Rust build (fixes `is_dev()` always true on Android → no more `127.0.0.1:1421` dev-server load)
- Strip `devUrl` from bundled `tauri.conf.json` in release APK assets
- Bundles UI inside APK (v0.1.3)
- Branded Hacash launcher icon (v0.1.2)
- Vault app-internal storage fix (v0.1.1)

### Direct download (GitHub)

```
https://github.com/Moskyera/hacash-wallet/releases/download/v0.1.5-mobile/hacash-wallet-mobile-v0.1.5-arm64.apk
```

### Install on GrapheneOS

1. Download the APK in **Vanadium** (or any browser) from the link above.
2. Open **Files** → Downloads → tap the APK.
3. If prompted, allow **Install unknown apps** for your browser or Files app (Settings → Apps → … → Install unknown apps).
4. Confirm install → open **Hacash Wallet Mobile**.

Or via `adb` from a PC:

```bash
adb install hacash-wallet-mobile-v0.1.5-arm64.apk
```

### Verify checksum (optional)

```powershell
Get-FileHash releases\hacash-wallet-mobile-v0.1.5-arm64.apk -Algorithm SHA256
```

Expected SHA256: `BA84EE13F0636176EF9530530BA39D05DD28E4F4AB655A400AF5AB272B534490`
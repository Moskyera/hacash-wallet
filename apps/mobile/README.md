# Hacash Wallet - Mobile

Tauri 2 mobile shell sharing **`hacash-wallet-core`** via **`wallet-tauri-common`**.

## Features

- Create / import / **watch-only** wallet
- HAC + HACD + **BTC** balances on Home
- **HAC send** (L1 + Fast Pay) with QR scan
- **HACD send** with HIP-5 visuals and batch send
- **BTC on-chain send** (Hacash network kind 8)
- Fast Pay enable + **channel management** (More → Fast Pay channel)
- Quantum Type 4 online send + **Type 4 air-gap QR**
- **L1 air-gap QR** (coordinator / offline signer)
- **Native biometrics** (Face ID / fingerprint on Android/iOS)
- **WebAuthn** passkeys in Security
- **Deep links** (`hacash://`, `hacd://`) via `tauri-plugin-deep-link`
- DUST Whisper + Messenger
- Dispute bills, contacts, privacy, security profiles

## Architecture

```
hacash-wallet-core
       ↑
wallet-tauri-common   ← shared Tauri IPC commands
       ↑
apps/mobile/src-tauri ← Tauri 2 mobile entry point
apps/mobile/src/      ← React UI (420px mobile layout)
```

## Dev - desktop preview (no Android SDK)

```bat
scripts\DEV-MOBILE.bat
```

Or:

```bash
cd apps/mobile
yarn install
yarn tauri dev
```

Opens a narrow window at `http://127.0.0.1:1421`. Biometrics use Windows Hello in this mode.

**Note:** `cargo build --release` alone produces a binary without bundled frontend. Use `yarn tauri build` or `yarn tauri dev` for a working app.

## Tests

```bash
cd apps/mobile
yarn test
```

Covers deep-link parsing and WebAuthn gate rules.

## Release - Android

Prerequisites: [Tauri mobile prerequisites](https://v2.tauri.app/start/prerequisites/) + Android Studio + NDK.

### One-time setup

```powershell
cd apps/mobile
.\setup-android.ps1
```

This installs SDK command-line tools, NDK `27.2.12479018`, sets `ANDROID_HOME` / `NDK_HOME` / `JAVA_HOME`, and adds Rust Android targets.

**Windows:** Enable **Developer Mode** (Settings → System → For developers) so Tauri can create symlinks for native libs. Without it, the build may fail unless run as Administrator.

### Build APK

Double-click or run:

```bat
BUILD-ANDROID.bat
```

Or:

```powershell
.\build-android.ps1
```

### Signed release APK

One-time keystore (password via env or prompt):

```powershell
$env:ANDROID_KEYSTORE_PASSWORD = "your-strong-password"
.\create-android-keystore.ps1
.\apply-android-patches.ps1
.\build-android.ps1
```

Or: `run-aarch64-signed-build.bat` (after keystore exists).

Signed output:

```
src-tauri\gen\android\app\build\outputs\apk\universal\release\app-universal-release.apk
```

Keystore: `src-tauri\hacash-wallet-release.jks` (gitignored). **Never commit** `.jks` or `keystore.properties`.

### Default network (wallet works out of the box)

| Setting | Default |
|---------|---------|
| **Hacash node (L1)** | `http://nodeapi.hacash.org` - public node API (balance, send, BTC, HACD) |
| **Fast Pay (L2)** | Off until you enable it in the app and configure a hub URL |
| **Quantum node** | Same as wallet node URL (Settings) |

Change node/hub anytime: **More → Network settings**. Android release allows HTTP only to `nodeapi.hacash.org` (network security config); other traffic stays HTTPS-only.

### Dev on device / emulator

```bash
yarn tauri android dev
```

USB debugging enabled on phone, or Android emulator running in Android Studio.

## Release - iOS (macOS only)

```bash
yarn tauri ios init
yarn tauri ios build
```

## Related

- Desktop: `apps/desktop/`
- Operator docs: `docs/HUB-OPERATOR.md`
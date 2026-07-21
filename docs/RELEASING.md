# Release process

Release metadata is synchronized by `scripts/release-version.mjs`. The pinned
Rust version is in `rust-toolchain.toml`, and the exact sibling fullnodedev
commit is in `.github/fullnode-revision`. CI and release jobs refuse to replace
an existing dirty or different fullnodedev checkout.

## Version gate

Run these commands before building a release:

```text
node scripts/release-version.mjs set 1.0.0
node scripts/release-version.mjs check 1.0.0
```

The release tags must match the synchronized version exactly:

- `v1.0.0-desktop`
- `v1.0.0-mobile`

Pushing a desktop tag builds Windows x64 and Linux x64 in separate jobs. The
release is published only after both jobs provide the complete required set and
the combined checksum manifest passes validation.

The Windows release contains NSIS, MSI, and a raw portable executable. The
Linux release contains deb, AppImage, and a raw `-x64-portable`. AppImage is the
portable Linux option. The raw Linux binary needs compatible GTK 3,
WebKitGTK 4.1, and their system runtime libraries.

## Android signing gate

The mobile release workflow requires all four GitHub Actions secrets:

- `ANDROID_KEYSTORE_BASE64`
- `ANDROID_KEYSTORE_PASSWORD`
- `ANDROID_KEY_ALIAS`
- `ANDROID_EXPECTED_CERT_SHA256`

`ANDROID_EXPECTED_CERT_SHA256` is the SHA-256 certificate fingerprint of the
existing production signing key. It prevents an accidental key replacement
that would make upgrades fail on installed devices.

The workflow never publishes an unsigned APK. It requires exactly one release
APK, then verifies its signing scheme and pinned certificate, package id,
version, min/target SDK, and exact `arm64-v8a` ABI. Only after those checks does
it rename the APK and generate `SHA256SUMS-vX.Y.Z-mobile.txt`.

Do not print, upload as a build artifact, or commit the keystore or its
password. A workflow dispatch without the required secrets is build-blocked and
does not publish anything.

## Supported v1.0.0 artifacts

- Windows 10/11 x64: NSIS, MSI, portable executable
- Linux x64: deb, AppImage, raw binary with runtime dependencies
- Android 9+ arm64: signed APK

Windows ARM64, Linux ARM64, Android x86/x86_64, and iOS are not release targets
in v1.0.0 and must not be advertised as built or tested artifacts.

# Hacash Wallet — Releases

## Latest downloads

**→ [github.com/Moskyera/hacash-wallet/releases/latest](https://github.com/Moskyera/hacash-wallet/releases/latest)**

Or the download page, which picks the newest build for you:
**[moskyera.github.io](https://moskyera.github.io/)**

This file used to carry download tables. It listed `v0.1.18` twenty times, long
after the wallet reached 1.0 — and every one of those links still answered 200
and handed a browser a real pre-1.0 wallet. Nobody saw an error; they just got
software eight releases old, from a file titled "Latest downloads".

So the tables are gone rather than corrected. A version written down in a second
place is a version that goes stale, and the two places that resolve the newest
release on their own have never needed touching:

- the releases page above always shows the newest tag
- `moskyera.github.io` reads the newest `-desktop` and `-mobile` tags from the
  GitHub API on every load and picks the assets by filename, so a release
  reaches people without anyone editing anything

## What is published

Each desktop tag (`v<version>-desktop`) carries Windows setup, MSI and portable
executables, a Linux AppImage, a `.deb`, a portable Linux binary, and a
`SHA256SUMS` file. Each mobile tag (`v<version>-mobile`) carries an arm64 APK.

## Install — Windows

1. Download the setup executable from the releases page above
2. Run it, then open **HPAY** from the Start menu

## Install — Android

1. Download the APK in a browser
2. Files → Downloads → tap the APK
3. Allow installation from that app if prompted

Or with adb, using the file you actually downloaded:

```bash
adb install <the-apk-you-downloaded>.apk
```

## Release notes

Written on each GitHub release itself, so the notes and the files can never
describe different builds.

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

## Isolated release signing

Create a GitHub Environment named `release-signing`, restrict deployment to the
two exact release tag patterns, and require an independent reviewer. Only the
`sign-windows` and `sign-android` jobs use this environment.

The build jobs are deliberately unprivileged. Repository checkout, fullnode
checkout, dependency installation, repository scripts, frontend compilation,
Rust compilation, Gradle, Tauri, NSIS, and WiX all run without private signing
secrets. Their exact unsigned outputs are uploaded as short-lived workflow
artifacts.

Each protected signing job:

1. starts on a fresh runner;
2. does not check out the repository;
3. downloads only the unsigned artifact from its required build job;
4. validates the exact filename set, version, format, architecture, and unsigned
   state before exposing a private key;
5. provides private values only to one inline signing-and-verification step; and
6. removes temporary key material before uploading the signed artifact.

No repository script or dependency runs in a protected signing job. The public
certificate fingerprints are GitHub repository Actions variables, not secrets.
Repository write access alone is not an adequate signing policy for a wallet.
Protect release tags and workflow files, and do not approve an environment
deployment until the source commit, completed CI run, and unsigned build
artifacts have been reviewed.

## Windows Authenticode gate

Configure these `release-signing` Environment secrets:

- `WINDOWS_CERTIFICATE_BASE64`
- `WINDOWS_CERTIFICATE_PASSWORD`

Configure this public repository Actions variable:

- `WINDOWS_EXPECTED_CERT_SHA256`

The variable is the normalized SHA-256 fingerprint of the full public
code-signing certificate. The unsigned Windows build receives only this public
pin because it is compiled into the updater. It never receives the PFX or its
password.

The protected Windows job accepts exactly one unsigned NSIS installer, MSI, and
portable executable for the synchronized version. It checks their PE/MSI magic
and refuses any pre-signed input. The inline signing step decodes the PFX, finds
exactly one private certificate with the code-signing EKU, rejects a certificate
outside the release validity window, and requires its full-certificate SHA-256
fingerprint to match the public variable. It then signs and timestamps all three
artifacts with `signtool` and re-verifies every Authenticode signature and
signer fingerprint before upload. The PFX is not imported into the persistent
Windows certificate store.

This isolated PFX flow signs the three downloadable files after Tauri has
packaged them. Tauri patches and copies the application PE while creating each
installer, so the executable embedded inside MSI/NSIS is not independently
Authenticode-signed by this post-package flow; trust is provided by the signed
outer installer. If an independently signed installed executable is required,
use Tauri's custom sign command with a non-exportable remote/HSM key. Do not put
an exportable PFX back into a checkout, dependency, or compilation job.


### Explicit one-tag unsigned Windows fallback

When a public Authenticode signer is not yet available, maintainers may publish a
complete desktop release only by setting the public repository variable
`UNSIGNED_WINDOWS_RELEASE_TAG` to the exact intended tag, for example
`v1.0.1-desktop`. The exception is valid for that tag only. The workflow requires
`WINDOWS_EXPECTED_CERT_SHA256` to be empty, verifies that all three Windows
artifacts remain unsigned, labels the release prominently, and declares the
custody class as `unsigned-distribution`.

An unsigned Windows build compiles without a publisher pin. Its in-app updater
therefore offers only the official release page and never downloads or launches
the installer automatically. Linux artifacts, SHA-256 checksums, and GitHub
provenance are still produced normally. Future tags fail closed unless they have
a valid signer pin or their own explicitly reviewed exact-tag exception.
### Windows high-value release gate

The isolated PFX workflow is a standard outer-signed distribution profile. It
must not be described or attested as `high-value`, `hardware-grade`,
`production custody`, or equivalent to a hardware wallet while the installed
application PE lacks its own verified Authenticode signature. The provenance
attestation later in the workflow proves source/workflow provenance only; it
does not change this classification.

The desktop publish job treats a missing `RELEASE_CUSTODY_CLASS` repository
variable as `standard-outer-signed` and accepts only that exact value. Any
attempt to set another class, including a high-value or production-custody
class, fails before provenance attestation and publication.

The required production-custody remediation is:

1. move the Windows private key to a non-exportable remote signing service or
   HSM;
2. invoke that signer through Tauri's custom sign command after Tauri patches
   the app PE and before it is embedded, while retaining isolated policy and
   reviewer approval;
3. restrict the signer identity to the protected repository, tag, publisher,
   and approved release policy; and
4. extract or sandbox-install both MSI and NSIS outputs and verify that the
   installed app PE and both outer installers chain to the exact public
   certificate fingerprint.

Only after all four gates pass may a release use a high-value custody claim.

For the strongest production setup, keep the private key non-exportable in a
managed signing service or HSM and replace the PFX-based inline signer with a
service call that preserves the same fingerprint and post-signing gates. A
base64 PFX in GitHub Secrets is encrypted at rest but remains exportable to the
approved signing runner, so it is not equivalent to an HSM.

Never commit or upload the PFX as a workflow artifact. Rotate a certificate only
through a reviewed wallet release that deliberately pins the successor before
the old signer expires.

## Android signing gate

Configure these `release-signing` Environment secrets:

- `ANDROID_KEYSTORE_BASE64`
- `ANDROID_KEYSTORE_PASSWORD`
- `ANDROID_KEY_ALIAS`

Configure this public repository Actions variable:

- `ANDROID_EXPECTED_CERT_SHA256`

The Android build job does not receive any of those three secrets. After the
tracked Android integration checks pass, it removes the generated Gradle release
signing block, proves that no keystore configuration remains, and compiles one
unsigned release APK. Before upload it requires a valid APK/ZIP, an unsigned
package, package id `org.hacash.wallet.mobile`, the synchronized version name
and code, SDK 28/36, and exactly the `arm64-v8a` ABI. A SHA-256 manifest binds
the unsigned input passed between jobs.

The protected Android job installs only the pinned Android signing tools before
the private values are provided. It rechecks the exact input set, unsigned
SHA-256, magic, ZIP integrity, unsigned state, package, version, SDK, and ABI.
The one inline secret-bearing step reconstructs the keystore in the runner
temporary directory, zip-aligns the APK, signs it with `apksigner`, and requires
one signer whose SHA-256 fingerprint matches the public repository variable. It
also requires Android signing scheme v2 or v3 and repeats the package, version,
SDK, ABI, magic, and ZIP checks before creating the final checksum manifest.
Temporary keystore and aligned files are removed by an exit trap.

Do not print, upload as a build artifact, or commit the keystore or password. A
missing or mismatched secret blocks only the protected signing job; compilation
does not need access to private signing material.

## Build provenance

After the complete artifact set and checksums pass, both release workflows create
GitHub/Sigstore build-provenance attestations before publishing. Verify a
downloaded artifact against this repository with:

```text
gh attestation verify PATH_TO_ARTIFACT -R Moskyera/hacash-wallet
```

An attestation proves which workflow and source commit produced a file. It does
not replace Authenticode, the Android package signer, or checksum verification.

It is not a claim that the wallet is hardware-grade, suitable for high-value
custody, or independently security audited.

## Supported v1.0.0 artifacts

- Windows 10/11 x64: NSIS, MSI, portable executable
- Linux x64: deb, AppImage, raw binary with runtime dependencies
- Android 9+ arm64: signed APK

Windows ARM64, Linux ARM64, Android x86/x86_64, and iOS are not release targets
in v1.0.0 and must not be advertised as built or tested artifacts.

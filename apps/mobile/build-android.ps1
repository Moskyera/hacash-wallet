# Build Hacash Wallet Android APK (Tauri 2)
$ErrorActionPreference = "Stop"
$mobile = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $mobile

$sdk = Join-Path $env:LOCALAPPDATA "Android\Sdk"
$ndkVersion = "27.2.12479018"
$ndkHome = Join-Path $sdk "ndk\$ndkVersion"
$studioJbr = "C:\Program Files\Android\Android Studio\jbr"

function Ensure-AndroidEnv {
    if (-not (Test-Path (Join-Path $sdk "cmdline-tools\latest\bin\sdkmanager.bat"))) {
        Write-Host "Bootstrapping Android SDK (first time)..." -ForegroundColor Cyan
        & (Join-Path $mobile "setup-android.ps1")
    }
    if (-not (Test-Path (Join-Path $ndkHome "source.properties"))) {
        Write-Host "NDK missing at $ndkHome - re-run setup-android.ps1" -ForegroundColor Red
        exit 1
    }
    $env:ANDROID_HOME = $sdk
    $env:ANDROID_SDK_ROOT = $sdk
    $env:NDK_HOME = $ndkHome.Trim()
    if (Test-Path $studioJbr) { $env:JAVA_HOME = $studioJbr }
    $env:PATH = "$env:JAVA_HOME\bin;$env:PATH"
}

Ensure-AndroidEnv

Write-Host "Installing JS dependencies..." -ForegroundColor Cyan
yarn install --frozen-lockfile --non-interactive
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

if (-not (Test-Path "$mobile\src-tauri\gen\android")) {
    Write-Host "Initializing Android project..." -ForegroundColor Cyan
    yarn tauri android init
    if ($LASTEXITCODE -ne 0) { exit 1 }
}

Write-Host "Building frontend..." -ForegroundColor Cyan
yarn build
if ($LASTEXITCODE -ne 0) { exit 1 }

Write-Host "Merging Android permissions..." -ForegroundColor Cyan
& (Join-Path $mobile "merge-android-permissions.ps1")

$keystore = Join-Path $mobile "src-tauri\hacash-wallet-release.jks"
$props = Join-Path $mobile "src-tauri\gen\android\keystore.properties"
if (-not (Test-Path $keystore) -or -not (Test-Path $props)) {
    throw "Release signing material is missing. Run create-android-keystore.ps1 first; unsigned release APKs are forbidden."
}
if ([string]::IsNullOrWhiteSpace($env:ANDROID_EXPECTED_CERT_SHA256)) {
    throw "ANDROID_EXPECTED_CERT_SHA256 is required to prevent accidental release-key changes."
}

Write-Host "Applying Android signing + network patches..." -ForegroundColor Cyan
& (Join-Path $mobile "apply-android-patches.ps1")

Write-Host "Building Android APK (aarch64)..." -ForegroundColor Cyan
Write-Host "Windows uses a verified copy fallback when Developer Mode symlinks are unavailable." -ForegroundColor Yellow
$apkOutput = Join-Path $mobile "src-tauri\gen\android\app\build\outputs\apk"
if (Test-Path -LiteralPath $apkOutput) {
    @(
        Get-ChildItem -LiteralPath $apkOutput -Recurse -File -Filter "*.apk" |
            Where-Object { $_.FullName -match '[\\/]release[\\/]' }
    ) | ForEach-Object { Remove-Item -LiteralPath $_.FullName -Force }
}
$previousErrorAction = $ErrorActionPreference
$ErrorActionPreference = "Continue"
try {
    $tauriOutput = @(yarn tauri android build --ci --target aarch64 --apk -c tauri.android.build.conf.json -- --locked 2>&1)
    $tauriExit = $LASTEXITCODE
} finally {
    $ErrorActionPreference = $previousErrorAction
}
$tauriOutput | ForEach-Object { Write-Host $_ }
if ($tauriExit -ne 0) {
    $tauriText = $tauriOutput -join "`n"
    if ($env:OS -ne "Windows_NT" -or $tauriText -notmatch 'Creation symbolic link is not allowed') {
        throw "Tauri Android build failed with exit code $tauriExit"
    }

    Write-Host "Developer Mode symlink unavailable; finishing the verified arm64 build with a file copy." -ForegroundColor Yellow
    $nativeLib = Join-Path $mobile "..\..\target\aarch64-linux-android\release\libhacash_wallet_mobile_lib.so"
    if (-not (Test-Path -LiteralPath $nativeLib -PathType Leaf)) {
        throw "Tauri built no arm64 native library for the safe copy fallback"
    }
    $jniDir = Join-Path $mobile "src-tauri\gen\android\app\src\main\jniLibs\arm64-v8a"
    New-Item -ItemType Directory -Path $jniDir -Force | Out-Null
    Copy-Item -LiteralPath $nativeLib -Destination (Join-Path $jniDir "libhacash_wallet_mobile_lib.so") -Force

    $gradleRoot = Join-Path $mobile "src-tauri\gen\android"
    Push-Location $gradleRoot
    try {
        & .\gradlew.bat assembleUniversalRelease --no-daemon
        if ($LASTEXITCODE -ne 0) { throw "Gradle release build failed" }
    } finally {
        Pop-Location
    }
}

# Tauri regenerates its auxiliary Gradle files during `android build`.
# Revalidate the final generated project before trusting any APK output.
& (Join-Path $mobile "validate-android-build.ps1")
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

$releaseApks = @(
    Get-ChildItem -LiteralPath $apkOutput -Recurse -File -Filter "*.apk" |
        Where-Object { $_.FullName -match '[\\/]release[\\/]' }
)
if ($releaseApks.Count -ne 1) {
    throw "Expected exactly one release APK, found $($releaseApks.Count)"
}
$expectedApk = $releaseApks[0].FullName
& (Join-Path $mobile "verify-release-apk.ps1") -ApkPath $expectedApk
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

$apk = Get-Item -LiteralPath $expectedApk
Write-Host "APK: $($apk.FullName)" -ForegroundColor Green
Write-Host "Size: $([math]::Round($apk.Length / 1MB, 1)) MB (signed, verified arm64 release APK)" -ForegroundColor Yellow

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
yarn install --frozen-lockfile 2>$null
if ($LASTEXITCODE -ne 0) { yarn install }

if (-not (Test-Path "$mobile\src-tauri\gen\android")) {
    Write-Host "Initializing Android project..." -ForegroundColor Cyan
    yarn tauri android init
    if ($LASTEXITCODE -ne 0) { exit 1 }
}

Write-Host "Merging Android permissions..." -ForegroundColor Cyan
& (Join-Path $mobile "merge-android-permissions.ps1")

$keystore = Join-Path $mobile "src-tauri\hacash-wallet-release.jks"
$props = Join-Path $mobile "src-tauri\gen\android\keystore.properties"
if (-not (Test-Path $keystore) -or -not (Test-Path $props)) {
    Write-Host "Keystore missing - run .\create-android-keystore.ps1 first (or set ANDROID_KEYSTORE_PASSWORD)." -ForegroundColor Yellow
    if ($env:ANDROID_KEYSTORE_PASSWORD) {
        & (Join-Path $mobile "create-android-keystore.ps1")
    } else {
        Write-Host "Building unsigned APK. For signed release, create keystore first." -ForegroundColor Yellow
    }
}

Write-Host "Applying Android signing + network patches..." -ForegroundColor Cyan
& (Join-Path $mobile "apply-android-patches.ps1")

Write-Host "Building frontend..." -ForegroundColor Cyan
yarn build
if ($LASTEXITCODE -ne 0) { exit 1 }

Write-Host "Building Android APK (aarch64)..." -ForegroundColor Cyan
Write-Host "Tip: enable Windows Developer Mode if symlink errors occur." -ForegroundColor Yellow
yarn tauri android build --target aarch64 --apk -c tauri.android.build.conf.json
if ($LASTEXITCODE -ne 0) { exit 1 }

$apk = Get-ChildItem -Path "$mobile\src-tauri\gen\android\app\build\outputs\apk" -Recurse -Filter "*.apk" -ErrorAction SilentlyContinue |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 1
if ($apk) {
    Write-Host "APK: $($apk.FullName)" -ForegroundColor Green
    Write-Host "Size: $([math]::Round($apk.Length / 1MB, 1)) MB (signed release APK)" -ForegroundColor Yellow
} else {
    Write-Host "Build finished but no APK found under gen/android/app/build/outputs/apk" -ForegroundColor Yellow
}
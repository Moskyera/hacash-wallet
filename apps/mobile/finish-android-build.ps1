# Finish Android APK when Tauri symlink step fails (no Developer Mode).
$ErrorActionPreference = "Stop"
$mobile = Split-Path -Parent $MyInvocation.MyCommand.Path
$android = Join-Path $mobile "src-tauri\gen\android"
$assets = Join-Path $android "app\src\main\assets"
$dist = Join-Path $mobile "dist"
$jniDir = Join-Path $android "app\src\main\jniLibs\arm64-v8a"
$libSrc = Join-Path $mobile "..\..\target\aarch64-linux-android\release\libhacash_wallet_mobile_lib.so"
$libDst = Join-Path $jniDir "libhacash_wallet_mobile_lib.so"

$sdk = Join-Path $env:LOCALAPPDATA "Android\Sdk"
$ndkHome = Join-Path $sdk "ndk\27.2.12479018"
$studioJbr = "C:\Program Files\Android\Android Studio\jbr"
$env:ANDROID_HOME = $sdk
$env:ANDROID_SDK_ROOT = $sdk
$env:NDK_HOME = $ndkHome
if (Test-Path $studioJbr) { $env:JAVA_HOME = $studioJbr }
$env:PATH = "$env:JAVA_HOME\bin;$env:PATH"

if (-not (Test-Path $libSrc)) {
    throw "Native library missing: $libSrc. Run cargo android build first."
}

Write-Host "Syncing frontend dist -> Android assets..." -ForegroundColor Cyan
if (-not (Test-Path $dist)) { throw "dist/ missing. Run: yarn build" }
Get-ChildItem $assets -Exclude "tauri.conf.json" | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
Copy-Item (Join-Path $dist "*") $assets -Recurse -Force

Write-Host "Copying native library (symlink workaround)..." -ForegroundColor Cyan
New-Item -ItemType Directory -Path $jniDir -Force | Out-Null
Copy-Item $libSrc $libDst -Force

Write-Host "Applying Android patches..." -ForegroundColor Cyan
& (Join-Path $mobile "apply-android-patches.ps1")
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "Running Gradle assembleUniversalRelease..." -ForegroundColor Cyan
Push-Location $android
try {
    & .\gradlew.bat assembleUniversalRelease --no-daemon
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
} finally {
    Pop-Location
}

$apk = Get-ChildItem -Path (Join-Path $android "app\build\outputs\apk") -Recurse -Filter "*.apk" |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 1
if ($apk) {
    Write-Host "APK: $($apk.FullName)" -ForegroundColor Green
    Write-Host "Size: $([math]::Round($apk.Length / 1MB, 1)) MB" -ForegroundColor Yellow
} else {
    throw "Gradle finished but no APK found."
}
# One-time Android SDK bootstrap for Tauri 2 (Windows)
# Installs cmdline-tools + NDK, sets env vars, adds Rust targets.
$ErrorActionPreference = "Stop"

$sdk = Join-Path $env:LOCALAPPDATA "Android\Sdk"
$cmdlineRoot = Join-Path $sdk "cmdline-tools"
$cmdlineLatest = Join-Path $cmdlineRoot "latest"
$sdkmanager = Join-Path $cmdlineLatest "bin\sdkmanager.bat"
$studioJbr = "C:\Program Files\Android\Android Studio\jbr"

Write-Host "Android SDK: $sdk" -ForegroundColor Cyan

if (-not (Test-Path $sdk)) {
    New-Item -ItemType Directory -Path $sdk -Force | Out-Null
}

$needsCmdlineTools = -not (Test-Path $sdkmanager)
if ($needsCmdlineTools -and (Test-Path $cmdlineRoot)) {
    Write-Host "Repairing incomplete cmdline-tools install..." -ForegroundColor Yellow
    Remove-Item $cmdlineRoot -Recurse -Force
}

if ($needsCmdlineTools) {
    Write-Host "Installing Android SDK Command-line Tools..." -ForegroundColor Cyan
    $zipUrl = "https://dl.google.com/android/repository/commandlinetools-win-14742923_latest.zip"
    $zipPath = Join-Path $env:TEMP ("commandlinetools-win-" + [guid]::NewGuid().ToString("n") + ".zip")
    Invoke-WebRequest -Uri $zipUrl -OutFile $zipPath -UseBasicParsing
    $extractDir = Join-Path $env:TEMP "cmdline-tools-extract"
    if (Test-Path $extractDir) { Remove-Item $extractDir -Recurse -Force }
    Expand-Archive -Path $zipPath -DestinationPath $extractDir -Force
    if (Test-Path $cmdlineRoot) { Remove-Item $cmdlineRoot -Recurse -Force }
    New-Item -ItemType Directory -Path $cmdlineRoot -Force | Out-Null
    # Zip contains a single "cmdline-tools" folder — move its contents to .../latest/
    Move-Item (Join-Path $extractDir "cmdline-tools\*") $cmdlineLatest
    # Newer zips place *.bat at latest/ root; Android expects latest/bin/
    $binDir = Join-Path $cmdlineLatest "bin"
    if (-not (Test-Path $binDir)) { New-Item -ItemType Directory -Path $binDir -Force | Out-Null }
    Get-ChildItem $cmdlineLatest -Filter "*.bat" -ErrorAction SilentlyContinue |
        Move-Item -Destination $binDir -Force
    Remove-Item $zipPath -Force -ErrorAction SilentlyContinue
    Remove-Item $extractDir -Recurse -Force -ErrorAction SilentlyContinue
}

if (-not (Test-Path $sdkmanager)) {
    throw "sdkmanager not found at $sdkmanager"
}

if (Test-Path $studioJbr) {
    $env:JAVA_HOME = $studioJbr
    [System.Environment]::SetEnvironmentVariable("JAVA_HOME", $studioJbr, "User")
    Write-Host "JAVA_HOME -> $studioJbr" -ForegroundColor Green
}

$env:ANDROID_HOME = $sdk
$env:ANDROID_SDK_ROOT = $sdk
[System.Environment]::SetEnvironmentVariable("ANDROID_HOME", $sdk, "User")
[System.Environment]::SetEnvironmentVariable("ANDROID_SDK_ROOT", $sdk, "User")

Write-Host "Accepting SDK licenses..." -ForegroundColor Cyan
$yes = ("y`n" * 200)
$prevEap = $ErrorActionPreference
$ErrorActionPreference = "Continue"
$yes | & $sdkmanager --licenses 2>&1 | Out-Null
$ErrorActionPreference = $prevEap

Write-Host "Installing NDK + Android packages..." -ForegroundColor Cyan
$ErrorActionPreference = "Continue"
& $sdkmanager --install `
    "platform-tools" `
    "ndk;27.2.12479018" `
    "platforms;android-34" `
    "build-tools;34.0.0" `
    "cmake;3.22.1"
$installExit = $LASTEXITCODE
$ErrorActionPreference = $prevEap
if ($installExit -ne 0) {
    Write-Host "Retrying with latest NDK tag..." -ForegroundColor Yellow
    $ErrorActionPreference = "Continue"
    & $sdkmanager --install "ndk;latest" "platform-tools" "platforms;android-34" "build-tools;34.0.0"
    $ErrorActionPreference = $prevEap
}

$ndkDir = Get-ChildItem (Join-Path $sdk "ndk") -Directory -ErrorAction SilentlyContinue |
    Sort-Object Name -Descending |
    Select-Object -First 1
if (-not $ndkDir) {
    throw "NDK installation failed. Check sdkmanager output above."
}
$ndkHome = $ndkDir.FullName
$env:NDK_HOME = $ndkHome
[System.Environment]::SetEnvironmentVariable("NDK_HOME", $ndkHome, "User")
Write-Host "NDK_HOME -> $ndkHome" -ForegroundColor Green

Write-Host "Adding Rust Android targets..." -ForegroundColor Cyan
rustup target add aarch64-linux-android armv7-linux-androideabi i686-linux-android x86_64-linux-android
if ($LASTEXITCODE -ne 0) { throw "rustup target add failed" }

if (-not (Test-Path $sdkmanager)) { throw "sdkmanager still missing after install." }
if (-not (Test-Path (Join-Path $ndkHome "source.properties"))) { throw "NDK still missing after install." }

Write-Host "Android SDK bootstrap complete." -ForegroundColor Green
Write-Host "  sdkmanager: $sdkmanager"
Write-Host "  NDK_HOME:   $ndkHome"
Write-Host "Restart terminal or run:" -ForegroundColor Yellow
Write-Host 'Refresh env: Get-ChildItem Env: from User scope in a new terminal.'
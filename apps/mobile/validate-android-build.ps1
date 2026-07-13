# Fail the release build if generated Android project is missing required pieces.
$ErrorActionPreference = "Stop"
$mobile = Split-Path -Parent $MyInvocation.MyCommand.Path
$android = Join-Path $mobile "src-tauri\gen\android"
$manifest = Join-Path $android "app\src\main\AndroidManifest.xml"
$settingsGradle = Join-Path $android "tauri.settings.gradle"
$tauriBuildGradle = Join-Path $android "app\tauri.build.gradle.kts"
$tauriProps = Join-Path $android "app\tauri.properties"
$pkgJson = Join-Path $mobile "package.json"
$proguard = Join-Path $android "app\proguard-rules.pro"

$errors = @()

if (-not (Test-Path $manifest)) {
    $errors += "Missing AndroidManifest.xml - run: yarn tauri android init"
}

if (Test-Path $manifest) {
    $mc = Get-Content $manifest -Raw
    $providerCount = ([regex]::Matches($mc, 'android:name="androidx\.core\.content\.FileProvider"')).Count
    if ($providerCount -ne 1) {
        $errors += "AndroidManifest must contain exactly one FileProvider (found $providerCount)"
    }
}

$requiredPlugins = @(
    "tauri-plugin-biometric",
    "tauri-plugin-deep-link",
    "tauri-plugin-opener"
)
foreach ($plugin in $requiredPlugins) {
    if ((Test-Path $settingsGradle) -and -not (Select-String -Path $settingsGradle -Pattern $plugin -Quiet)) {
        $errors += "tauri.settings.gradle missing $plugin"
    }
    if ((Test-Path $tauriBuildGradle) -and -not (Select-String -Path $tauriBuildGradle -Pattern $plugin -Quiet)) {
        $errors += "tauri.build.gradle.kts missing $plugin"
    }
}

if ((Test-Path $pkgJson) -and (Test-Path $tauriProps)) {
    $ver = (Get-Content $pkgJson -Raw | ConvertFrom-Json).version
    $props = Get-Content $tauriProps -Raw
    if ($props -notmatch "tauri\.android\.versionName=$([regex]::Escape($ver))") {
        $errors += "tauri.properties versionName does not match package.json ($ver)"
    }
    $parts = $ver.Split(".")
    if ($parts.Length -ge 3) {
        $expectedCode = ([int]$parts[0] * 10000) + ([int]$parts[1] * 100) + [int]$parts[2]
        if ($props -notmatch "tauri\.android\.versionCode=$expectedCode") {
            $errors += "tauri.properties versionCode expected $expectedCode for $ver"
        }
    }
}

$filePaths = Join-Path $android "app\src\main\res\xml\file_paths.xml"
if (Test-Path $filePaths) {
    $fp = Get-Content $filePaths -Raw
    if ($fp -notmatch 'cache-path[^>]*name="cache_updates"') {
        $errors += "file_paths.xml must expose cache-path for in-app APK updates"
    }
}

if (Test-Path $proguard) {
    $pg = Get-Content $proguard -Raw
    foreach ($keep in @("ApkInstaller", "BackupFileHelper", "BackupExportHelper", "app.tauri.opener.OpenerPlugin", "app.tauri.deep_link", "app.tauri.biometric")) {
        if ($pg -notmatch [regex]::Escape($keep)) {
            $errors += "proguard-rules.pro missing keep rule for $keep"
        }
    }
}

if ($errors.Count -gt 0) {
    Write-Host "Android build validation FAILED:" -ForegroundColor Red
    $errors | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }
    exit 1
}

Write-Host "Android build validation OK" -ForegroundColor Green
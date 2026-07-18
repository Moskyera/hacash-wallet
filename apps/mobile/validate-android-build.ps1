# Fail the release build if generated Android project is missing required pieces.
$ErrorActionPreference = "Stop"
$mobile = Split-Path -Parent $MyInvocation.MyCommand.Path
$android = Join-Path $mobile "src-tauri\gen\android"
$manifest = Join-Path $android "app\src\main\AndroidManifest.xml"
$settingsGradle = Join-Path $android "tauri.settings.gradle"
$appGradle = Join-Path $android "app\build.gradle.kts"
$tauriBuildGradle = Join-Path $android "app\tauri.build.gradle.kts"
$tauriProps = Join-Path $android "app\tauri.properties"
$pkgJson = Join-Path $mobile "package.json"
$proguard = Join-Path $android "app\proguard-rules.pro"
$handlerInventory = Join-Path $mobile "..\..\crates\wallet-tauri-common\src\handlers.rs"
$mobileLib = Join-Path $mobile "src-tauri\src\lib.rs"
$mobileCargo = Join-Path $mobile "src-tauri\Cargo.toml"
$commonCargo = Join-Path $mobile "..\..\crates\wallet-tauri-common\Cargo.toml"
$commonRust = Join-Path $mobile "..\..\crates\wallet-tauri-common\src"
$mobileRust = Join-Path $mobile "src-tauri\src"
$nativePluginSource = Join-Path $mobile "src-tauri\android-src\org\hacash\wallet\mobile\WalletNativePlugin.kt"
$nativePluginGenerated = Join-Path $android "app\src\main\java\org\hacash\wallet\mobile\WalletNativePlugin.kt"
$biometricStoreSource = Join-Path $mobile "src-tauri\android-src\org\hacash\wallet\mobile\BiometricSecretStore.kt"
$backupExportSource = Join-Path $mobile "src-tauri\android-src\org\hacash\wallet\mobile\BackupExportHelper.kt"
$androidPermissions = Join-Path $mobile "src-tauri\android-permissions.xml"
$mobileCapability = Join-Path $mobile "src-tauri\capabilities\mobile.json"
$walletPermissions = Join-Path $mobile "src-tauri\permissions\wallet.toml"
$dataExtractionRules = Join-Path $android "app\src\main\res\xml\data_extraction_rules.xml"
$legacyBackupRules = Join-Path $android "app\src\main\res\xml\backup_rules.xml"
$backupDomains = @(
    "root", "file", "database", "sharedpref", "external",
    "device_root", "device_file", "device_database", "device_sharedpref"
)

$errors = @()

if (-not (Test-Path $manifest)) {
    $errors += "Missing AndroidManifest.xml - run: yarn tauri android init"
}

if (Test-Path $manifest) {
    $mc = Get-Content $manifest -Raw
    if ($mc -notmatch "<queries>") {
        $errors += "AndroidManifest must declare <queries> for APK installer visibility (API 30+)"
    }
    $legacyStoragePermissionCount = ([regex]::Matches(
        $mc,
        'android:name="android\.permission\.WRITE_EXTERNAL_STORAGE"'
    )).Count
    $scopedLegacyStoragePermissionCount = ([regex]::Matches(
        $mc,
        '<uses-permission\s+android:name="android\.permission\.WRITE_EXTERNAL_STORAGE"\s+android:maxSdkVersion="28"\s*/>'
    )).Count
    if ($legacyStoragePermissionCount -ne 1 -or $scopedLegacyStoragePermissionCount -ne 1) {
        $errors += "Android 9 backup export requires exactly one WRITE_EXTERNAL_STORAGE permission capped with maxSdkVersion=28"
    }
}

if (Test-Path $androidPermissions) {
    $permissionTemplate = Get-Content $androidPermissions -Raw
    if ($permissionTemplate -notmatch 'android:name="android\.permission\.WRITE_EXTERNAL_STORAGE"\s+android:maxSdkVersion="28"') {
        $errors += "android-permissions.xml must cap WRITE_EXTERNAL_STORAGE to Android 9"
    }
}

if ((Test-Path $mobileCapability) -and
    (Select-String -Path $mobileCapability -Pattern 'biometric:default' -Quiet)) {
    $errors += "Android capability must not reference the removed upstream biometric plugin"
}

if (Test-Path $manifest) {
    $mc = Get-Content $manifest -Raw
    $providerCount = ([regex]::Matches($mc, 'android:name="androidx\.core\.content\.FileProvider"')).Count
    if ($providerCount -ne 1) {
        $errors += "AndroidManifest must contain exactly one FileProvider (found $providerCount)"
    }

    foreach ($requiredAttribute in @(
        'android:allowBackup="false"',
        'android:fullBackupContent="@xml/backup_rules"',
        'android:dataExtractionRules="@xml/data_extraction_rules"'
    )) {
        $count = ([regex]::Matches($mc, [regex]::Escape($requiredAttribute))).Count
        if ($count -ne 1) {
            $errors += "AndroidManifest must contain exactly one $requiredAttribute"
        }
    }
}

function Test-BackupExclusions([string] $path, [string[]] $sections, [string] $label) {
    if (-not (Test-Path $path)) {
        $script:errors += "Missing $label backup exclusion file: $path"
        return
    }

    try {
        [xml] $rules = Get-Content $path -Raw
    } catch {
        $script:errors += "$label backup exclusion XML is invalid: $($_.Exception.Message)"
        return
    }

    foreach ($section in $sections) {
        $nodes = @($rules.SelectNodes($section))
        $domains = @($nodes | ForEach-Object { $_.GetAttribute("domain") })
        $invalidPaths = @($nodes | Where-Object { $_.GetAttribute("path") -ne "." })
        $missing = @($script:backupDomains | Where-Object { $_ -notin $domains })
        $unexpected = @($domains | Where-Object { $_ -notin $script:backupDomains })
        $duplicates = @($domains | Group-Object | Where-Object Count -ne 1)
        if ($nodes.Count -ne $script:backupDomains.Count -or
            $invalidPaths.Count -gt 0 -or
            $missing.Count -gt 0 -or
            $unexpected.Count -gt 0 -or
            $duplicates.Count -gt 0) {
            $script:errors += "$label must exclude path . exactly once for every Android app-data domain in $section"
        }
    }
}

Test-BackupExclusions $dataExtractionRules @(
    "/data-extraction-rules/cloud-backup/exclude",
    "/data-extraction-rules/device-transfer/exclude"
) "Android 12+ cloud/device-transfer"
Test-BackupExclusions $legacyBackupRules @(
    "/full-backup-content/exclude"
) "Android 6-11 legacy"

if (Test-Path $appGradle) {
    $gradleContent = Get-Content $appGradle -Raw
    $compileSdkLines = ([regex]::Matches($gradleContent, '(?m)^\s*compileSdk\s*=\s*\d+\s*$')).Count
    $androidBlocks = ([regex]::Matches($gradleContent, '(?m)^android\s*\{')).Count
    $signingBlocks = ([regex]::Matches($gradleContent, '(?m)^\s*signingConfigs\s*\{')).Count
    $releaseSigningLinks = ([regex]::Matches(
        $gradleContent,
        'signingConfig\s*=\s*signingConfigs\.getByName\("release"\)'
    )).Count
    if ($androidBlocks -ne 1) {
        $errors += "build.gradle.kts must contain exactly one android block (found $androidBlocks)"
    }
    if ($compileSdkLines -ne 1) {
        $errors += "build.gradle.kts must contain one standalone numeric compileSdk assignment (found $compileSdkLines)"
    }
    if ($signingBlocks -ne 1) {
        $errors += "build.gradle.kts must contain exactly one release signing configuration"
    }
    if ($releaseSigningLinks -ne 1) {
        $errors += "release build must reference exactly one release signing configuration"
    }
    $biometricDependencyCount = ([regex]::Matches(
        $gradleContent,
        'implementation\("androidx\.biometric:biometric:1\.1\.0"\)'
    )).Count
    if ($biometricDependencyCount -ne 1) {
        $errors += "persistent app/build.gradle.kts must contain exactly one wallet-native AndroidX biometric dependency"
    }
}

$requiredPlugins = @(
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
foreach ($generatedPluginFile in @($settingsGradle, $tauriBuildGradle)) {
    if ((Test-Path $generatedPluginFile) -and
        (Select-String -Path $generatedPluginFile -Pattern 'tauri-plugin-biometric' -Quiet)) {
        $errors += "Android must not link the weak-auth tauri biometric plugin: $generatedPluginFile"
    }
}
if ((Test-Path $tauriBuildGradle) -and
    (Select-String -Path $tauriBuildGradle -Pattern 'androidx.biometric:biometric' -Quiet)) {
    $errors += "wallet-native AndroidX biometric dependency must not live in regenerated tauri.build.gradle.kts"
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
    if ($fp -notmatch 'cache-path[^>]*name="verified_updates"[^>]*path="updates/"') {
        $errors += "file_paths.xml must expose only the verified updater cache"
    }
    if ($fp -match '<external-path|<external-cache-path|path="\."') {
        $errors += "file_paths.xml exposes a path broader than cache/updates"
    }
}

$networkConfig = Join-Path $android "app\src\main\res\xml\network_security_config.xml"
if (Test-Path $networkConfig) {
    $net = Get-Content $networkConfig -Raw
    $allowedDomains = @("nodeapi.hacash.org", "localhost", "127.0.0.1")
    $strictDomains = [regex]::Matches($net, '<domain\s+includeSubdomains="false">([^<]+)</domain>')
    $allDomainTags = [regex]::Matches($net, '<domain\b[^>]*>[^<]+</domain>')
    $declaredDomains = @($strictDomains | ForEach-Object { $_.Groups[1].Value })
    $unexpectedDomains = @($declaredDomains | Where-Object { $_ -notin $allowedDomains })
    $missingDomains = @($allowedDomains | Where-Object { $_ -notin $declaredDomains })

    if ($net -notmatch '<base-config cleartextTrafficPermitted="false"' -or
        $net -notmatch '<certificates src="system" />' -or
        $net -match '<certificates\s+src="user"' -or
        $allDomainTags.Count -ne $strictDomains.Count -or
        $declaredDomains.Count -ne $allowedDomains.Count -or
        $unexpectedDomains.Count -gt 0 -or
        $missingDomains.Count -gt 0) {
        $errors += "network security must trust system CAs only and allow cleartext only for the exact approved node/local hosts"
    }
}

if (Test-Path $proguard) {
    $pg = Get-Content $proguard -Raw
    foreach ($keep in @("WalletNativePlugin", "ApkInstaller", "BiometricSecretStore", "BackupFileHelper", "BackupExportHelper", "app.tauri.opener.OpenerPlugin", "app.tauri.deep_link")) {
        if ($pg -notmatch [regex]::Escape($keep)) {
            $errors += "proguard-rules.pro missing keep rule for $keep"
        }
    }
}

foreach ($pluginFile in @($nativePluginSource, $nativePluginGenerated)) {
    if (-not (Test-Path $pluginFile)) {
        $errors += "Missing wallet-native Tauri Android plugin: $pluginFile"
    }
}

if (Test-Path $nativePluginSource) {
    $nativePlugin = Get-Content $nativePluginSource -Raw
    foreach ($permissionContract in @(
        'Manifest.permission.WRITE_EXTERNAL_STORAGE',
        'requestPermissionForAlias(',
        '@PermissionCallback',
        'fun copyBackupPermissionResult(',
        'getPermissionState(BACKUP_DOWNLOADS_PERMISSION)'
    )) {
        if ($nativePlugin -notmatch [regex]::Escape($permissionContract)) {
            $errors += "WalletNativePlugin missing Android 9 backup permission contract: $permissionContract"
        }
    }
}

if (Test-Path $biometricStoreSource) {
    $biometricStore = Get-Content $biometricStoreSource -Raw
    if ($biometricStore -match '\.apply\(\)' -or
        ([regex]::Matches($biometricStore, '\.commit\(\)')).Count -lt 2) {
        $errors += "Biometric secret store must durably commit both save and clear operations off the UI thread"
    }
}

if (Test-Path $backupExportSource) {
    $backupExport = Get-Content $backupExportSource -Raw
    foreach ($filenameGuard in @(
        'displayName.length > 128',
        'File(displayName).name != displayName',
        "it == '/'",
        'it.code == 92',
        'it.isISOControl()'
    )) {
        if ($backupExport -notmatch [regex]::Escape($filenameGuard)) {
            $errors += "Backup export filename validation missing: $filenameGuard"
        }
    }
}

if ((Test-Path $mobileLib) -and
    -not (Select-String -Path $mobileLib -Pattern 'android_native::init\(\)' -Quiet)) {
    $errors += "Mobile builder must register the wallet-native plugin on Android"
}

foreach ($manifestPath in @($mobileCargo, $commonCargo)) {
    if ((Test-Path $manifestPath) -and
        (Select-String -Path $manifestPath -Pattern '^\s*(jni|ndk-context)\s*=' -Quiet)) {
        $errors += "Direct JNI/ndk-context dependency is forbidden: $manifestPath"
    }
}

foreach ($rustRoot in @($mobileRust, $commonRust)) {
    if (Test-Path $rustRoot) {
        $legacyNativeCalls = @(Get-ChildItem -Path $rustRoot -Recurse -Filter "*.rs" |
            Select-String -Pattern 'ndk_context::|jni::')
        if ($legacyNativeCalls.Count -gt 0) {
            $errors += "Rust Android native calls must use the managed Tauri plugin, not direct JNI/ndk-context"
        }
    }
}

function Get-RegisteredCommandNames([string] $source, [string] $pattern, [string] $label) {
    $match = [regex]::Match($source, $pattern)
    if (-not $match.Success) {
        $script:errors += "Unable to parse $label command inventory"
        return @()
    }

    return @([regex]::Matches(
        $match.Groups["commands"].Value,
        '(?m)^\s*(?:[A-Za-z_][A-Za-z0-9_]*::)*(?<command>[A-Za-z_][A-Za-z0-9_]*)\s*,?\s*$'
    ) | ForEach-Object { $_.Groups["command"].Value })
}

if ((Test-Path $handlerInventory) -and (Test-Path $mobileLib) -and (Test-Path $walletPermissions)) {
    $sharedSource = Get-Content $handlerInventory -Raw
    $mobileSource = Get-Content $mobileLib -Raw
    $permissionSource = Get-Content $walletPermissions -Raw

    $registered = @(
        Get-RegisteredCommandNames $sharedSource '(?s)tauri::generate_handler!\s*\[(?<commands>.*?)\]' "shared"
        Get-RegisteredCommandNames $mobileSource '(?s)\.invoke_handler\s*\(\s*wallet_tauri_common::wallet_invoke_handler!\s*\[(?<commands>.*?)\]\s*\)' "mobile"
    ) | Sort-Object -Unique

    $permissionMatch = [regex]::Match(
        $permissionSource,
        '(?s)\[\[permission\]\]\s*identifier\s*=\s*"allow-main-wallet"(?<body>.*?)(?=\r?\n\[\[permission\]\]|\z)'
    )
    if (-not $permissionMatch.Success) {
        $errors += "Unable to parse allow-main-wallet permission"
    } else {
        $allowMatch = [regex]::Match($permissionMatch.Groups["body"].Value, '(?s)commands\.allow\s*=\s*\[(?<commands>.*?)\]')
        if (-not $allowMatch.Success) {
            $errors += "Unable to parse allow-main-wallet command list"
        } else {
            $allowed = @([regex]::Matches($allowMatch.Groups["commands"].Value, '"(?<command>[A-Za-z_][A-Za-z0-9_]*)"') |
                ForEach-Object { $_.Groups["command"].Value })
            $duplicates = @($allowed | Group-Object | Where-Object Count -gt 1 | ForEach-Object Name)
            $missing = @($registered | Where-Object { $_ -notin $allowed })
            $stale = @($allowed | Where-Object { $_ -notin $registered })

            if ($duplicates.Count -gt 0) {
                $errors += "allow-main-wallet contains duplicate commands: $($duplicates -join ', ')"
            }
            if ($missing.Count -gt 0) {
                $errors += "allow-main-wallet is missing registered commands: $($missing -join ', ')"
            }
            if ($stale.Count -gt 0) {
                $errors += "allow-main-wallet contains unregistered commands: $($stale -join ', ')"
            }
        }
    }
} else {
    $errors += "Missing handler inventory, mobile lib.rs, or wallet permission manifest"
}

if ($errors.Count -gt 0) {
    Write-Host "Android build validation FAILED:" -ForegroundColor Red
    $errors | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }
    exit 1
}

Write-Host "Android build validation OK" -ForegroundColor Green

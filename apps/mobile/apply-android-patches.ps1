# Apply signing + network security patches to generated Android project (idempotent).
$ErrorActionPreference = "Stop"
$mobile = Split-Path -Parent $MyInvocation.MyCommand.Path
$android = Join-Path $mobile "src-tauri\gen\android"
$gradle = Join-Path $android "app\build.gradle.kts"
$manifest = Join-Path $android "app\src\main\AndroidManifest.xml"
$netSrc = Join-Path $mobile "src-tauri\android-network-security.xml"
$netDstDir = Join-Path $android "app\src\main\res\xml"
$netDst = Join-Path $netDstDir "network_security_config.xml"
$rulesSrc = Join-Path $mobile "src-tauri\android-data-extraction-rules.xml"
$rulesDst = Join-Path $netDstDir "data_extraction_rules.xml"
$backupRulesSrc = Join-Path $mobile "src-tauri\android-backup-rules.xml"
$backupRulesDst = Join-Path $netDstDir "backup_rules.xml"

if (-not (Test-Path $gradle)) {
    throw "Missing $gradle. Run yarn tauri android init first."
}

& (Join-Path $mobile "merge-android-permissions.ps1")

$queriesSrc = Join-Path $mobile "src-tauri\android-queries.xml"
if (Test-Path $queriesSrc) {
    $queriesBlock = Get-Content $queriesSrc -Raw
    $manifestContent = Get-Content $manifest -Raw
    if ($manifestContent -notmatch "<queries>") {
        $manifestContent = $manifestContent -replace "</manifest>", ($queriesBlock.Trim() + "`r`n</manifest>")
        Set-Content -Path $manifest -Value $manifestContent -NoNewline
        Write-Host "Merged package-installer queries into AndroidManifest" -ForegroundColor Green
    }
}

if (-not (Test-Path $netDstDir)) { New-Item -ItemType Directory -Path $netDstDir -Force | Out-Null }
Copy-Item $netSrc $netDst -Force
Copy-Item $rulesSrc $rulesDst -Force
Copy-Item $backupRulesSrc $backupRulesDst -Force
Write-Host "Copied network security and both Android backup exclusion configs" -ForegroundColor Green

$manifestContent = Get-Content $manifest -Raw
if ($manifestContent -notmatch "networkSecurityConfig") {
    $manifestContent = $manifestContent.Replace(
        'android:usesCleartextTraffic="${usesCleartextTraffic}">',
        'android:usesCleartextTraffic="${usesCleartextTraffic}" android:networkSecurityConfig="@xml/network_security_config">'
    )
}
foreach ($attribute in @(
    @{ Name = "allowBackup"; Value = "false" },
    @{ Name = "fullBackupContent"; Value = "@xml/backup_rules" },
    @{ Name = "dataExtractionRules"; Value = "@xml/data_extraction_rules" }
)) {
    $pattern = 'android:' + $attribute.Name + '="[^"]*"'
    $replacement = 'android:' + $attribute.Name + '="' + $attribute.Value + '"'
    if ($manifestContent -match $pattern) {
        $manifestContent = $manifestContent -replace $pattern, $replacement
    } else {
        $manifestContent = $manifestContent.Replace('<application', '<application ' + $replacement)
    }
}
Write-Host "Disabled Android cloud backup and device transfer" -ForegroundColor Green
Set-Content -Path $manifest -Value $manifestContent -NoNewline
if ($manifestContent -match "networkSecurityConfig") {
    Write-Host "AndroidManifest security patches OK" -ForegroundColor Green
}

$gradleContent = Get-Content $gradle -Raw
$gradleLineEnding = if ($gradleContent.Contains("`r`n")) { "`r`n" } else { "`n" }
if ($gradleContent -notmatch "import java.io.FileInputStream") {
    $gradleContent = "import java.io.FileInputStream$gradleLineEnding" + $gradleContent
}

if ($gradleContent -notmatch "signingConfigs") {
    $signingBlock = @'
    signingConfigs {
        create("release") {
            val keystorePropertiesFile = rootProject.file("keystore.properties")
            val keystoreProperties = Properties()
            if (keystorePropertiesFile.exists()) {
                keystoreProperties.load(FileInputStream(keystorePropertiesFile))
            }
            keyAlias = keystoreProperties["keyAlias"] as String
            keyPassword = keystoreProperties["password"] as String
            storeFile = file(keystoreProperties["storeFile"] as String)
            storePassword = keystoreProperties["password"] as String
        }
    }
'@
    $signingBlock = $signingBlock.TrimEnd([char[]]"`r`n") + $gradleLineEnding
    $gradleContent = $gradleContent -replace '(android \{\r?\n)(\s*compileSdk)', "`$1$signingBlock`$2"
    Write-Host "Added signingConfigs inside android block" -ForegroundColor Green
}

if ($gradleContent -match 'getByName\("release"\)' -and $gradleContent -notmatch 'signingConfig = signingConfigs') {
    $gradleContent = $gradleContent.Replace(
        'getByName("release") {',
        "getByName(`"release`") {${gradleLineEnding}            signingConfig = signingConfigs.getByName(`"release`")"
    )
    Write-Host "Linked release signingConfig" -ForegroundColor Green
}

# Keep the manifest-wide cleartext flag disabled. The network security XML grants
# an exact exception only to the official HTTP node and local development hosts.

# WalletNativePlugin is application code, so its direct AndroidX dependency must
# live in the persistent app Gradle file. Tauri regenerates tauri.build.gradle.kts
# during every Android build and would otherwise erase this compile dependency.
$biometricDependency = 'implementation("androidx.biometric:biometric:1.1.0")'
if ($gradleContent -notmatch [regex]::Escape('androidx.biometric:biometric:1.1.0')) {
    $gradleContent = $gradleContent -replace '(dependencies \{\r?\n)', "`$1    $biometricDependency${gradleLineEnding}"
    Write-Host "Linked persistent AndroidX strong-biometric API" -ForegroundColor Green
}

Set-Content -Path $gradle -Value $gradleContent -NoNewline

# Sync branded launcher icons into generated Android res (gen/ uses Tauri placeholder by default).
$iconSrcRoot = Join-Path $mobile "src-tauri\icons\android"
$iconDstRoot = Join-Path $android "app\src\main\res"
$mipmapProbe = Join-Path $iconSrcRoot "mipmap-xxxhdpi\ic_launcher_foreground.png"
if (-not (Test-Path $mipmapProbe)) {
    Write-Host "Regenerating Android launcher mipmaps (missing or stale)..." -ForegroundColor Yellow
    & (Join-Path $mobile "generate-app-icons.ps1")
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}
if (Test-Path $iconSrcRoot) {
    Get-ChildItem -Path $iconSrcRoot -Recurse -File | ForEach-Object {
        $rel = $_.FullName.Substring($iconSrcRoot.Length).TrimStart([char[]]@('\', '/'))
        $dst = Join-Path $iconDstRoot $rel
        $parent = Split-Path -Parent $dst
        if (-not (Test-Path $parent)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
        Copy-Item $_.FullName $dst -Force
    }
    Write-Host "Synced branded launcher icons to gen/android res" -ForegroundColor Green
}

# Replace default green Tauri adaptive background with solid black (matches Hacash branding).
$bgXml = Join-Path $iconDstRoot "drawable\ic_launcher_background.xml"
if (Test-Path $bgXml) {
    @'
<?xml version="1.0" encoding="utf-8"?>
<vector xmlns:android="http://schemas.android.com/apk/res/android"
    android:width="108dp"
    android:height="108dp"
    android:viewportWidth="108"
    android:viewportHeight="108">
    <path
        android:fillColor="#000000"
        android:pathData="M0,0h108v108h-108z" />
</vector>
'@ | Set-Content -Path $bgXml -Encoding UTF8 -NoNewline
    Write-Host "Set adaptive icon background to black" -ForegroundColor Green
}

$bgColorXml = Join-Path $iconDstRoot "values\ic_launcher_background.xml"
if (-not (Test-Path (Split-Path -Parent $bgColorXml))) {
    New-Item -ItemType Directory -Path (Split-Path -Parent $bgColorXml) -Force | Out-Null
}
@'
<?xml version="1.0" encoding="utf-8"?>
<resources>
  <color name="ic_launcher_background">#000000</color>
</resources>
'@ | Set-Content -Path $bgColorXml -Encoding UTF8 -NoNewline

# In-app APK updates: merge paths into Tauri's file_paths.xml (single FileProvider authority).
$providerPathsSrc = Join-Path $mobile "src-tauri\android-file-provider-paths.xml"
$filePathsDst = Join-Path $netDstDir "file_paths.xml"
if (Test-Path $providerPathsSrc) {
    Copy-Item $providerPathsSrc $filePathsDst -Force
    Copy-Item $providerPathsSrc (Join-Path $netDstDir "file_provider_paths.xml") -Force
    Write-Host "Updated file_paths.xml for APK updates" -ForegroundColor Green
}

$kotlinSrcRoot = Join-Path $mobile "src-tauri\android-src"
$kotlinDstRoot = Join-Path $android "app\src\main\java"
if (Test-Path $kotlinSrcRoot) {
    Get-ChildItem -Path $kotlinSrcRoot -Recurse -Filter "*.kt" | ForEach-Object {
        $rel = $_.FullName.Substring($kotlinSrcRoot.Length).TrimStart([char[]]@('\', '/'))
        $dst = Join-Path $kotlinDstRoot $rel
        $parent = Split-Path -Parent $dst
        if (-not (Test-Path $parent)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
        Copy-Item $_.FullName $dst -Force
    }
    Write-Host "Synced Kotlin wallet-native plugin and helpers" -ForegroundColor Green
}

# Duplicate FileProvider authorities crash Android on launch; keep exactly one entry.
$manifestContent = Get-Content $manifest -Raw
$providerPattern = '(?s)\s*<provider[^>]*android:name="androidx\.core\.content\.FileProvider"[^>]*>.*?</provider>\s*'
while ([regex]::Matches($manifestContent, $providerPattern).Count -gt 0) {
    $manifestContent = [regex]::Replace($manifestContent, $providerPattern, '', 1)
}
$providerBlock = @'
        <provider
            android:name="androidx.core.content.FileProvider"
            android:authorities="${applicationId}.fileprovider"
            android:exported="false"
            android:grantUriPermissions="true">
            <meta-data
                android:name="android.support.FILE_PROVIDER_PATHS"
                android:resource="@xml/file_paths" />
        </provider>
'@
$manifestContent = $manifestContent -replace '</application>', ($providerBlock + "`r`n    </application>")
Set-Content -Path $manifest -Value $manifestContent -NoNewline
Write-Host "Normalized single FileProvider in AndroidManifest" -ForegroundColor Green

& (Join-Path $mobile "sync-app-version.ps1")

# Link every Tauri Android plugin crate referenced in Cargo.lock (Rust init without Gradle = startup crash).
$repoRoot = Split-Path -Parent (Split-Path -Parent $mobile)
$cargoLock = Join-Path $repoRoot "Cargo.lock"
$cargoHome = $env:CARGO_HOME
if ([string]::IsNullOrWhiteSpace($cargoHome)) {
    $userHome = $env:HOME
    if ([string]::IsNullOrWhiteSpace($userHome)) { $userHome = $env:USERPROFILE }
    if ([string]::IsNullOrWhiteSpace($userHome)) {
        $userHome = [Environment]::GetFolderPath([Environment+SpecialFolder]::UserProfile)
    }
    if ([string]::IsNullOrWhiteSpace($userHome)) {
        throw "Unable to resolve the user home directory for the Cargo registry"
    }
    $cargoHome = Join-Path $userHome ".cargo"
}
$registrySrc = Join-Path $cargoHome "registry/src"
$registryRoots = @(Get-ChildItem -LiteralPath $registrySrc -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -like "index.crates.io-*" })
$pluginCrates = @("tauri-plugin-deep-link", "tauri-plugin-opener")
$settingsGradle = Join-Path $android "tauri.settings.gradle"
$tauriBuildGradle = Join-Path $android "app\tauri.build.gradle.kts"

# Android strong authentication is owned by WalletNativePlugin. Remove stale
# generated links to the weak-auth upstream plugin; iOS keeps its Rust plugin.
if (Test-Path $settingsGradle) {
    $sg = Get-Content $settingsGradle -Raw
    $sg = $sg -replace '(?m)^include '':tauri-plugin-biometric''\r?\n', ''
    $sg = $sg -replace '(?m)^project\('':tauri-plugin-biometric''\)\.projectDir = .*\r?\n', ''
    Set-Content -Path $settingsGradle -Value $sg -NoNewline
}
if (Test-Path $tauriBuildGradle) {
    $bg = Get-Content $tauriBuildGradle -Raw
    $bg = $bg -replace '(?m)^\s*implementation\(project\(":tauri-plugin-biometric"\)\)\r?\n', ''
    $bg = $bg -replace '(?m)^\s*implementation\("androidx\.biometric:biometric:[^"]+"\)\r?\n', ''
    Set-Content -Path $tauriBuildGradle -Value $bg -NoNewline
}

function Resolve-PluginAndroidDir([string]$crateName) {
    if (-not (Test-Path $cargoLock)) { return $null }
    $lockText = Get-Content $cargoLock -Raw
    if ($lockText -notmatch "name = `"$crateName`"\r?\nversion = `"([^`"]+)`"") { return $null }
    $ver = $Matches[1]
    foreach ($root in $registryRoots) {
        $candidate = Join-Path $root.FullName "$crateName-$ver\android"
        if (Test-Path $candidate) { return $candidate }
    }
    return $null
}

foreach ($crate in $pluginCrates) {
    $androidDir = Resolve-PluginAndroidDir $crate
    if (-not $androidDir) {
        Write-Host "WARN: $crate android module not found in cargo registry" -ForegroundColor Yellow
        continue
    }
    $gradlePath = ($androidDir -replace '\\', '\\')
    if (Test-Path $settingsGradle) {
        $sg = Get-Content $settingsGradle -Raw
        if ($sg -notmatch [regex]::Escape($crate)) {
            Add-Content -Path $settingsGradle -Value @"

include ':$crate'
project(':$crate').projectDir = new File("$gradlePath")
"@ -Encoding UTF8
            Write-Host "Linked $crate in tauri.settings.gradle" -ForegroundColor Green
        }
    }
    if (Test-Path $tauriBuildGradle) {
        $bg = Get-Content $tauriBuildGradle -Raw
        if ($bg -notmatch [regex]::Escape($crate)) {
            if ($bg -match 'dependencies \{\r?\n') {
                $bg = $bg -replace '(dependencies \{\r?\n)', "`$1  implementation(project(`":$crate`"))`r`n"
                Set-Content -Path $tauriBuildGradle -Value $bg -NoNewline
                Write-Host "Linked $crate in tauri.build.gradle.kts" -ForegroundColor Green
            }
        }
    }
}

$proguardPath = Join-Path $android "app\proguard-rules.pro"
$proguardKeeps = @'
# Native wallet plugin (loaded by class name through Tauri's Android lifecycle)
-keep class org.hacash.wallet.mobile.WalletNativePlugin { *; }
-keep class org.hacash.wallet.mobile.ApkInstaller { *; }
-keep class org.hacash.wallet.mobile.BackupFileHelper { *; }
-keep class org.hacash.wallet.mobile.BiometricSecretStore { *; }
-keep class org.hacash.wallet.mobile.BackupExportHelper { *; }
-keep class androidx.core.content.FileProvider { *; }
# Tauri Android plugins (loaded by class name at runtime)
-keep class app.tauri.opener.OpenerPlugin { *; }
-keep class app.tauri.deep_link.** { *; }
'@
if (Test-Path $proguardPath) {
    $proguard = Get-Content $proguardPath -Raw
    if (
        $proguard -notmatch "WalletNativePlugin" -or
        $proguard -notmatch "app\.tauri\.opener\.OpenerPlugin" -or
        $proguard -notmatch "BackupFileHelper" -or
        $proguard -notmatch "BiometricSecretStore" -or
        $proguard -notmatch "BackupExportHelper"
    ) {
        Add-Content -Path $proguardPath -Value $proguardKeeps -Encoding UTF8
        Write-Host "Added per-plugin ProGuard keep rules" -ForegroundColor Green
    }
}

& (Join-Path $mobile "validate-android-build.ps1")
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

$distIndex = Join-Path $mobile "dist\index.html"
if (Test-Path $distIndex) {
    & (Join-Path $mobile "sync-android-frontend.ps1")
}

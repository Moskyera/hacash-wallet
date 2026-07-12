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

if (-not (Test-Path $gradle)) {
    throw "Missing $gradle. Run yarn tauri android init first."
}

& (Join-Path $mobile "merge-android-permissions.ps1")

if (-not (Test-Path $netDstDir)) { New-Item -ItemType Directory -Path $netDstDir -Force | Out-Null }
Copy-Item $netSrc $netDst -Force
Copy-Item $rulesSrc $rulesDst -Force
Write-Host "Copied network_security_config.xml + data_extraction_rules.xml" -ForegroundColor Green

$manifestContent = Get-Content $manifest -Raw
if ($manifestContent -notmatch "networkSecurityConfig") {
    $manifestContent = $manifestContent.Replace(
        'android:usesCleartextTraffic="${usesCleartextTraffic}">',
        'android:usesCleartextTraffic="${usesCleartextTraffic}" android:networkSecurityConfig="@xml/network_security_config">'
    )
}
if ($manifestContent -notmatch 'android:allowBackup="false"') {
    $manifestContent = $manifestContent.Replace(
        '<application',
        '<application android:allowBackup="false" android:fullBackupContent="false" android:dataExtractionRules="@xml/data_extraction_rules"'
    )
    Write-Host "Disabled Android cloud backup (allowBackup=false)" -ForegroundColor Green
}
Set-Content -Path $manifest -Value $manifestContent -NoNewline
if ($manifestContent -match "networkSecurityConfig") {
    Write-Host "AndroidManifest security patches OK" -ForegroundColor Green
}

$gradleContent = Get-Content $gradle -Raw
if ($gradleContent -notmatch "import java.io.FileInputStream") {
    $gradleContent = "import java.io.FileInputStream`r`n" + $gradleContent
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
    $gradleContent = $gradleContent -replace '(android \{\r?\n)(\s*compileSdk)', "`$1$signingBlock`$1`$2"
    Write-Host "Added signingConfigs inside android block" -ForegroundColor Green
}

if ($gradleContent -match 'getByName\("release"\)' -and $gradleContent -notmatch 'signingConfig = signingConfigs') {
    $gradleContent = $gradleContent.Replace(
        'getByName("release") {',
        "getByName(`"release`") {`r`n            signingConfig = signingConfigs.getByName(`"release`")"
    )
    Write-Host "Linked release signingConfig" -ForegroundColor Green
}

# Release builds must allow HTTP to nodeapi.hacash.org (Rust reqwest, not only WebView).
if ($gradleContent -match 'manifestPlaceholders\["usesCleartextTraffic"\] = "false"') {
    $gradleContent = $gradleContent.Replace(
        'manifestPlaceholders["usesCleartextTraffic"] = "false"',
        'manifestPlaceholders["usesCleartextTraffic"] = "true"'
    )
    Write-Host "Enabled cleartext HTTP for release (Hacash node API)" -ForegroundColor Green
}

Set-Content -Path $gradle -Value $gradleContent -NoNewline

# Sync branded launcher icons into generated Android res (gen/ uses Tauri placeholder by default).
$iconSrcRoot = Join-Path $mobile "src-tauri\icons\android"
$iconDstRoot = Join-Path $android "app\src\main\res"
if (Test-Path $iconSrcRoot) {
    Get-ChildItem -Path $iconSrcRoot -Recurse -File | ForEach-Object {
        $rel = $_.FullName.Substring($iconSrcRoot.Length).TrimStart('\')
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

# In-app APK updates: FileProvider + Kotlin installer helper.
$providerPathsSrc = Join-Path $mobile "src-tauri\android-file-provider-paths.xml"
$providerPathsDst = Join-Path $netDstDir "file_provider_paths.xml"
if (Test-Path $providerPathsSrc) {
    Copy-Item $providerPathsSrc $providerPathsDst -Force
    Write-Host "Copied file_provider_paths.xml for APK updates" -ForegroundColor Green
}

$kotlinSrcRoot = Join-Path $mobile "src-tauri\android-src"
$kotlinDstRoot = Join-Path $android "app\src\main\java"
if (Test-Path $kotlinSrcRoot) {
    Get-ChildItem -Path $kotlinSrcRoot -Recurse -Filter "*.kt" | ForEach-Object {
        $rel = $_.FullName.Substring($kotlinSrcRoot.Length).TrimStart('\')
        $dst = Join-Path $kotlinDstRoot $rel
        $parent = Split-Path -Parent $dst
        if (-not (Test-Path $parent)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
        Copy-Item $_.FullName $dst -Force
    }
    Write-Host "Synced Kotlin helpers (ApkInstaller)" -ForegroundColor Green
}

$manifestContent = Get-Content $manifest -Raw
if ($manifestContent -notmatch 'android:name=".fileprovider"') {
    $providerBlock = @'
        <provider
            android:name="androidx.core.content.FileProvider"
            android:authorities="${applicationId}.fileprovider"
            android:exported="false"
            android:grantUriPermissions="true">
            <meta-data
                android:name="android.support.FILE_PROVIDER_PATHS"
                android:resource="@xml/file_provider_paths" />
        </provider>
'@
    $manifestContent = $manifestContent -replace '</application>', ($providerBlock + "`r`n    </application>")
    Set-Content -Path $manifest -Value $manifestContent -NoNewline
    Write-Host "Added FileProvider for in-app APK install" -ForegroundColor Green
}

$distIndex = Join-Path $mobile "dist\index.html"
if (Test-Path $distIndex) {
    & (Join-Path $mobile "sync-android-frontend.ps1")
}
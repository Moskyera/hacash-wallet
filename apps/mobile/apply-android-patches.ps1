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

Set-Content -Path $gradle -Value $gradleContent -NoNewline
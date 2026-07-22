param(
    [Parameter(Mandatory = $true)][string] $ApkPath,
    [string] $ExpectedVersion,
    [string] $ExpectedCertSha256 = $env:ANDROID_EXPECTED_CERT_SHA256
)

$ErrorActionPreference = "Stop"
$mobile = Split-Path -Parent $MyInvocation.MyCommand.Path
$ApkPath = [System.IO.Path]::GetFullPath($ApkPath)
if (-not (Test-Path -LiteralPath $ApkPath -PathType Leaf)) {
    throw "Release APK is missing: $ApkPath"
}

if ([string]::IsNullOrWhiteSpace($ExpectedVersion)) {
    $ExpectedVersion = (Get-Content (Join-Path $mobile "package.json") -Raw | ConvertFrom-Json).version
}
if ($ExpectedVersion -notmatch '^\d+\.\d+\.\d+$') {
    throw "ExpectedVersion must be numeric semver, got $ExpectedVersion"
}
$versionParts = @($ExpectedVersion.Split('.') | ForEach-Object { [int64] $_ })
$expectedVersionCode = ($versionParts[0] * 10000) + ($versionParts[1] * 100) + $versionParts[2]
if ($expectedVersionCode -gt [int]::MaxValue) {
    throw "ExpectedVersion produces an Android versionCode outside the supported range"
}
if ([string]::IsNullOrWhiteSpace($ExpectedCertSha256)) {
    throw "ANDROID_EXPECTED_CERT_SHA256 is required; refusing to accept an unpinned Android signer"
}
$expectedSigner = ($ExpectedCertSha256 -replace '[^0-9A-Fa-f]', '').ToLowerInvariant()
if ($expectedSigner.Length -ne 64) {
    throw "ANDROID_EXPECTED_CERT_SHA256 must be a SHA-256 certificate fingerprint"
}

$sdk = if ($env:ANDROID_SDK_ROOT) { $env:ANDROID_SDK_ROOT } elseif ($env:ANDROID_HOME) { $env:ANDROID_HOME } else { Join-Path $env:LOCALAPPDATA "Android\Sdk" }
$buildTools = Join-Path $sdk "build-tools\36.0.0"
$suffix = if ($IsWindows -or $env:OS -eq "Windows_NT") { ".bat" } else { "" }
$apksigner = Join-Path $buildTools "apksigner$suffix"
$aaptName = if ($IsWindows -or $env:OS -eq "Windows_NT") { "aapt.exe" } else { "aapt" }
$aapt = Join-Path $buildTools $aaptName
if (-not (Test-Path -LiteralPath $apksigner)) { throw "apksigner 36.0.0 not found: $apksigner" }
if (-not (Test-Path -LiteralPath $aapt)) { throw "aapt 36.0.0 not found: $aapt" }

$signatureOutput = @(& $apksigner verify --verbose --print-certs $ApkPath 2>&1)
if ($LASTEXITCODE -ne 0) { throw "apksigner rejected the APK" }
$signatureText = $signatureOutput -join "`n"
$signerMatch = [regex]::Match($signatureText, 'Signer #1 certificate SHA-256 digest:\s*([0-9A-Fa-f:]+)')
if (-not $signerMatch.Success) { throw "Unable to read the APK signing certificate digest" }
$actualSigner = ($signerMatch.Groups[1].Value -replace '[^0-9A-Fa-f]', '').ToLowerInvariant()
if ($actualSigner -ne $expectedSigner) { throw "APK signer does not match the pinned release certificate" }
if ($signatureText -notmatch 'Verified using v2 scheme.*:\s*true' -and $signatureText -notmatch 'Verified using v3 scheme.*:\s*true') {
    throw "APK must use Android signing scheme v2 or newer"
}

$badgingOutput = @(& $aapt dump badging $ApkPath 2>&1)
if ($LASTEXITCODE -ne 0) { throw "aapt could not inspect the APK" }
$badging = $badgingOutput -join "`n"
if ($badging -notmatch "package: name='org\.hacash\.wallet\.mobile'[^\r\n]*versionName='$([regex]::Escape($ExpectedVersion))'") {
    throw "APK package id or versionName does not match org.hacash.wallet.mobile v$ExpectedVersion"
}
if ($badging -notmatch "package: name='org\.hacash\.wallet\.mobile'[^\r\n]*versionCode='$expectedVersionCode'") {
    throw "APK versionCode does not match the required upgrade code $expectedVersionCode"
}
if ($badging -notmatch "(?m)^sdkVersion:'28'\s*$" -or $badging -notmatch "(?m)^targetSdkVersion:'36'\s*$") {
    throw "APK minSdk/targetSdk must be 28/36"
}
$nativeLines = @($badgingOutput | Where-Object { $_ -match '^native-code:' })
if ($nativeLines.Count -ne 1 -or $nativeLines[0].Trim() -ne "native-code: 'arm64-v8a'") {
    throw "Release APK must contain exactly the arm64-v8a ABI"
}

Write-Host "Signed Android APK verified: org.hacash.wallet.mobile v$ExpectedVersion, arm64-v8a, SDK 28-36" -ForegroundColor Green

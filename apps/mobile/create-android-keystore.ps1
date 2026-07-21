# Generate release keystore + keystore.properties for signed Android APK.
# Secrets stay in gitignored files - never commit the .jks or keystore.properties.
$ErrorActionPreference = "Stop"
$mobile = Split-Path -Parent $MyInvocation.MyCommand.Path
$keystore = Join-Path $mobile "src-tauri\hacash-wallet-release.jks"
$props = Join-Path $mobile "src-tauri\gen\android\keystore.properties"
$keytool = "C:\Program Files\Android\Android Studio\jbr\bin\keytool.exe"
$alias = "hacash-wallet"

if (-not (Test-Path $keytool)) {
    throw "keytool not found at $keytool. Install Android Studio JBR."
}

if (-not (Test-Path (Split-Path $props))) {
    throw "Run 'yarn tauri android init' first (missing src-tauri/gen/android)."
}

$password = $env:ANDROID_KEYSTORE_PASSWORD
if ([string]::IsNullOrWhiteSpace($password)) {
    $password = Read-Host "Keystore password (min 6 chars, stored in keystore.properties)"
}
if ($password.Length -lt 6) { throw "Password too short." }

if (-not (Test-Path $keystore)) {
    Write-Host "Creating keystore: $keystore" -ForegroundColor Cyan
    $dname = "CN=Hacash Wallet Mobile, OU=Wallet, O=Hacash, L=Athens, ST=Attica, C=GR"
    & $keytool -genkey -v `
        -keystore $keystore `
        -storetype JKS `
        -keyalg RSA `
        -keysize 2048 `
        -validity 10000 `
        -alias $alias `
        -storepass $password `
        -keypass $password `
        -dname $dname
    if ($LASTEXITCODE -ne 0) { throw "keytool failed." }
} else {
    Write-Host "Keystore already exists: $keystore" -ForegroundColor Yellow
}

$storePath = $keystore.Replace("\", "/")
@"
password=$password
keyAlias=$alias
storeFile=$storePath
"@ | Set-Content -Path $props -Encoding ASCII

Write-Host "Wrote $props" -ForegroundColor Green
Write-Host "Keep the .jks and password safe. For CI, set ANDROID_KEYSTORE_PASSWORD." -ForegroundColor Yellow
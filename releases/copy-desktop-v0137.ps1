$ErrorActionPreference = "Stop"
$releases = "C:\Users\KQHEX\Documents\moskyera-quantum-wallet\releases"
$target = "C:\Users\KQHEX\Documents\moskyera-quantum-wallet\target\release"
$desktop = "C:\Users\KQHEX\Desktop"

$setupSrc = Join-Path $target "bundle\nsis\Hacash Wallet_0.1.37_x64-setup.exe"
$msiSrc = Join-Path $target "bundle\msi\Hacash Wallet_0.1.37_x64_en-US.msi"
$portableSrc = Join-Path $target "hacash-wallet.exe"

$setupDst = Join-Path $releases "hacash-wallet-desktop-v0.1.37-x64-setup.exe"
$msiDst = Join-Path $releases "hacash-wallet-desktop-v0.1.37-x64.msi"
$portableDst = Join-Path $releases "hacash-wallet-desktop-v0.1.37-x64-portable.exe"
$desktopSetup = Join-Path $desktop "hacash-wallet-desktop-v0.1.37-x64-setup.exe"

foreach ($f in @($setupSrc, $msiSrc, $portableSrc)) {
    if (-not (Test-Path $f)) { throw "Missing: $f" }
}

Copy-Item -Path $setupSrc -Destination $setupDst -Force
Copy-Item -Path $msiSrc -Destination $msiDst -Force
Copy-Item -Path $portableSrc -Destination $portableDst -Force
Copy-Item -Path $setupSrc -Destination $desktopSetup -Force

Write-Host "OK setup: $setupDst"
Write-Host "OK msi: $msiDst"
Write-Host "OK portable: $portableDst"
Write-Host "OK desktop: $desktopSetup"

Get-Item $setupDst, $msiDst, $portableDst, $desktopSetup | Select-Object FullName, Length, LastWriteTime | Format-Table -AutoSize
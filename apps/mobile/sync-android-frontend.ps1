# Bundle Vite dist/ into Android assets (required for release APK on device).
$ErrorActionPreference = "Stop"
$mobile = Split-Path -Parent $MyInvocation.MyCommand.Path
$dist = Join-Path $mobile "dist"
$assets = Join-Path $mobile "src-tauri\gen\android\app\src\main\assets"

if (-not (Test-Path (Join-Path $dist "index.html"))) {
    throw "Missing $dist\index.html - run yarn build first"
}
if (-not (Test-Path $assets)) {
    throw "Missing Android assets dir. Run: yarn tauri android init"
}

# Keep generated tauri.conf.json; replace stale UI bundle.
Get-ChildItem -Path $assets -File | Where-Object { $_.Name -ne "tauri.conf.json" } | Remove-Item -Force
Get-ChildItem -Path $assets -Directory | Where-Object { $_.Name -ne "dexopt" } | Remove-Item -Recurse -Force

Copy-Item -Path (Join-Path $dist "*") -Destination $assets -Recurse -Force
Write-Host "Bundled frontend into Android assets: $assets" -ForegroundColor Green
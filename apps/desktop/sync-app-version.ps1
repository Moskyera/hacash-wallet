# Single source of truth: apps/desktop/package.json -> tauri.conf.json
$ErrorActionPreference = "Stop"
$desktop = Split-Path -Parent $MyInvocation.MyCommand.Path
$pkgJson = Join-Path $desktop "package.json"
$tauriConf = Join-Path $desktop "src-tauri\tauri.conf.json"

$ver = (Get-Content $pkgJson -Raw | ConvertFrom-Json).version

if (Test-Path $tauriConf) {
    $conf = Get-Content $tauriConf -Raw | ConvertFrom-Json
    if ($conf.version -ne $ver) {
        $conf.version = $ver
        $conf | ConvertTo-Json -Depth 20 | Set-Content -Path $tauriConf -Encoding UTF8
        Write-Host "Synced tauri.conf.json version -> $ver" -ForegroundColor Green
    } else {
        Write-Host "tauri.conf.json already at $ver" -ForegroundColor Green
    }
}
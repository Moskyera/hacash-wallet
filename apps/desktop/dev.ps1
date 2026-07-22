# Moskyera Quantum Wallet - hot-reload dev launcher
$ErrorActionPreference = "Stop"
$desktop = $PSScriptRoot

Write-Host "Stopping stale wallet/vite..." -ForegroundColor Yellow
Get-Process hacash-wallet -ErrorAction SilentlyContinue | Stop-Process -Force
Get-NetTCPConnection -LocalPort 1420 -State Listen -ErrorAction SilentlyContinue |
  ForEach-Object { Stop-Process -Id $_.OwningProcess -Force -ErrorAction SilentlyContinue }
Start-Sleep -Seconds 2

Set-Location $desktop
Write-Host "Starting yarn tauri dev (Vite @ http://127.0.0.1:1420)..." -ForegroundColor Green
yarn tauri dev
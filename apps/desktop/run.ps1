# Standalone launcher: Vite (1420) + debug wallet exe
# Debug hacash-wallet.exe always loads http://127.0.0.1:1420 - not dist/
$ErrorActionPreference = "Stop"
$desktop = $PSScriptRoot
$exe = Join-Path $desktop "..\..\target\debug\hacash-wallet.exe"

Write-Host "Stopping stale processes..." -ForegroundColor Yellow
Get-Process hacash-wallet -ErrorAction SilentlyContinue | Stop-Process -Force
Get-NetTCPConnection -LocalPort 1420 -State Listen -ErrorAction SilentlyContinue |
  ForEach-Object { Stop-Process -Id $_.OwningProcess -Force -ErrorAction SilentlyContinue }
Start-Sleep -Seconds 2

if (-not (Test-Path $exe)) {
  Write-Host "Building wallet (first run)..." -ForegroundColor Cyan
  Set-Location $desktop
  node node_modules/@tauri-apps/cli/tauri.js build --debug 2>&1 | Out-Null
  if (-not (Test-Path $exe)) { throw "Missing $exe - run: yarn tauri build --debug" }
}

Set-Location $desktop
Write-Host "Starting Vite @ http://127.0.0.1:1420 ..." -ForegroundColor Green
$node = (Get-Command node -ErrorAction Stop).Source
$viteBin = Join-Path $desktop "node_modules\vite\bin\vite.js"
$vite = Start-Process -FilePath $node -ArgumentList $viteBin, "--host", "127.0.0.1", "--port", "1420" `
  -WorkingDirectory $desktop -PassThru -WindowStyle Minimized

$ready = $false
foreach ($i in 1..20) {
  Start-Sleep -Seconds 1
  try {
    $r = Invoke-WebRequest -Uri "http://127.0.0.1:1420/" -UseBasicParsing -TimeoutSec 2
    if ($r.StatusCode -eq 200) { $ready = $true; break }
  } catch {}
}
if (-not $ready) {
  Stop-Process -Id $vite.Id -Force -ErrorAction SilentlyContinue
  throw "Vite did not start on :1420"
}

Write-Host "Launching hacash-wallet..." -ForegroundColor Green
Start-Process -FilePath $exe -WorkingDirectory $desktop
Write-Host "OK - close this window to keep Vite running in background." -ForegroundColor Cyan

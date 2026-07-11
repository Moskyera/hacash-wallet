# Start Hacash Wallet Mobile — Vite + debug exe (reliable desktop preview)
$ErrorActionPreference = "Stop"
$mobile = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = (Resolve-Path (Join-Path $mobile "..\..")).Path
$exe = Join-Path $repoRoot "target\debug\hacash-wallet-mobile.exe"
$viteLog = Join-Path $mobile "vite-server.log"

function Test-ViteReady {
    try {
        $r = Invoke-WebRequest -Uri "http://127.0.0.1:1421" -UseBasicParsing -TimeoutSec 2
        return $r.StatusCode -eq 200
    } catch {
        return $false
    }
}

function Stop-PortListener([int]$Port) {
    $conn = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($conn) {
        Stop-Process -Id $conn.OwningProcess -Force -ErrorAction SilentlyContinue
        Start-Sleep -Milliseconds 500
    }
}

# Stop old wallet only (do NOT kill all node — breaks other tools)
Get-Process -Name hacash-wallet-mobile -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Milliseconds 400

if (-not (Test-ViteReady)) {
    Stop-PortListener 1421
    $viteCmd = "Set-Location -LiteralPath '$mobile'; node .\node_modules\vite\bin\vite.js --host 127.0.0.1 --port 1421 --strictPort *>> '$viteLog'"
    Start-Process -FilePath "powershell.exe" `
        -ArgumentList "-NoExit", "-ExecutionPolicy", "Bypass", "-Command", $viteCmd `
        -WindowStyle Minimized
    $deadline = (Get-Date).AddSeconds(25)
    while ((Get-Date) -lt $deadline) {
        if (Test-ViteReady) { break }
        Start-Sleep -Milliseconds 500
    }
}

if (-not (Test-ViteReady)) {
    Write-Host "Vite failed on http://127.0.0.1:1421"
    Write-Host "Check: $viteLog"
    exit 1
}

if (-not (Test-Path $exe)) {
    Write-Host "Building wallet..."
    Push-Location (Join-Path $mobile "src-tauri")
    cargo build -q
    Pop-Location
}

if (-not (Test-Path $exe)) {
    Write-Host "Missing: $exe"
    exit 1
}

Start-Process -FilePath "explorer.exe" -ArgumentList "`"$exe`""

Start-Sleep -Seconds 8
$proc = Get-Process -Name hacash-wallet-mobile -ErrorAction SilentlyContinue | Select-Object -First 1
if ($proc) {
    if ($proc.MainWindowHandle -ne 0) {
        Add-Type @"
using System.Runtime.InteropServices;
public class W { [DllImport("user32.dll")] public static extern bool SetForegroundWindow(System.IntPtr h); [DllImport("user32.dll")] public static extern bool ShowWindow(System.IntPtr h, int c); }
"@
        [void][W]::ShowWindow($proc.MainWindowHandle, 9)
        [void][W]::SetForegroundWindow($proc.MainWindowHandle)
    }
    Write-Host "Hacash Wallet opened (PID $($proc.Id)). Vite: OK"
    Write-Host "Keep the minimized 'Vite server' window running."
} else {
    Write-Host "Wallet failed. Vite is OK at http://127.0.0.1:1421"
    Write-Host "Try manually: $exe"
    exit 1
}
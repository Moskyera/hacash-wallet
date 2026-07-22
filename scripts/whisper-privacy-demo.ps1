# DUST Whisper privacy demo - shows direct read vs relay submit paths.
# Usage: .\scripts\whisper-privacy-demo.ps1 [-NodeUrl http://nodeapi.hacash.org]

param(
    [string]$NodeUrl = "http://nodeapi.hacash.org",
    [string]$RelayUrl = "http://127.0.0.1:8787",
    [string]$Address = "1LCY6uQS3iNGy2mKSmhFVU2dHgBQLf74Fx"
)

$ErrorActionPreference = "Continue"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

Write-Host "`n=== DUST Whisper privacy demo ===" -ForegroundColor Cyan
Write-Host "Public node: $NodeUrl"
Write-Host "Local relay: $RelayUrl"
Write-Host ""

Write-Host "[1] DIRECT read path (wallet -> node)" -ForegroundColor Yellow
Write-Host "    The node operator sees YOUR IP on balance/preview queries."
try {
    $latest = Invoke-RestMethod -Uri "$NodeUrl/query/latest" -TimeoutSec 15
    Write-Host "    OK latest height: $($latest.height)" -ForegroundColor Green
} catch {
    Write-Host "    Node unreachable from this machine: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "    (Wallet Rust HTTP client may still work; check in app UI.)"
}

try {
    $bal = Invoke-RestMethod -Uri "$NodeUrl/query/balance?unit=mei&address=$Address" -TimeoutSec 15
    $mei = $bal.list[0].hacash
    Write-Host "    OK balance $Address : $mei HAC" -ForegroundColor Green
} catch {
    Write-Host "    Balance query failed: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host ""
Write-Host "[2] WHISPER submit path (wallet -> relay -> node)" -ForegroundColor Yellow
Write-Host "    On broadcast, the node sees the RELAY IP, not yours."
Write-Host "    Tx hex is encrypted wallet->relay (X25519 + AES-GCM)."
try {
    $info = Invoke-RestMethod -Uri "$RelayUrl/whisper/v1/info" -TimeoutSec 5
    Write-Host "    OK relay online v=$($info.v)" -ForegroundColor Green
    Write-Host "    Relay forwards to: $($info.node_url)"
    Write-Host "    Relay pubkey: $($info.pubkey.Substring(0,12))..."
} catch {
    Write-Host "    Relay offline: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "    Start wallet (auto-start) or run dust-whisper-relay.exe manually."
}

Write-Host ""
Write-Host "[3] What changes in production" -ForegroundColor Cyan
Write-Host @"
    | Step              | Without Whisper      | With Whisper              |
    |-------------------|----------------------|---------------------------|
    | Balance query     | Your IP -> node      | Your IP -> node (same)    |
    | Sign tx           | Local only           | Local only                |
    | Broadcast submit  | Your IP -> node      | Relay IP -> node          |
    | Tx on blockchain  | Public (from/to)     | Public (from/to)          |

    Privacy gain: submit metadata (IP) hidden from node operator.
    Not hidden: on-chain addresses, amounts, balance reads.
"@

Write-Host "Done.`n"
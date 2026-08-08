<# Starts a CPU-only poworker after verifying the exact Local Pilot node API. #>
[CmdletBinding()]
param(
    [string] $PoworkerExe = "C:\Users\KQHEX\Documents\hacash-fullnodedev\target\hpay-local-pilot\release\poworker.exe",
    [string] $RuntimeDir = (Join-Path $env:LOCALAPPDATA "HPAY\agent-local-pilot-v1\runtime"),
    [ValidateRange(1, 65535)] [int] $RpcPort = 8197
)
$ErrorActionPreference = "Stop"
function Fail([string] $Message) { throw "HPAY Local Pilot miner guard: $Message" }
Write-Host "HPAY LOCAL PILOT CHAIN" -ForegroundColor Yellow
Write-Host "PRIVATE DEVELOPMENT NETWORK" -ForegroundColor Yellow
Write-Host "NO MAINNET FUNDS" -ForegroundColor Yellow
Write-Host "NOT HACASH PUBLIC TESTNET" -ForegroundColor Yellow
if (-not (Test-Path -LiteralPath $PoworkerExe -PathType Leaf)) { Fail "poworker binary not found" }
$baseUrl = "http://127.0.0.1:$RpcPort"
$capabilities = Invoke-RestMethod -Uri "$baseUrl/query/capabilities" -TimeoutSec 3
if ($capabilities.ret -ne 0 -or $capabilities.chain.id -ne 7 -or
    $capabilities.chain.mainnet -ne $false -or
    $capabilities.network.kind -ne "local_pilot_v1" -or
    $capabilities.network.node_profile_id -ne "hpay-local-pilot-chain-v1") {
    Fail "refusing to mine: endpoint is not the exact HPAY Local Pilot Chain V1"
}
$template = Join-Path $PSScriptRoot "agent-local-pilot\poworker.ini.template"
if (-not (Test-Path -LiteralPath $template -PathType Leaf)) { Fail "worker template not found" }
New-Item -ItemType Directory -Force -Path $RuntimeDir | Out-Null
$config = Join-Path $RuntimeDir "poworker.ini"
$stats = (Join-Path $RuntimeDir "miner-stats.json") -replace '\\', '/'
(Get-Content -LiteralPath $template -Raw).
    Replace("@@RPC_PORT@@", "$RpcPort").
    Replace("@@STATS_FILE@@", $stats) |
    Set-Content -LiteralPath $config -Encoding utf8
$stdout = Join-Path $RuntimeDir "poworker.out.log"
$stderr = Join-Path $RuntimeDir "poworker.err.log"
$worker = Start-Process -FilePath $PoworkerExe -ArgumentList "`"$config`"" `
    -WorkingDirectory $RuntimeDir -RedirectStandardOutput $stdout `
    -RedirectStandardError $stderr -PassThru -WindowStyle Hidden
$worker.Id | Set-Content -LiteralPath (Join-Path $RuntimeDir "poworker.pid") -Encoding ascii
Write-Host "CPU poworker started. PID: $($worker.Id)"
Write-Host "Mining rewards follow the reward address in the guarded node configuration."

<#
.SYNOPSIS
Starts the isolated HPAY custom fullnode 1.0.10 testnet profile.

.DESCRIPTION
This launcher never deletes, migrates, copies, or resynchronizes node data. It
uses a user-scoped data directory, loopback-only HTTP API, separate ports, and
an exact marker. A runtime identity mismatch stops only the process launched by
this invocation. It never discovers or falls back to another node.
#>

[CmdletBinding()]
param(
    [string] $FullnodeExe = "C:\Users\KQHEX\Documents\hacash-fullnodedev\target\release\fullnode.exe",
    [string] $DataDir = (Join-Path $env:LOCALAPPDATA "HPAY\agent-testnet-v3\data"),
    [string] $RuntimeDir = (Join-Path $env:LOCALAPPDATA "HPAY\agent-testnet-v3\runtime"),
    [ValidateRange(1, 65535)] [int] $P2pPort = 3099,
    [ValidateRange(1, 65535)] [int] $RpcPort = 8099,
    [switch] $ValidateOnly
)

$ErrorActionPreference = "Stop"
$ExpectedChainId = 7
$ExpectedNodeVersion = "1.0.10"
$ExpectedProfile = "hpay-custom-1.0.10-testnet"
$ExpectedNetwork = "testnet-v3"
$TemplatePath = Join-Path $PSScriptRoot "agent-testnet\node.ini.template"
$RepoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$FullnodeRepoRoot = [IO.Path]::GetFullPath((Join-Path $RepoRoot "..\hacash-fullnodedev"))
$UserPilotRoot = [IO.Path]::GetFullPath((Join-Path $env:LOCALAPPDATA "HPAY"))

function Fail([string] $Message) {
    throw "HPAY testnet guard: $Message"
}

function CanonicalPath([string] $Path) {
    return [IO.Path]::GetFullPath($Path).TrimEnd('\', '/')
}

function IsWithin([string] $Child, [string] $Parent) {
    $prefix = (CanonicalPath $Parent) + [IO.Path]::DirectorySeparatorChar
    return (CanonicalPath $Child).StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)
}

function AssertPortFree([int] $Port) {
    $listener = Get-NetTCPConnection -State Listen -LocalPort $Port -ErrorAction SilentlyContinue
    if ($listener) { Fail "port $Port is already in use" }
}

function AssertNoReparsePoint([string] $Path) {
    $cursor = CanonicalPath $Path
    while ($cursor.StartsWith($UserPilotRoot, [StringComparison]::OrdinalIgnoreCase)) {
        if (Test-Path -LiteralPath $cursor) {
            $item = Get-Item -LiteralPath $cursor -Force
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                Fail "data or runtime path traverses a junction or symbolic link"
            }
        }
        if ($cursor -eq $UserPilotRoot) { break }
        $parent = Split-Path -Parent $cursor
        if ([string]::IsNullOrWhiteSpace($parent) -or $parent -eq $cursor) { break }
        $cursor = CanonicalPath $parent
    }
}

function StopLaunchedProcess($Process) {
    if ($Process -and -not $Process.HasExited) {
        Stop-Process -Id $Process.Id -Force -ErrorAction SilentlyContinue
    }
}

Write-Host "HPAY CUSTOM FULLNODE 1.0.10" -ForegroundColor Yellow
Write-Host "TESTNET V3" -ForegroundColor Yellow
Write-Host "NO MAINNET FUNDS" -ForegroundColor Yellow

if ($P2pPort -eq $RpcPort) { Fail "P2P and RPC ports must differ" }
if (-not (Test-Path -LiteralPath $FullnodeExe -PathType Leaf)) { Fail "fullnode binary not found" }
if (-not (Test-Path -LiteralPath $TemplatePath -PathType Leaf)) { Fail "profile template not found" }

$resolvedData = CanonicalPath $DataDir
$resolvedRuntime = CanonicalPath $RuntimeDir
if (-not (IsWithin $resolvedData $UserPilotRoot) -or
    -not (IsWithin $resolvedRuntime $UserPilotRoot)) {
    Fail "data and runtime directories must stay under the user-scoped HPAY root"
}
if ($resolvedData -match "(?i)(^|[\\/])[^\\/]*mainnet[^\\/]*($|[\\/])") {
    Fail "data directory resembles a mainnet path"
}
if ((IsWithin $resolvedData $RepoRoot) -or (IsWithin $resolvedData $FullnodeRepoRoot)) {
    Fail "data directory must be outside all source repositories"
}
if ($resolvedData -eq $resolvedRuntime -or
    (IsWithin $resolvedRuntime $resolvedData) -or
    (IsWithin $resolvedData $resolvedRuntime)) {
    Fail "runtime files must not share the chain data directory"
}
AssertNoReparsePoint $resolvedData
AssertNoReparsePoint $resolvedRuntime

$markerPath = Join-Path $resolvedRuntime "testnet-marker.json"
$configPath = Join-Path $resolvedRuntime "node.ini"
$pidPath = Join-Path $resolvedRuntime "fullnode.pid"
$identityPath = Join-Path $resolvedRuntime "runtime-identity.json"

if (Test-Path -LiteralPath $resolvedData) {
    $hasData = @(Get-ChildItem -LiteralPath $resolvedData -Force -ErrorAction Stop).Count -gt 0
    if ($hasData -and -not (Test-Path -LiteralPath $markerPath -PathType Leaf)) {
        Fail "non-empty data directory has no matching testnet marker"
    }
}
if (Test-Path -LiteralPath $markerPath -PathType Leaf) {
    $marker = Get-Content -LiteralPath $markerPath -Raw | ConvertFrom-Json
    if ($marker.network -ne $ExpectedNetwork -or
        $marker.node_profile -ne $ExpectedProfile -or
        $marker.chain_id -ne $ExpectedChainId -or
        $marker.created_by -ne "controlled-pilot" -or
        (CanonicalPath $marker.data_dir) -ne $resolvedData) {
        Fail "existing testnet marker does not match this profile"
    }
}
if (Test-Path -LiteralPath $pidPath -PathType Leaf) {
    $oldPid = [int](Get-Content -LiteralPath $pidPath -Raw)
    if (Get-Process -Id $oldPid -ErrorAction SilentlyContinue) {
        Fail "profile already has a live process (PID $oldPid)"
    }
}

AssertPortFree $P2pPort
AssertPortFree $RpcPort
Write-Host "Profile guard: PASS"
Write-Host "Data directory: user-scoped and isolated"
Write-Host "API: http://127.0.0.1:$RpcPort"

if ($ValidateOnly) {
    Write-Host "Validation only; no files or processes created."
    exit 0
}

New-Item -ItemType Directory -Force -Path $resolvedData | Out-Null
New-Item -ItemType Directory -Force -Path $resolvedRuntime | Out-Null

$marker = [ordered]@{
    network = $ExpectedNetwork
    node_profile = $ExpectedProfile
    chain_id = $ExpectedChainId
    created_by = "controlled-pilot"
    data_dir = $resolvedData
}
$marker | ConvertTo-Json | Set-Content -LiteralPath $markerPath -Encoding utf8

$rendered = (Get-Content -LiteralPath $TemplatePath -Raw).
    Replace("@@DATA_DIR@@", ($resolvedData -replace '\\', '/')).
    Replace("@@P2P_PORT@@", "$P2pPort").
    Replace("@@RPC_PORT@@", "$RpcPort")
$rendered | Set-Content -LiteralPath $configPath -Encoding utf8

$stdout = Join-Path $resolvedRuntime "fullnode.out.log"
$stderr = Join-Path $resolvedRuntime "fullnode.err.log"
$node = Start-Process -FilePath $FullnodeExe -ArgumentList "`"$configPath`"" `
    -WorkingDirectory $resolvedRuntime -RedirectStandardOutput $stdout `
    -RedirectStandardError $stderr -PassThru -WindowStyle Hidden
$node.Id | Set-Content -LiteralPath $pidPath -Encoding ascii

$baseUrl = "http://127.0.0.1:$RpcPort"
try {
    $capabilities = $null
    for ($attempt = 0; $attempt -lt 30; $attempt++) {
        if ($node.HasExited) { Fail "fullnode exited during startup" }
        try {
            $capabilities = Invoke-RestMethod -Uri "$baseUrl/query/capabilities" -TimeoutSec 2
            break
        } catch {
            Start-Sleep -Milliseconds 500
        }
    }
    if (-not $capabilities) { Fail "capability endpoint did not become ready" }
    if ($capabilities.ret -ne 0 -or
        $capabilities.api_version -ne 1 -or
        $capabilities.node.name -ne "hacash-fullnode" -or
        $capabilities.node.version -ne $ExpectedNodeVersion -or
        $capabilities.chain.mainnet -ne $false -or
        $capabilities.chain.id -ne $ExpectedChainId -or
        2 -notin $capabilities.transactions.enabled -or
        1 -notin $capabilities.actions.enabled -or
        $capabilities.api.balance_query -ne $true -or
        $capabilities.api.transaction_submit -ne $true -or
        $capabilities.api.transaction_query -ne $true -or
        $capabilities.api.reconciliation_by_tx_hash -ne $true) {
        Fail "runtime capability identity mismatch"
    }

    $latest = Invoke-RestMethod -Uri "$baseUrl/query/latest" -TimeoutSec 3
    $identity = [ordered]@{
        verified_at_utc = [DateTime]::UtcNow.ToString("o")
        node_name = $capabilities.node.name
        node_version = $capabilities.node.version
        node_build_time = $capabilities.node.build_time
        capability_api_version = $capabilities.api_version
        chain_id = $capabilities.chain.id
        mainnet = $capabilities.chain.mainnet
        height = $capabilities.chain.height
        endpoint = $baseUrl
        block_one = $null
        transaction_ready = $false
    }
    if ([uint64]$capabilities.chain.height -ge 1) {
        $blockOne = Invoke-RestMethod -Uri "$baseUrl/query/block/intro?height=1" -TimeoutSec 3
        if ($blockOne.ret -eq 0 -and $blockOne.height -eq 1 -and $blockOne.hash -match "^[0-9a-fA-F]{64}$") {
            $identity.block_one = $blockOne.hash.ToLowerInvariant()
            $identity.transaction_ready = $true
        }
    }
    $identity | ConvertTo-Json | Set-Content -LiteralPath $identityPath -Encoding utf8
    Write-Host "Runtime identity: VERIFIED" -ForegroundColor Green
    Write-Host "Chain ID: $($identity.chain_id); mainnet: $($identity.mainnet); height: $($identity.height)"
    if (-not $identity.transaction_ready) {
        Write-Warning "No canonical block 1 is available. Agent Wallet signing remains blocked."
    }
    Write-Host "Fullnode PID: $($node.Id)"
} catch {
    StopLaunchedProcess $node
    Remove-Item -LiteralPath $pidPath -Force -ErrorAction SilentlyContinue
    throw
}

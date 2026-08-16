<#
.SYNOPSIS
Starts the isolated HPAY Local Pilot Chain V1 node.

.DESCRIPTION
This is a private development chain, never an official Hacash testnet. The
launcher uses a new user-scoped data directory, loopback API, no peers, no
UPnP, and exact runtime identity checks. It never deletes or migrates data.
#>

[CmdletBinding()]
param(
    [string] $FullnodeExe = "C:\Users\KQHEX\Documents\hacash-fullnodedev\target\hpay-local-pilot\release\fullnode.exe",
    [string] $DataDir = (Join-Path $env:LOCALAPPDATA "HPAY\agent-local-pilot-v1\data"),
    [string] $RuntimeDir = (Join-Path $env:LOCALAPPDATA "HPAY\agent-local-pilot-v1\runtime"),
    [ValidateRange(1, 65535)] [int] $P2pPort = 3197,
    [ValidateRange(1, 65535)] [int] $RpcPort = 8197,
    [string] $RewardAddress = "",
    [string] $PilotFundingAddress = "",
    [switch] $EnableMining,
    [switch] $ValidateOnly
)

$ErrorActionPreference = "Stop"
$ExpectedChainId = 7
$ExpectedNodeVersion = "1.0.10"
$ExpectedNetworkKind = "local_pilot_v1"
$ExpectedProfile = "hpay-local-pilot-chain-v1"
$TemplatePath = Join-Path $PSScriptRoot "agent-local-pilot\node.ini.template"
$RepoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$FullnodeRepoRoot = [IO.Path]::GetFullPath((Join-Path $RepoRoot "..\hacash-fullnodedev"))
$PilotRoot = [IO.Path]::GetFullPath((Join-Path $env:LOCALAPPDATA "HPAY\agent-local-pilot-v1"))

function Fail([string] $Message) { throw "HPAY Local Pilot guard: $Message" }
function CanonicalPath([string] $Path) { [IO.Path]::GetFullPath($Path).TrimEnd('\', '/') }
function IsWithin([string] $Child, [string] $Parent) {
    $prefix = (CanonicalPath $Parent) + [IO.Path]::DirectorySeparatorChar
    (CanonicalPath $Child).StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)
}
function AssertPortFree([int] $Port) {
    if (Get-NetTCPConnection -State Listen -LocalPort $Port -ErrorAction SilentlyContinue) {
        Fail "port $Port is already in use"
    }
}
function AssertNoReparsePoint([string] $Path) {
    $cursor = CanonicalPath $Path
    while ($cursor.StartsWith($PilotRoot, [StringComparison]::OrdinalIgnoreCase)) {
        if (Test-Path -LiteralPath $cursor) {
            $item = Get-Item -LiteralPath $cursor -Force
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                Fail "data or runtime path traverses a junction or symbolic link"
            }
        }
        if ($cursor -eq $PilotRoot) { break }
        $parent = Split-Path -Parent $cursor
        if ([string]::IsNullOrWhiteSpace($parent) -or $parent -eq $cursor) { break }
        $cursor = CanonicalPath $parent
    }
}
function IsHacashPrivateKeyAddress([string] $Address) {
    # Base58Check leading zeroes are not printed, so canonical Hacash
    # private-key addresses can be either 33 or 34 readable characters.
    # The fullnode config parser performs the authoritative checksum and
    # address-version validation before the node can start.
    $Address -match '^[13][1-9A-HJ-NP-Za-km-z]{32,33}$'
}
function StopLaunchedProcess($Process) {
    if ($Process -and -not $Process.HasExited) {
        Stop-Process -Id $Process.Id -Force -ErrorAction SilentlyContinue
    }
}

Write-Host "HPAY LOCAL PILOT CHAIN" -ForegroundColor Yellow
Write-Host "PRIVATE DEVELOPMENT NETWORK" -ForegroundColor Yellow
Write-Host "NO MAINNET FUNDS" -ForegroundColor Yellow
Write-Host "NOT HACASH PUBLIC TESTNET" -ForegroundColor Yellow

if ($P2pPort -eq $RpcPort) { Fail "P2P and API ports must differ" }
if (-not (Test-Path -LiteralPath $FullnodeExe -PathType Leaf)) { Fail "fullnode binary not found" }
if (-not (Test-Path -LiteralPath $TemplatePath -PathType Leaf)) { Fail "profile template not found" }
if ($EnableMining -and -not (IsHacashPrivateKeyAddress $RewardAddress)) {
    Fail "mining requires an explicit valid PRIVAKEY reward address"
}
if ($PilotFundingAddress -and -not (IsHacashPrivateKeyAddress $PilotFundingAddress)) {
    Fail "pilot funding address must be a valid PRIVAKEY address"
}

$resolvedData = CanonicalPath $DataDir
$resolvedRuntime = CanonicalPath $RuntimeDir
if (-not (IsWithin $resolvedData $PilotRoot) -or -not (IsWithin $resolvedRuntime $PilotRoot)) {
    Fail "data and runtime directories must stay under the versioned Local Pilot root"
}
if ($resolvedData -match '(?i)(^|[\\/])[^\\/]*mainnet[^\\/]*($|[\\/])') {
    Fail "data directory resembles a mainnet path"
}
if ((IsWithin $resolvedData $RepoRoot) -or (IsWithin $resolvedData $FullnodeRepoRoot)) {
    Fail "chain data must be outside source repositories"
}
if ($resolvedData -eq $resolvedRuntime -or (IsWithin $resolvedData $resolvedRuntime) -or
    (IsWithin $resolvedRuntime $resolvedData)) {
    Fail "runtime and chain data directories must be separate"
}
AssertNoReparsePoint $resolvedData
AssertNoReparsePoint $resolvedRuntime
AssertPortFree $P2pPort
AssertPortFree $RpcPort

$markerPath = Join-Path $resolvedRuntime "local-pilot-marker.json"
$configPath = Join-Path $resolvedRuntime "node.ini"
$pidPath = Join-Path $resolvedRuntime "fullnode.pid"
$identityPath = Join-Path $resolvedRuntime "runtime-identity.json"
if (Test-Path -LiteralPath $resolvedData) {
    $hasData = @(Get-ChildItem -LiteralPath $resolvedData -Force).Count -gt 0
    if ($hasData -and -not (Test-Path -LiteralPath $markerPath -PathType Leaf)) {
        Fail "non-empty data directory has no matching Local Pilot marker"
    }
}
if (Test-Path -LiteralPath $markerPath -PathType Leaf) {
    $marker = Get-Content -LiteralPath $markerPath -Raw | ConvertFrom-Json
    if ($marker.network_kind -ne $ExpectedNetworkKind -or
        $marker.node_profile_id -ne $ExpectedProfile -or
        $marker.chain_id -ne $ExpectedChainId -or
        $marker.created_by -ne "hpay-local-pilot-v1" -or
        (CanonicalPath $marker.data_dir) -ne $resolvedData) {
        Fail "existing marker does not match this Local Pilot instance"
    }
}
if (Test-Path -LiteralPath $pidPath -PathType Leaf) {
    $oldPid = [int](Get-Content -LiteralPath $pidPath -Raw)
    $oldProcess = Get-CimInstance Win32_Process -Filter "ProcessId=$oldPid" -ErrorAction SilentlyContinue
    if ($oldProcess) { Fail "profile already has a live process (PID $oldPid)" }
}

Write-Host "Profile guard: PASS"
Write-Host "Data directory: $resolvedData"
Write-Host "API: http://127.0.0.1:$RpcPort"
if ($ValidateOnly) {
    Write-Host "Validation only; no files or processes created."
    exit 0
}

New-Item -ItemType Directory -Force -Path $resolvedData | Out-Null
New-Item -ItemType Directory -Force -Path $resolvedRuntime | Out-Null
[ordered]@{
    network_kind = $ExpectedNetworkKind
    node_profile_id = $ExpectedProfile
    chain_id = $ExpectedChainId
    created_by = "hpay-local-pilot-v1"
    data_dir = $resolvedData
} | ConvertTo-Json | Set-Content -LiteralPath $markerPath -Encoding utf8

$fundingLine = if ($PilotFundingAddress) {
    "pilot_funding_address = $PilotFundingAddress"
} else {
    "; pilot_funding_address intentionally unset until an Agent Wallet address exists"
}
$rendered = (Get-Content -LiteralPath $TemplatePath -Raw).
    Replace("@@DATA_DIR@@", ($resolvedData -replace '\\', '/')).
    Replace("@@P2P_PORT@@", "$P2pPort").
    Replace("@@RPC_PORT@@", "$RpcPort").
    Replace("@@PILOT_FUNDING_LINE@@", $fundingLine).
    Replace("@@MINER_ENABLED@@", $(if ($EnableMining) { "true" } else { "false" })).
    Replace("@@REWARD_ADDRESS@@", $RewardAddress)
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
        } catch { Start-Sleep -Milliseconds 500 }
    }
    if (-not $capabilities) { Fail "capability endpoint did not become ready" }
    if ($capabilities.ret -ne 0 -or
        $capabilities.api_version -ne 1 -or
        $capabilities.node.name -ne "hacash-fullnode" -or
        $capabilities.node.version -ne $ExpectedNodeVersion -or
        $capabilities.chain.mainnet -ne $false -or
        $capabilities.chain.id -ne $ExpectedChainId -or
        $capabilities.network.kind -ne $ExpectedNetworkKind -or
        $capabilities.network.node_profile_id -ne $ExpectedProfile -or
        $capabilities.network.current_height -ne $capabilities.chain.height -or
        $capabilities.network.transaction_format_version -ne 2 -or
        2 -notin $capabilities.transactions.enabled -or
        1 -notin $capabilities.actions.enabled -or
        $capabilities.api.balance_query -ne $true -or
        $capabilities.api.transaction_submit -ne $true -or
        $capabilities.api.transaction_submit_bound -ne $true -or
        $capabilities.api.transaction_query -ne $true -or
        $capabilities.api.reconciliation_by_tx_hash -ne $true) {
        Fail "runtime identity or transaction API contract mismatch"
    }
    if ($capabilities.network.block_1_available) {
        $blockOne = Invoke-RestMethod -Uri "$baseUrl/query/block/intro?height=1" -TimeoutSec 3
        if ($blockOne.ret -ne 0 -or $blockOne.height -ne 1 -or
            $blockOne.hash.ToLowerInvariant() -ne $capabilities.network.block_1_hash) {
            Fail "canonical block 1 query does not match the capability contract"
        }
    }
    [ordered]@{
        verified_at_utc = [DateTime]::UtcNow.ToString("o")
        node_name = $capabilities.node.name
        node_version = $capabilities.node.version
        network_kind = $capabilities.network.kind
        node_profile_id = $capabilities.network.node_profile_id
        chain_id = $capabilities.chain.id
        mainnet = $capabilities.chain.mainnet
        height = $capabilities.chain.height
        endpoint = $baseUrl
        block_one = $capabilities.network.block_1_hash
        network_instance_id = $capabilities.network.instance_id
        funding_confirmed = $capabilities.network.funding_confirmed
        transaction_ready = $capabilities.network.transaction_ready
    } | ConvertTo-Json | Set-Content -LiteralPath $identityPath -Encoding utf8
    Write-Host "Runtime identity: VERIFIED" -ForegroundColor Green
    Write-Host "Height: $($capabilities.chain.height); transaction-ready: $($capabilities.network.transaction_ready)"
    Write-Host "Fullnode PID: $($node.Id)"
} catch {
    StopLaunchedProcess $node
    Remove-Item -LiteralPath $pidPath -Force -ErrorAction SilentlyContinue
    throw
}

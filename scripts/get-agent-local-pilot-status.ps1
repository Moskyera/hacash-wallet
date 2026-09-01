[CmdletBinding()]
param(
    [ValidateRange(1, 65535)] [int] $RpcPort = 8197,
    [string] $RuntimeDir = (Join-Path $env:LOCALAPPDATA "HPAY\agent-local-pilot-v1\runtime")
)
$ErrorActionPreference = "Stop"
function Fail([string] $Message) { throw "HPAY Local Pilot status guard: $Message" }
$baseUrl = "http://127.0.0.1:$RpcPort"
$capabilities = Invoke-RestMethod -Uri "$baseUrl/query/capabilities" -TimeoutSec 3
if ($capabilities.ret -ne 0 -or $capabilities.chain.id -ne 7 -or
    $capabilities.chain.mainnet -ne $false -or
    $capabilities.network.kind -ne "local_pilot_v1" -or
    $capabilities.network.node_profile_id -ne "hpay-local-pilot-chain-v1" -or
    $capabilities.network.current_height -ne $capabilities.chain.height -or
    $capabilities.network.transaction_format_version -ne 2 -or
    $capabilities.api.transaction_submit_bound -ne $true) {
    Fail "endpoint identity does not match HPAY Local Pilot Chain V1"
}
$blockOne = $null
if ($capabilities.network.block_1_available) {
    $intro = Invoke-RestMethod -Uri "$baseUrl/query/block/intro?height=1" -TimeoutSec 3
    if ($intro.ret -ne 0 -or $intro.height -ne 1 -or
        $intro.hash.ToLowerInvariant() -ne $capabilities.network.block_1_hash) {
        Fail "block 1 capability and canonical query disagree"
    }
    $blockOne = $intro.hash.ToLowerInvariant()
}
$status = [ordered]@{
    verified_at_utc = [DateTime]::UtcNow.ToString("o")
    evidence_category = "LOCAL_PRIVATE_CHAIN"
    node_name = $capabilities.node.name
    node_version = $capabilities.node.version
    network_kind = $capabilities.network.kind
    node_profile_id = $capabilities.network.node_profile_id
    chain_id = $capabilities.chain.id
    mainnet = $capabilities.chain.mainnet
    height = $capabilities.chain.height
    endpoint = $baseUrl
    block_one = $blockOne
    network_instance_id = $capabilities.network.instance_id
    funding_confirmed = $capabilities.network.funding_confirmed
    transaction_ready = $capabilities.network.transaction_ready
}
New-Item -ItemType Directory -Force -Path $RuntimeDir | Out-Null
$status | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $RuntimeDir "runtime-identity.json") -Encoding utf8
$status | ConvertTo-Json

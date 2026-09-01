<#
.SYNOPSIS
Stops the guarded Local Pilot worker at an exact public funding target.

.DESCRIPTION
This watcher never signs or submits a transaction. It reads only the exact
loopback Local Pilot capability and balance APIs, then stops only the worker
recorded by this profile after validating its command line. Any network
identity drift or repeated API failure also stops the worker fail closed.
#>

[CmdletBinding()]
param(
    [string] $RuntimeDir = (Join-Path $env:LOCALAPPDATA "HPAY\agent-local-pilot-v1\runtime"),
    [ValidateRange(1, [uint64]::MaxValue)] [uint64] $TargetZhu = 20300000000,
    [ValidateRange(1, 60)] [int] $PollSeconds = 5,
    [ValidateRange(1, 60)] [int] $MaxConsecutiveFailures = 12
)

$ErrorActionPreference = "Stop"
$ExpectedBlockOne = "000087f67e55660eaefed72e0b9499147556a33a34f18fa48900f4a2fa30cd29"
$ExpectedInstance = "9ebd8657a72faed35ed4d6e309fab2ef259f054e4820684fab6c6b848e4438f3"
$FundingAddress = "1KCRLdAATCyeEPPtYn27RpJTdLV9Ueamk"
$BaseUrl = "http://127.0.0.1:8197"
$PidPath = Join-Path $RuntimeDir "poworker.pid"
$MonitorPidPath = Join-Path $RuntimeDir "funding-watcher.pid"
$LogPath = Join-Path $RuntimeDir "funding-watcher.log"

function Write-Status([string] $Message) {
    "{0:o} {1}" -f [DateTime]::UtcNow, $Message | Add-Content -LiteralPath $LogPath -Encoding utf8
}

function Stop-ExactWorker([string] $Reason) {
    if (-not (Test-Path -LiteralPath $PidPath -PathType Leaf)) {
        Write-Status "$Reason; no worker PID file exists"
        return
    }
    $workerPid = [int](Get-Content -LiteralPath $PidPath -Raw)
    $process = Get-CimInstance Win32_Process -Filter "ProcessId=$workerPid" -ErrorAction SilentlyContinue
    $expectedConfig = [IO.Path]::GetFullPath((Join-Path $RuntimeDir "poworker.ini"))
    if ($process -and $process.Name -eq "poworker.exe" -and
        $process.CommandLine -and $process.CommandLine.Contains($expectedConfig)) {
        Stop-Process -Id $workerPid -Force -ErrorAction Stop
        Write-Status "$Reason; stopped guarded worker PID $workerPid"
    } elseif ($process) {
        Write-Status "$Reason; refused to stop PID $workerPid because its identity changed"
    } else {
        Write-Status "$Reason; worker PID $workerPid is no longer running"
    }
}

New-Item -ItemType Directory -Force -Path $RuntimeDir | Out-Null
$PID | Set-Content -LiteralPath $MonitorPidPath -Encoding ascii
$failures = 0
try {
    Write-Status "watcher started; target_zhu=$TargetZhu address=$FundingAddress"
    while ($true) {
        try {
            $capabilities = Invoke-RestMethod -Uri "$BaseUrl/query/capabilities" -TimeoutSec 5
            if ($capabilities.ret -ne 0 -or $capabilities.chain.id -ne 7 -or
                $capabilities.chain.mainnet -ne $false -or
                $capabilities.network.kind -ne "local_pilot_v1" -or
                $capabilities.network.block_1_hash -ne $ExpectedBlockOne -or
                $capabilities.network.instance_id -ne $ExpectedInstance) {
                Stop-ExactWorker "network identity drift"
                exit 2
            }
            $balance = Invoke-RestMethod -Uri "$BaseUrl/query/balance?unit=zhu&address=$FundingAddress" -TimeoutSec 5
            if ($balance.ret -ne 0 -or @($balance.list).Count -ne 1) {
                throw "balance response contract mismatch"
            }
            $observed = [uint64]$balance.list[0].hacash
            $failures = 0
            if ($observed -ge $TargetZhu) {
                Stop-ExactWorker "funding target reached at height $($capabilities.chain.height), balance_zhu=$observed"
                exit 0
            }
        } catch {
            $failures++
            Write-Status "probe failure $failures/${MaxConsecutiveFailures}: $($_.Exception.Message)"
            if ($failures -ge $MaxConsecutiveFailures) {
                Stop-ExactWorker "repeated node probe failure"
                exit 3
            }
        }
        Start-Sleep -Seconds $PollSeconds
    }
} finally {
    Remove-Item -LiteralPath $MonitorPidPath -Force -ErrorAction SilentlyContinue
}

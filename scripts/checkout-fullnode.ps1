param(
    [string] $Destination,
    [string] $Repository = "https://github.com/Moskyera/fullnodedev.git"
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$revisionFile = Join-Path $root ".github\fullnode-revision"

if (-not (Test-Path -LiteralPath $revisionFile -PathType Leaf)) {
    throw "Pinned fullnodedev revision is missing: $revisionFile"
}

$revision = (Get-Content -LiteralPath $revisionFile -Raw).Trim().ToLowerInvariant()
if ($revision -notmatch '^[0-9a-f]{40}$') {
    throw ".github/fullnode-revision must contain exactly one full 40-character commit SHA"
}

if ([string]::IsNullOrWhiteSpace($Destination)) {
    $Destination = Join-Path (Split-Path -Parent $root) "hacash-fullnodedev"
}
$Destination = [System.IO.Path]::GetFullPath($Destination)

function Invoke-Git {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]] $GitArguments)
    & git @GitArguments
    if ($LASTEXITCODE -ne 0) {
        throw "git command failed with exit code $LASTEXITCODE"
    }
}

if (Test-Path -LiteralPath $Destination) {
    $gitDir = Join-Path $Destination ".git"
    if (-not (Test-Path -LiteralPath $gitDir)) {
        throw "Refusing to replace existing non-git directory: $Destination"
    }

    $current = (& git -C $Destination rev-parse HEAD 2>$null).Trim().ToLowerInvariant()
    $dirty = @(& git -C $Destination status --porcelain)
    if ($LASTEXITCODE -eq 0 -and $current -eq $revision -and $dirty.Count -eq 0) {
        Write-Host "Pinned fullnodedev checkout already present: $revision"
        exit 0
    }
    throw "Refusing to modify an existing fullnodedev checkout at $Destination (HEAD $current)"
}

New-Item -ItemType Directory -Path $Destination | Out-Null
try {
    Invoke-Git -C $Destination init
    Invoke-Git -C $Destination remote add origin $Repository
    Invoke-Git -C $Destination fetch --no-tags --depth 1 origin $revision
    Invoke-Git -C $Destination checkout --detach FETCH_HEAD

    $resolved = (& git -C $Destination rev-parse HEAD).Trim().ToLowerInvariant()
    if ($LASTEXITCODE -ne 0 -or $resolved -ne $revision) {
        throw "fullnodedev checkout resolved to $resolved, expected $revision"
    }
    if (@(& git -C $Destination status --porcelain).Count -ne 0) {
        throw "Pinned fullnodedev checkout is unexpectedly dirty"
    }
} catch {
    throw "Unable to create pinned fullnodedev checkout at ${Destination}: $($_.Exception.Message)"
}

Write-Host "Pinned fullnodedev checkout verified: $revision"

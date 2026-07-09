# Switch wallet node profile in %APPDATA%\HacashWallet\settings.json
# Usage:
#   .\scripts\switch-node-profile.ps1 -Profile public
#   .\scripts\switch-node-profile.ps1 -Profile local

param(
    [ValidateSet("public", "local")]
    [string]$Profile = "public"
)

$settingsPath = Join-Path $env:APPDATA "HacashWallet\settings.json"
if (-not (Test-Path $settingsPath)) {
    Write-Error "Settings not found: $settingsPath"
    exit 1
}

$settings = Get-Content $settingsPath -Raw | ConvertFrom-Json

switch ($Profile) {
    "public" {
        $settings.node_url = "http://nodeapi.hacash.org"
        Write-Host "Profile: PUBLIC mainnet (privacy demo / real mainnet)" -ForegroundColor Cyan
        Write-Host "  Reads:  wallet -> nodeapi.hacash.org (your IP visible)"
        Write-Host "  Submit: wallet -> whisper relay -> nodeapi (relay IP visible)"
    }
    "local" {
        $settings.node_url = "http://127.0.0.1:8080"
        Write-Host "Profile: LOCAL dev fullnode (your test coins)" -ForegroundColor Cyan
        Write-Host "  Reads + relay forward: localhost"
    }
}

# Keep whisper relay list clean (never point relay URLs at the fullnode port)
$settings.dust_whisper.enabled = $true
$settings.dust_whisper.relay_urls = @("http://127.0.0.1:8787")
$settings.dust_whisper.fallback_direct = $false
$settings.dust_whisper.auto_start_relay = $true

$settings | ConvertTo-Json -Depth 6 -Compress | Set-Content $settingsPath -Encoding UTF8
Write-Host "Saved $settingsPath"
Write-Host "Restart the wallet app to apply (relay auto-restarts with new node URL)."
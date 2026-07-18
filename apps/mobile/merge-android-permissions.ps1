# Merge src-tauri/android-permissions.xml into generated AndroidManifest.xml
$ErrorActionPreference = "Stop"
$mobile = Split-Path -Parent $MyInvocation.MyCommand.Path
$manifestPath = Join-Path $mobile "src-tauri/gen/android/app/src/main/AndroidManifest.xml"
$manifest = Get-Item -LiteralPath $manifestPath -ErrorAction SilentlyContinue
$permsFile = Join-Path $mobile "src-tauri/android-permissions.xml"

if (-not $manifest) {
    throw "AndroidManifest.xml not found under src-tauri/gen/android. Run: yarn tauri android init"
}
if (-not (Test-Path $permsFile)) {
    throw "Permissions template not found: $permsFile"
}

$content = Get-Content $manifest.FullName -Raw
$lines = Get-Content $permsFile | Where-Object { $_ -match 'uses-permission|uses-feature' }

foreach ($line in $lines) {
    $trim = $line.Trim()
    if ([string]::IsNullOrWhiteSpace($trim) -or $trim.StartsWith("<!--")) { continue }
    if ($content -notmatch [regex]::Escape($trim)) {
        $content = $content -replace '(<manifest[^>]*>)', "`$1`r`n    $trim"
        Write-Host "Added: $trim" -ForegroundColor Green
    } else {
        Write-Host "Already present: $trim" -ForegroundColor DarkGray
    }
}

Set-Content -Path $manifest.FullName -Value $content -NoNewline
Write-Host "Updated $($manifest.FullName)" -ForegroundColor Cyan

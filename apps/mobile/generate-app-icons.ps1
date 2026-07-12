# Generate Hacash Wallet launcher icons from glossy symbol only (mosky.png — no text).
$ErrorActionPreference = "Stop"
$mobile = Split-Path -Parent $MyInvocation.MyCommand.Path
$icons = Join-Path $mobile "src-tauri\icons"
$androidRoot = Join-Path $icons "android"
$srcIcon = Join-Path $mobile "src\assets\mosky.png"
$fgOut = Join-Path $icons "android-fg.png"
$appIcon = Join-Path $icons "app-icon.png"
$fillRatio = 0.92

Add-Type -AssemblyName System.Drawing

function New-SquareBitmap([int]$size, [System.Drawing.Color]$clear) {
    $bmp = New-Object System.Drawing.Bitmap $size, $size
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::HighQuality
    $g.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
    $g.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
    $g.CompositingQuality = [System.Drawing.Drawing2D.CompositingQuality]::HighQuality
    $g.Clear($clear)
    return @{ Bitmap = $bmp; Graphics = $g }
}

function Draw-FullImage(
    [System.Drawing.Graphics]$g,
    [System.Drawing.Image]$src,
    [int]$canvasSize,
    [double]$fill
) {
    $target = [int][Math]::Floor($canvasSize * $fill)
    $scale = [Math]::Min($target / $src.Width, $target / $src.Height)
    $w = [int][Math]::Round($src.Width * $scale)
    $h = [int][Math]::Round($src.Height * $scale)
    $x = [int][Math]::Round(($canvasSize - $w) / 2)
    $y = [int][Math]::Round(($canvasSize - $h) / 2)
    $dstRect = New-Object System.Drawing.Rectangle $x, $y, $w, $h
    $g.DrawImage($src, $dstRect)
}

function Write-MipmapPng(
    [System.Drawing.Image]$src,
    [string]$dstPath,
    [int]$size,
    [System.Drawing.Color]$clear,
    [double]$fill
) {
    $parent = Split-Path -Parent $dstPath
    if (-not (Test-Path $parent)) { New-Item -ItemType Directory -Force -Path $parent | Out-Null }
    $canvas = New-SquareBitmap $size $clear
    Draw-FullImage $canvas.Graphics $src $size $fill
    $canvas.Bitmap.Save($dstPath, [System.Drawing.Imaging.ImageFormat]::Png)
    $canvas.Graphics.Dispose(); $canvas.Bitmap.Dispose()
}

function Write-AndroidMipmaps([string]$srcPath, [string]$fileBase, [hashtable]$sizes, [System.Drawing.Color]$clear, [double]$fill) {
    $src = [System.Drawing.Image]::FromFile($srcPath)
    try {
        foreach ($density in $sizes.Keys) {
            $px = $sizes[$density]
            $dir = Join-Path $androidRoot ("mipmap-" + $density)
            $dst = Join-Path $dir ($fileBase + ".png")
            Write-MipmapPng $src $dst $px $clear $fill
            Write-Host "Wrote $dst (${px}px)" -ForegroundColor DarkGray
        }
    } finally {
        $src.Dispose()
    }
}

$launcherSizes = @{
    mdpi    = 48
    hdpi    = 72
    xhdpi   = 96
    xxhdpi  = 144
    xxxhdpi = 192
}
$foregroundSizes = @{
    mdpi    = 108
    hdpi    = 162
    xhdpi   = 216
    xxhdpi  = 324
    xxxhdpi = 432
}

$size = 1024
$srcBmp = New-Object System.Drawing.Bitmap $srcIcon
Write-Host "Source artwork: $($srcBmp.Width)x$($srcBmp.Height)" -ForegroundColor Cyan

$fgCanvas = New-SquareBitmap $size ([System.Drawing.Color]::Transparent)
Draw-FullImage $fgCanvas.Graphics $srcBmp $size $fillRatio
$fgCanvas.Bitmap.Save($fgOut, [System.Drawing.Imaging.ImageFormat]::Png)
$fgCanvas.Graphics.Dispose(); $fgCanvas.Bitmap.Dispose()
Write-Host "Wrote $fgOut" -ForegroundColor Green

$appCanvas = New-SquareBitmap $size ([System.Drawing.Color]::FromArgb(255, 0, 0, 0))
Draw-FullImage $appCanvas.Graphics $srcBmp $size $fillRatio
$appCanvas.Bitmap.Save($appIcon, [System.Drawing.Imaging.ImageFormat]::Png)
$appCanvas.Graphics.Dispose(); $appCanvas.Bitmap.Dispose()
$srcBmp.Dispose()
Write-Host "Wrote $appIcon" -ForegroundColor Green

Set-Location $mobile
yarn tauri icon "src-tauri/icons/icon-manifest.json"
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
Write-Host "Tauri icon set generated (ico/icns/icon.png)." -ForegroundColor Green

# Tauri CLI does not reliably refresh icons/android/mipmap-* — write glossy mipmaps explicitly.
if (Test-Path $androidRoot) {
    Get-ChildItem -Path $androidRoot -Directory -Filter "mipmap-*" | Remove-Item -Recurse -Force
}
Write-AndroidMipmaps $appIcon "ic_launcher" $launcherSizes ([System.Drawing.Color]::FromArgb(255, 0, 0, 0)) $fillRatio
Write-AndroidMipmaps $appIcon "ic_launcher_round" $launcherSizes ([System.Drawing.Color]::FromArgb(255, 0, 0, 0)) $fillRatio
Write-AndroidMipmaps $fgOut "ic_launcher_foreground" $foregroundSizes ([System.Drawing.Color]::Transparent) $fillRatio

$anydpi = Join-Path $androidRoot "mipmap-anydpi-v26"
New-Item -ItemType Directory -Force -Path $anydpi | Out-Null
@'
<?xml version="1.0" encoding="utf-8"?>
<adaptive-icon xmlns:android="http://schemas.android.com/apk/res/android">
  <foreground android:drawable="@mipmap/ic_launcher_foreground"/>
  <background android:drawable="@color/ic_launcher_background"/>
</adaptive-icon>
'@ | Set-Content -Path (Join-Path $anydpi "ic_launcher.xml") -Encoding UTF8 -NoNewline
@'
<?xml version="1.0" encoding="utf-8"?>
<adaptive-icon xmlns:android="http://schemas.android.com/apk/res/android">
  <foreground android:drawable="@mipmap/ic_launcher_foreground"/>
  <background android:drawable="@color/ic_launcher_background"/>
</adaptive-icon>
'@ | Set-Content -Path (Join-Path $anydpi "ic_launcher_round.xml") -Encoding UTF8 -NoNewline
Write-Host "Android launcher mipmaps synced (glossy artwork)." -ForegroundColor Green
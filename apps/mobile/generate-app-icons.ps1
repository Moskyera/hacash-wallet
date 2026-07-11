# Generate Hacash Wallet launcher icons from brand assets (hb-icon / hwm-icon).
$ErrorActionPreference = "Stop"
$mobile = Split-Path -Parent $MyInvocation.MyCommand.Path
$icons = Join-Path $mobile "src-tauri\icons"
$srcIcon = Join-Path $mobile "src\assets\hb-icon.png"
$fgOut = Join-Path $icons "android-fg.png"
$appIcon = Join-Path $icons "app-icon.png"

Add-Type -AssemblyName System.Drawing

function New-SquareBitmap([int]$size, [System.Drawing.Color]$clear) {
    $bmp = New-Object System.Drawing.Bitmap $size, $size
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::HighQuality
    $g.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
    $g.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
    $g.Clear($clear)
    return @{ Bitmap = $bmp; Graphics = $g }
}

# Foreground: golden mark on transparent (adaptive icon safe zone).
$size = 1024
$src = [System.Drawing.Image]::FromFile($srcIcon)
$canvas = New-SquareBitmap $size ([System.Drawing.Color]::Transparent)
$scale = [Math]::Min(($size * 0.62) / $src.Width, ($size * 0.62) / $src.Height)
$w = [int][Math]::Round($src.Width * $scale)
$h = [int][Math]::Round($src.Height * $scale)
$x = [int](($size - $w) / 2)
$y = [int](($size - $h) / 2)
$canvas.Graphics.DrawImage($src, $x, $y, $w, $h)
$canvas.Bitmap.Save($fgOut, [System.Drawing.Imaging.ImageFormat]::Png)
$canvas.Graphics.Dispose(); $canvas.Bitmap.Dispose(); $src.Dispose()
Write-Host "Wrote $fgOut" -ForegroundColor Green

# App icon: golden mark on black (legacy + iOS + store).
$src2 = [System.Drawing.Image]::FromFile($srcIcon)
$canvas2 = New-SquareBitmap $size ([System.Drawing.Color]::FromArgb(255, 0, 0, 0))
$canvas2.Graphics.DrawImage($src2, $x, $y, $w, $h)
$canvas2.Bitmap.Save($appIcon, [System.Drawing.Imaging.ImageFormat]::Png)
$canvas2.Graphics.Dispose(); $canvas2.Bitmap.Dispose(); $src2.Dispose()
Write-Host "Wrote $appIcon" -ForegroundColor Green

Set-Location $mobile
yarn tauri icon "src-tauri/icons/icon-manifest.json"
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
Write-Host "Tauri icon set generated." -ForegroundColor Green
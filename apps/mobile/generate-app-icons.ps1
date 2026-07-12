# Generate Hacash Wallet launcher icons from full glossy brand artwork (nhw → hb-icon.png).
$ErrorActionPreference = "Stop"
$mobile = Split-Path -Parent $MyInvocation.MyCommand.Path
$icons = Join-Path $mobile "src-tauri\icons"
$srcIcon = Join-Path $mobile "src\assets\hb-icon.png"
$fgOut = Join-Path $icons "android-fg.png"
$appIcon = Join-Path $icons "app-icon.png"
$fillRatio = 0.88

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
Write-Host "Tauri icon set generated." -ForegroundColor Green
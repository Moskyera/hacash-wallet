# Generate Hacash Wallet launcher icons from brand assets (hb-icon).
# Content-aware centering + larger fill for symmetric Android adaptive icons.
$ErrorActionPreference = "Stop"
$mobile = Split-Path -Parent $MyInvocation.MyCommand.Path
$icons = Join-Path $mobile "src-tauri\icons"
$srcIcon = Join-Path $mobile "src\assets\hb-icon.png"
$fgOut = Join-Path $icons "android-fg.png"
$appIcon = Join-Path $icons "app-icon.png"
$fillRatio = 0.82

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

function Get-MarkBounds([System.Drawing.Bitmap]$bmp) {
    $minX = $bmp.Width
    $minY = $bmp.Height
    $maxX = -1
    $maxY = -1
    for ($y = 0; $y -lt $bmp.Height; $y++) {
        for ($x = 0; $x -lt $bmp.Width; $x++) {
            $c = $bmp.GetPixel($x, $y)
            if ($c.A -lt 24) { continue }
            if ($c.R -lt 48 -and $c.G -lt 48 -and $c.B -lt 48) { continue }
            if ($x -lt $minX) { $minX = $x }
            if ($y -lt $minY) { $minY = $y }
            if ($x -gt $maxX) { $maxX = $x }
            if ($y -gt $maxY) { $maxY = $y }
        }
    }
    if ($maxX -lt 0) { throw "No mark pixels found in $srcIcon" }
    return @{
        X = $minX
        Y = $minY
        W = $maxX - $minX + 1
        H = $maxY - $minY + 1
    }
}

function Draw-CenteredMark(
    [System.Drawing.Graphics]$g,
    [System.Drawing.Image]$src,
    [hashtable]$bounds,
    [int]$canvasSize,
    [double]$fill
) {
    $target = [int][Math]::Floor($canvasSize * $fill)
    $scale = [Math]::Min($target / $bounds.W, $target / $bounds.H)
    $w = [int][Math]::Round($bounds.W * $scale)
    $h = [int][Math]::Round($bounds.H * $scale)
    $x = [int][Math]::Round(($canvasSize - $w) / 2)
    $y = [int][Math]::Round(($canvasSize - $h) / 2)
    $srcRect = New-Object System.Drawing.Rectangle $bounds.X, $bounds.Y, $bounds.W, $bounds.H
    $dstRect = New-Object System.Drawing.Rectangle $x, $y, $w, $h
    $g.DrawImage($src, $dstRect, $srcRect, [System.Drawing.GraphicsUnit]::Pixel)
}

$size = 1024
$srcBmp = New-Object System.Drawing.Bitmap $srcIcon
$bounds = Get-MarkBounds $srcBmp
Write-Host "Mark bounds: $($bounds.W)x$($bounds.H) at ($($bounds.X),$($bounds.Y))" -ForegroundColor Cyan

$fgCanvas = New-SquareBitmap $size ([System.Drawing.Color]::Transparent)
Draw-CenteredMark $fgCanvas.Graphics $srcBmp $bounds $size $fillRatio
$fgCanvas.Bitmap.Save($fgOut, [System.Drawing.Imaging.ImageFormat]::Png)
$fgCanvas.Graphics.Dispose(); $fgCanvas.Bitmap.Dispose()
Write-Host "Wrote $fgOut" -ForegroundColor Green

$appCanvas = New-SquareBitmap $size ([System.Drawing.Color]::FromArgb(255, 0, 0, 0))
Draw-CenteredMark $appCanvas.Graphics $srcBmp $bounds $size $fillRatio
$appCanvas.Bitmap.Save($appIcon, [System.Drawing.Imaging.ImageFormat]::Png)
$appCanvas.Graphics.Dispose(); $appCanvas.Bitmap.Dispose()
$srcBmp.Dispose()
Write-Host "Wrote $appIcon" -ForegroundColor Green

Set-Location $mobile
yarn tauri icon "src-tauri/icons/icon-manifest.json"
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
Write-Host "Tauri icon set generated." -ForegroundColor Green
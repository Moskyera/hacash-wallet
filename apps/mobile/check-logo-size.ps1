Add-Type -AssemblyName System.Drawing
$m = [System.Drawing.Image]::FromFile('C:\Users\KQHEX\Downloads\nhw.png')
$d = [System.Drawing.Image]::FromFile('C:\Users\KQHEX\Downloads\dnhw.png')
Write-Output "nhw: $($m.Width)x$($m.Height)"
Write-Output "dnhw: $($d.Width)x$($d.Height)"
$m.Dispose()
$d.Dispose()
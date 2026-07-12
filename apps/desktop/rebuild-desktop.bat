@echo off
setlocal
set "ROOT=C:\Users\KQHEX\Documents\moskyera-quantum-wallet"
set "DESKTOP=%ROOT%\apps\desktop"
set "LOG=%DESKTOP%\rebuild-desktop.log"

for /f "delims=" %%V in ('powershell -NoProfile -Command "(Get-Content '%DESKTOP%\package.json' -Raw | ConvertFrom-Json).version"') do set "VER=%%V"

echo === desktop v%VER% rebuild started %DATE% %TIME% === > "%LOG%"

powershell -ExecutionPolicy Bypass -File "%DESKTOP%\sync-app-version.ps1" >> "%LOG%" 2>&1
if errorlevel 1 goto fail

cd /d "%DESKTOP%"
powershell -ExecutionPolicy Bypass -File "%DESKTOP%\generate-app-icons.ps1" >> "%LOG%" 2>&1
if errorlevel 1 goto fail

call yarn build >> "%LOG%" 2>&1
if errorlevel 1 goto fail

call yarn tauri build >> "%LOG%" 2>&1
if errorlevel 1 goto fail

if not exist "%ROOT%\releases" mkdir "%ROOT%\releases"

copy /Y "%ROOT%\target\release\bundle\nsis\Hacash Wallet_%VER%_x64-setup.exe" "%ROOT%\releases\hacash-wallet-desktop-v%VER%-x64-setup.exe" >> "%LOG%" 2>&1
copy /Y "%ROOT%\target\release\bundle\msi\Hacash Wallet_%VER%_x64_en-US.msi" "%ROOT%\releases\hacash-wallet-desktop-v%VER%-x64.msi" >> "%LOG%" 2>&1
copy /Y "%ROOT%\target\release\hacash-wallet.exe" "%ROOT%\releases\hacash-wallet-desktop-v%VER%-x64-portable.exe" >> "%LOG%" 2>&1

echo === desktop v%VER% rebuild OK %DATE% %TIME% === >> "%LOG%"
echo Releases: %ROOT%\releases\hacash-wallet-desktop-v%VER%-x64-*
exit /b 0

:fail
echo === desktop v%VER% rebuild FAILED %DATE% %TIME% === >> "%LOG%"
exit /b 1
@echo off
setlocal
set "ROOT=C:\Users\KQHEX\Documents\moskyera-quantum-wallet"
set "DESKTOP=%ROOT%\apps\desktop"
set "LOG=%DESKTOP%\rebuild-desktop.log"
set "VER=0.1.17"

echo === desktop v%VER% rebuild started %DATE% %TIME% === > "%LOG%"

cd /d "%DESKTOP%"
call yarn build >> "%LOG%" 2>&1
if errorlevel 1 goto fail

call yarn tauri build >> "%LOG%" 2>&1
if errorlevel 1 goto fail

if not exist "%ROOT%\releases" mkdir "%ROOT%\releases"

copy /Y "%ROOT%\target\release\bundle\nsis\Hacash Wallet_0.1.17_x64-setup.exe" "%ROOT%\releases\hacash-wallet-desktop-v%VER%-x64-setup.exe" >> "%LOG%" 2>&1
copy /Y "%ROOT%\target\release\bundle\msi\Hacash Wallet_0.1.17_x64_en-US.msi" "%ROOT%\releases\hacash-wallet-desktop-v%VER%-x64.msi" >> "%LOG%" 2>&1
copy /Y "%ROOT%\target\release\hacash-wallet.exe" "%ROOT%\releases\hacash-wallet-desktop-v%VER%-x64-portable.exe" >> "%LOG%" 2>&1

echo === desktop v%VER% rebuild OK %DATE% %TIME% === >> "%LOG%"
exit /b 0

:fail
echo === desktop v%VER% rebuild FAILED %DATE% %TIME% === >> "%LOG%"
exit /b 1
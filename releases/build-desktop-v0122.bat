@echo off
setlocal
cd /d "C:\Users\KQHEX\Documents\moskyera-quantum-wallet\apps\desktop"
echo === desktop tauri build started %DATE% %TIME% === > "C:\Users\KQHEX\Documents\moskyera-quantum-wallet\releases\desktop-build.log"
yarn tauri build >> "C:\Users\KQHEX\Documents\moskyera-quantum-wallet\releases\desktop-build.log" 2>&1
if errorlevel 1 (
  echo === desktop tauri build FAILED %DATE% %TIME% === >> "C:\Users\KQHEX\Documents\moskyera-quantum-wallet\releases\desktop-build.log"
  exit /b 1
)
echo === desktop tauri build OK %DATE% %TIME% === >> "C:\Users\KQHEX\Documents\moskyera-quantum-wallet\releases\desktop-build.log"
exit /b 0
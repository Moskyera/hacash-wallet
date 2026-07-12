@echo off
setlocal
set "JAVA_HOME=C:\Program Files\Android\Android Studio\jbr"
set "PATH=%JAVA_HOME%\bin;%PATH%"
set "ROOT=C:\Users\KQHEX\Documents\moskyera-quantum-wallet"
set "LOG=%ROOT%\releases\gradle-mobile.log"

echo === gradle assembleUniversalRelease started %DATE% %TIME% === > "%LOG%"
cd /d "%ROOT%\apps\mobile\src-tauri\gen\android"
call gradlew.bat assembleUniversalRelease --no-daemon >> "%LOG%" 2>&1
if errorlevel 1 (
  echo === gradle FAILED %DATE% %TIME% === >> "%LOG%"
  exit /b 1
)
copy /Y "%ROOT%\apps\mobile\src-tauri\gen\android\app\build\outputs\apk\universal\release\app-universal-release.apk" "%ROOT%\releases\hacash-wallet-mobile-v0.1.22-arm64.apk" >> "%LOG%" 2>&1
echo === gradle OK %DATE% %TIME% === >> "%LOG%"
exit /b 0
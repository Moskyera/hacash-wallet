@echo off
setlocal
set "ANDROID_HOME=%LOCALAPPDATA%\Android\Sdk"
set "ANDROID_SDK_ROOT=%LOCALAPPDATA%\Android\Sdk"
set "JAVA_HOME=C:\Program Files\Android\Android Studio\jbr"
set "PATH=%JAVA_HOME%\bin;%PATH%"
cd /d "C:\Users\KQHEX\Documents\moskyera-quantum-wallet\apps\mobile\src-tauri\gen\android"
echo === Gradle signed build started %DATE% %TIME% === > "C:\Users\KQHEX\Documents\moskyera-quantum-wallet\apps\mobile\gradle-signed-build4.log"
call gradlew.bat assembleUniversalRelease --no-daemon >> "C:\Users\KQHEX\Documents\moskyera-quantum-wallet\apps\mobile\gradle-signed-build4.log" 2>&1
echo === Gradle signed build finished exit=%ERRORLEVEL% %DATE% %TIME% === >> "C:\Users\KQHEX\Documents\moskyera-quantum-wallet\apps\mobile\gradle-signed-build4.log"
exit /b %ERRORLEVEL%
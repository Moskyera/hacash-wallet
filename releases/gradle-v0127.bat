@echo off
setlocal
set "ANDROID_HOME=%LOCALAPPDATA%\Android\Sdk"
set "ANDROID_SDK_ROOT=%LOCALAPPDATA%\Android\Sdk"
set "JAVA_HOME=C:\Program Files\Android\Android Studio\jbr"
set "PATH=%JAVA_HOME%\bin;%PATH%"
cd /d "C:\Users\KQHEX\Documents\moskyera-quantum-wallet\apps\mobile\src-tauri\gen\android"
call gradlew.bat assembleUniversalRelease --no-daemon
exit /b %ERRORLEVEL%
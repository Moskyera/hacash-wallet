@echo off
setlocal
cd /d "C:\Users\KQHEX\Documents\moskyera-quantum-wallet\apps\mobile\src-tauri\gen\android"
set "ANDROID_HOME=%LOCALAPPDATA%\Android\Sdk"
set "ANDROID_SDK_ROOT=%LOCALAPPDATA%\Android\Sdk"
set "NDK_HOME=%LOCALAPPDATA%\Android\Sdk\ndk\27.2.12479018"
set "JAVA_HOME=C:\Program Files\Android\Android Studio\jbr"
set "PATH=%JAVA_HOME%\bin;%ProgramFiles%\nodejs;%APPDATA%\npm;%PATH%"
echo === Gradle build2 started %DATE% %TIME% === > "C:\Users\KQHEX\Documents\moskyera-quantum-wallet\apps\mobile\gradle-build2.log"
call gradlew.bat :app:assembleArm64Release --no-daemon >> "C:\Users\KQHEX\Documents\moskyera-quantum-wallet\apps\mobile\gradle-build2.log" 2>&1
echo === Gradle build2 finished exit=%ERRORLEVEL% %DATE% %TIME% === >> "C:\Users\KQHEX\Documents\moskyera-quantum-wallet\apps\mobile\gradle-build2.log"
exit /b %ERRORLEVEL%
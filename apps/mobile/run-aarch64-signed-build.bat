@echo off
setlocal
set "ANDROID_HOME=%LOCALAPPDATA%\Android\Sdk"
set "ANDROID_SDK_ROOT=%LOCALAPPDATA%\Android\Sdk"
set "NDK_HOME=%LOCALAPPDATA%\Android\Sdk\ndk\27.2.12479018"
set "JAVA_HOME=C:\Program Files\Android\Android Studio\jbr"
set "PATH=%JAVA_HOME%\bin;%PATH%"
set "MOBILE=C:\Users\KQHEX\Documents\moskyera-quantum-wallet\apps\mobile"
set "LOG=%MOBILE%\aarch64-signed-build.log"
set "SRC=C:\Users\KQHEX\Documents\moskyera-quantum-wallet\target\aarch64-linux-android\release\libhacash_wallet_mobile_lib.so"
set "JNI=%MOBILE%\src-tauri\gen\android\app\src\main\jniLibs\arm64-v8a"

if not exist "%JNI%" mkdir "%JNI%"
copy /Y "%SRC%" "%JNI%\libhacash_wallet_mobile_lib.so" >nul

cd /d "%MOBILE%\src-tauri\gen\android"
echo === aarch64 signed build started %DATE% %TIME% === > "%LOG%"
call gradlew.bat assembleUniversalRelease --no-daemon >> "%LOG%" 2>&1
set "RC=%ERRORLEVEL%"
echo === aarch64 signed build finished exit=%RC% %DATE% %TIME% === >> "%LOG%"
exit /b %RC%
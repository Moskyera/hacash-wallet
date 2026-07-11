Set-Location 'C:\Users\KQHEX\Documents\moskyera-quantum-wallet\apps\mobile'
$ErrorActionPreference = 'Continue'
$sdk = Join-Path $env:LOCALAPPDATA 'Android\Sdk'
$env:ANDROID_HOME = $sdk
$env:ANDROID_SDK_ROOT = $sdk
$env:NDK_HOME = (Get-ChildItem (Join-Path $sdk 'ndk') -Directory | Sort-Object Name -Descending | Select-Object -First 1).FullName
$env:JAVA_HOME = 'C:\Program Files\Android\Android Studio\jbr'
$log = Join-Path $PSScriptRoot 'tauri-android-build2.log'

"=== Android build started $(Get-Date -Format o) ===" | Out-File $log -Encoding utf8
"ANDROID_HOME=$env:ANDROID_HOME" | Out-File $log -Append -Encoding utf8
"NDK_HOME=$env:NDK_HOME" | Out-File $log -Append -Encoding utf8

# Build aarch64 APK only (faster first build)
& node .\node_modules\@tauri-apps\cli\tauri.js android build --target aarch64 --apk -v 2>&1 |
    Tee-Object -FilePath $log -Append

$code = $LASTEXITCODE
"=== Android build finished $(Get-Date -Format o) exit=$code ===" | Out-File $log -Append -Encoding utf8
exit $code
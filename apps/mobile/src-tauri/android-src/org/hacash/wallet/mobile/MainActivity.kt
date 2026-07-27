package org.hacash.wallet.mobile

import android.os.Bundle
import android.os.Process
import android.view.WindowManager
import android.webkit.WebSettings
import android.webkit.WebView
import androidx.activity.enableEdgeToEdge

/**
 * The wallet window is always secure, including the lock and recovery screens.
 * Keeping this in tracked source makes the protection survive `tauri android init`.
 */
class MainActivity : TauriActivity() {
  override fun onCreate(savedInstanceState: Bundle?) {
    window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
    enableEdgeToEdge()
    super.onCreate(savedInstanceState)
  }

  override fun onWebViewCreate(webView: WebView) {
    super.onWebViewCreate(webView)
    // The frontend ships inside the APK and every asset filename is content hashed, so
    // index.html is the only document the WebView can cache by name. RustWebView never
    // sets cacheMode, which leaves the default that honours HTTP caching, and the cache
    // lives in the app data directory, which survives a package update. The result is a
    // wallet that keeps running the previous release after an update: the owner installs
    // a new build and sees none of it.
    //
    // Only the resource cache is cleared. localStorage holds saved contacts, the wallet
    // display name and the do-not-ask-again choice, and it must survive; that is
    // WebStorage, which this does not touch.
    webView.settings.cacheMode = WebSettings.LOAD_NO_CACHE
    webView.clearCache(true)
  }

  override fun onResume() {
    // Reassert the flag in case an Android configuration change recreated the window.
    window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
    super.onResume()
  }

  override fun onStop() {
    super.onStop()
    if (isChangingConfigurations) return
    val coldVault = getSharedPreferences(
      COLD_VAULT_LIFECYCLE_PREFS,
      MODE_PRIVATE,
    ).getBoolean(COLD_VAULT_BACKGROUND_KILL, false)
    if (coldVault) {
      // Android may freeze the Rust runtime before an async timer or WebView
      // callback runs. Terminating the cold-signer process guarantees that a
      // decrypted key cannot survive after the Activity leaves the screen.
      finishAndRemoveTask()
      Process.killProcess(Process.myPid())
    }
  }
}

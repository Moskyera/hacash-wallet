package org.hacash.wallet.mobile

import android.os.Bundle
import android.os.Process
import android.view.WindowManager
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

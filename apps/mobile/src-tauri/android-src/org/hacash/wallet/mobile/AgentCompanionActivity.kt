package org.hacash.wallet.mobile

import android.os.Bundle
import android.view.WindowManager
import android.webkit.WebSettings
import android.webkit.WebView
import androidx.activity.enableEdgeToEdge
import androidx.lifecycle.Lifecycle
import java.lang.ref.WeakReference

/**
 * Private Android host for the least-privilege Agent Wallet webview.
 *
 * The separate Activity lets Tauri bind the `agent-companion` capability to a
 * distinct webview label instead of exposing Personal Wallet commands to an
 * in-page Agent route.
 */
class AgentCompanionActivity : TauriActivity() {
  companion object {
    @Volatile
    private var resumedActivity: WeakReference<AgentCompanionActivity>? = null

    fun currentResumed(): AgentCompanionActivity? {
      val current = resumedActivity?.get()
      return current?.takeIf {
        !it.isFinishing &&
          !it.isDestroyed &&
          it.lifecycle.currentState.isAtLeast(Lifecycle.State.RESUMED)
      }
    }

    private fun markResumed(activity: AgentCompanionActivity) {
      synchronized(this) {
        resumedActivity = WeakReference(activity)
      }
    }

    private fun clearResumed(activity: AgentCompanionActivity) {
      synchronized(this) {
        if (resumedActivity?.get() === activity) {
          resumedActivity = null
        }
      }
    }
  }

  override fun onCreate(savedInstanceState: Bundle?) {
    window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
    enableEdgeToEdge()
    super.onCreate(savedInstanceState)
  }

  override fun onWebViewCreate(webView: WebView) {
    super.onWebViewCreate(webView)
    webView.settings.cacheMode = WebSettings.LOAD_NO_CACHE
    webView.clearCache(true)
  }

  override fun onResume() {
    super.onResume()
    window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
    markResumed(this)
  }

  override fun onPause() {
    clearResumed(this)
    super.onPause()
  }

  override fun onDestroy() {
    clearResumed(this)
    super.onDestroy()
  }
}

package org.hacash.wallet.mobile

import android.Manifest
import android.app.Activity
import android.os.Build
import androidx.appcompat.app.AppCompatActivity
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import app.tauri.PermissionState
import app.tauri.annotation.Command
import app.tauri.annotation.InvokeArg
import app.tauri.annotation.Permission
import app.tauri.annotation.PermissionCallback
import app.tauri.annotation.TauriPlugin
import app.tauri.plugin.Invoke
import app.tauri.plugin.JSObject
import app.tauri.plugin.Plugin
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean

private const val BACKUP_DOWNLOADS_PERMISSION = "backup-downloads"

@InvokeArg
class StoreBiometricArgs {
  lateinit var passphrase: String
}

@InvokeArg
class InstallApkArgs {
  lateinit var apkPath: String
}

@InvokeArg
class CopyBackupArgs {
  lateinit var sourcePath: String
  lateinit var displayName: String
}

@InvokeArg
class DeleteBackupArgs {
  lateinit var source: String
}

@InvokeArg
class AuthenticateStrongArgs {
  lateinit var reason: String
}

/**
 * Native wallet operations bound to Tauri's current Activity.
 *
 * File and Keystore work runs off the Android UI thread. Tauri owns the
 * Activity lifecycle and delivers every command to this registered plugin,
 * avoiding the uninitialized legacy ndk-context global.
 */
@TauriPlugin(
  permissions = [
    Permission(
      strings = [Manifest.permission.WRITE_EXTERNAL_STORAGE],
      alias = BACKUP_DOWNLOADS_PERMISSION,
    ),
  ],
)
class WalletNativePlugin(private val activity: Activity) : Plugin(activity) {
  private class PendingInvoke(val invoke: Invoke) {
    private val complete = AtomicBoolean(false)

    fun resolve(response: JSObject?) {
      if (!complete.compareAndSet(false, true)) return
      if (response == null) invoke.resolve() else invoke.resolve(response)
    }

    fun reject(message: String) {
      if (complete.compareAndSet(false, true)) invoke.reject(message)
    }
  }

  private val worker: ExecutorService = Executors.newSingleThreadExecutor { task ->
    Thread(task, "hacash-wallet-native").apply { isDaemon = true }
  }
  private val destroyed = AtomicBoolean(false)
  private val pending = ConcurrentHashMap.newKeySet<PendingInvoke>()
  private var activePrompt: BiometricPrompt? = null
  private var activeAuthentication: PendingInvoke? = null

  private fun authenticators(): Int = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
    BiometricManager.Authenticators.BIOMETRIC_STRONG or
      BiometricManager.Authenticators.DEVICE_CREDENTIAL
  } else {
    BiometricManager.Authenticators.BIOMETRIC_STRONG
  }

  private fun execute(invoke: Invoke, operation: () -> JSObject?) {
    val call = PendingInvoke(invoke)
    if (destroyed.get()) {
      call.reject("Android Activity is no longer available")
      return
    }
    pending.add(call)
    try {
      worker.execute {
        try {
          if (destroyed.get()) {
            call.reject("Android Activity is no longer available")
          } else {
            call.resolve(operation())
          }
        } catch (error: Exception) {
          call.reject(error.message ?: error.javaClass.simpleName)
        } finally {
          pending.remove(call)
        }
      }
    } catch (error: Exception) {
      pending.remove(call)
      call.reject(error.message ?: "Android wallet-native worker is unavailable")
    }
  }

  @Command
  fun biometricIsConfigured(invoke: Invoke) {
    execute(invoke) {
      JSObject().apply {
        put("configured", BiometricSecretStore.isConfigured(activity))
      }
    }
  }

  @Command
  fun biometricStore(invoke: Invoke) {
    val args = invoke.parseArgs(StoreBiometricArgs::class.java)
    execute(invoke) {
      try {
        BiometricSecretStore.store(activity, args.passphrase)
        null
      } finally {
        // Kotlin strings cannot be wiped in place. Drop our reference promptly;
        // BiometricSecretStore separately wipes every mutable byte buffer.
        args.passphrase = ""
      }
    }
  }

  @Command
  fun biometricLoad(invoke: Invoke) {
    execute(invoke) {
      var passphrase = BiometricSecretStore.load(activity)
      try {
        JSObject().apply { put("passphrase", passphrase) }
      } finally {
        // The JSON bridge requires an immutable String; release this local copy.
        passphrase = ""
      }
    }
  }

  @Command
  fun biometricClear(invoke: Invoke) {
    execute(invoke) {
      BiometricSecretStore.clear(activity)
      null
    }
  }

  @Command
  fun strongBiometricStatus(invoke: Invoke) {
    execute(invoke) {
      val available = BiometricManager.from(activity)
        .canAuthenticate(authenticators()) == BiometricManager.BIOMETRIC_SUCCESS
      JSObject().apply {
        put("available", available)
        put(
          "kind",
          if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            "Strong biometric or device credential"
          } else {
            "Strong biometric"
          },
        )
      }
    }
  }

  @Command
  fun authenticateStrong(invoke: Invoke) {
    val args = invoke.parseArgs(AuthenticateStrongArgs::class.java)
    val fragmentActivity = activity as? FragmentActivity
    if (fragmentActivity == null) {
      invoke.reject("Android Activity does not support biometric authentication")
      return
    }
    val call = PendingInvoke(invoke)
    synchronized(this) {
      if (destroyed.get()) {
        call.reject("Android Activity is no longer available")
        return
      }
      if (activeAuthentication != null) {
        call.reject("Another biometric authentication is already active")
        return
      }
      activeAuthentication = call
      pending.add(call)
    }

    activity.runOnUiThread {
      try {
        if (destroyed.get()) {
          finishAuthentication(call) {
            call.reject("Android Activity is no longer available")
          }
          return@runOnUiThread
        }
        val callback = object : BiometricPrompt.AuthenticationCallback() {
          override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
            finishAuthentication(call) { call.resolve(null) }
          }

          override fun onAuthenticationError(errorCode: Int, errorMessage: CharSequence) {
            finishAuthentication(call) {
              call.reject(errorMessage.toString().ifBlank { "Biometric authentication failed" })
            }
          }
        }
        val prompt = BiometricPrompt(
          fragmentActivity,
          ContextCompat.getMainExecutor(activity),
          callback,
        )
        val promptInfo = BiometricPrompt.PromptInfo.Builder()
          .setTitle("Hacash Wallet")
          .setDescription(args.reason)
          .setConfirmationRequired(true)
          .setAllowedAuthenticators(authenticators())
          .apply {
            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.R) {
              setNegativeButtonText("Cancel")
            }
          }
          .build()
        synchronized(this) {
          if (activeAuthentication === call) activePrompt = prompt
        }
        prompt.authenticate(promptInfo)
      } catch (error: Exception) {
        finishAuthentication(call) {
          call.reject(error.message ?: "Biometric authentication could not start")
        }
      }
    }
  }

  private fun finishAuthentication(call: PendingInvoke, finish: () -> Unit) {
    synchronized(this) {
      if (activeAuthentication === call) {
        activeAuthentication = null
        activePrompt = null
      }
    }
    pending.remove(call)
    finish()
  }

  @Command
  fun installApk(invoke: Invoke) {
    val args = invoke.parseArgs(InstallApkArgs::class.java)
    execute(invoke) {
      ApkInstaller.install(activity, args.apkPath)
      null
    }
  }

  @Command
  fun copyBackupToDownloads(invoke: Invoke) {
    val args = invoke.parseArgs(CopyBackupArgs::class.java)
    if (Build.VERSION.SDK_INT <= Build.VERSION_CODES.P &&
      getPermissionState(BACKUP_DOWNLOADS_PERMISSION) != PermissionState.GRANTED
    ) {
      requestPermissionForAlias(
        BACKUP_DOWNLOADS_PERMISSION,
        invoke,
        "copyBackupPermissionResult",
      )
      return
    }
    executeBackupCopy(invoke, args)
  }

  @PermissionCallback
  fun copyBackupPermissionResult(invoke: Invoke) {
    val args = invoke.parseArgs(CopyBackupArgs::class.java)
    if (Build.VERSION.SDK_INT <= Build.VERSION_CODES.P &&
      getPermissionState(BACKUP_DOWNLOADS_PERMISSION) != PermissionState.GRANTED
    ) {
      invoke.reject("Storage permission is required to export a backup on Android 9")
      return
    }
    executeBackupCopy(invoke, args)
  }

  private fun executeBackupCopy(invoke: Invoke, args: CopyBackupArgs) {
    execute(invoke) {
      val destination = BackupExportHelper.copyFileToDownloads(
        activity,
        args.sourcePath,
        args.displayName,
      )
      JSObject().apply { put("destination", destination) }
    }
  }

  @Command
  fun deleteBackupSource(invoke: Invoke) {
    val args = invoke.parseArgs(DeleteBackupArgs::class.java)
    execute(invoke) {
      if (!BackupFileHelper.deleteBackupSource(activity, args.source)) {
        throw IllegalStateException(
          "backup file could not be deleted. remove it manually from Downloads",
        )
      }
      null
    }
  }

  override fun onDestroy(activity: AppCompatActivity) {
    destroyed.set(true)
    synchronized(this) {
      activePrompt?.cancelAuthentication()
      activePrompt = null
      activeAuthentication = null
    }
    pending.forEach { call ->
      call.reject("Android Activity was destroyed before the operation completed")
    }
    pending.clear()
    worker.shutdownNow()
  }
}

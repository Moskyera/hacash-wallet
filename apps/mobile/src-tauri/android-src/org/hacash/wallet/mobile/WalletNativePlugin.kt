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
import javax.crypto.Cipher

private const val BACKUP_DOWNLOADS_PERMISSION = "backup-downloads"
internal const val COLD_VAULT_LIFECYCLE_PREFS = "hacash_wallet_security"
internal const val COLD_VAULT_BACKGROUND_KILL = "cold_vault_background_kill"

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

@InvokeArg
class SetColdVaultLifecycleArgs {
  var enabled: Boolean = false
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
  private class PendingInvoke(
    val invoke: Invoke,
    private val onComplete: () -> Unit = {},
  ) {
    private val complete = AtomicBoolean(false)

    fun isComplete(): Boolean = complete.get()

    fun resolve(response: JSObject?) {
      if (!complete.compareAndSet(false, true)) return
      try {
        if (response == null) invoke.resolve() else invoke.resolve(response)
      } finally {
        onComplete()
      }
    }

    fun reject(message: String) {
      if (!complete.compareAndSet(false, true)) return
      try {
        invoke.reject(message)
      } finally {
        onComplete()
      }
    }
  }

  private val worker: ExecutorService = Executors.newSingleThreadExecutor { task ->
    Thread(task, "hacash-wallet-native").apply { isDaemon = true }
  }
  private val destroyed = AtomicBoolean(false)
  private val pending = ConcurrentHashMap.newKeySet<PendingInvoke>()
  private var activePrompt: BiometricPrompt? = null
  private var activeAuthentication: PendingInvoke? = null

  /**
   * Authenticators for releasing the passphrase held in the Android Keystore.
   *
   * Restored from the released v0.1.55 policy: the device credential is accepted
   * alongside a Class 3 biometric, which is exactly what the Keystore key allows.
   * Android offers the credential whenever the fingerprint fails, so the phone PIN
   * or pattern can unlock the wallet. That cost is stated on the Security screen
   * and in docs/HOW-IT-WORKS.md rather than hidden.
   */
  private fun unlockAuthenticators(): Int =
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
      BiometricManager.Authenticators.BIOMETRIC_STRONG or
        BiometricManager.Authenticators.DEVICE_CREDENTIAL
    } else {
      BiometricManager.Authenticators.BIOMETRIC_STRONG
    }

  /**
   * Authenticators for authorizing a prepared operation: a send at or above the
   * threshold, or Cold Vault activation.
   *
   * This ceremony never touches the Keystore key, so nothing here forces a
   * credential fallback. A device PIN or pattern is intentionally not accepted as
   * authorization for a high-value signing decision, which is the distinction the
   * unlock path cannot make.
   */
  private fun signingAuthenticators(): Int = BiometricManager.Authenticators.BIOMETRIC_STRONG

  /**
   * BiometricPrompt requires a negative button unless a device credential is
   * allowed, and rejects one when it is. Deriving it from the same value passed to
   * `setAllowedAuthenticators` keeps `build()` from throwing on either path.
   */
  private fun BiometricPrompt.PromptInfo.Builder.withCancelButton(
    allowed: Int,
  ): BiometricPrompt.PromptInfo.Builder = apply {
    if ((allowed and BiometricManager.Authenticators.DEVICE_CREDENTIAL) == 0) {
      setNegativeButtonText("Cancel")
    }
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

  private fun reserveAuthentication(call: PendingInvoke): Boolean {
    synchronized(this) {
      if (destroyed.get()) {
        call.reject("Android Activity is no longer available")
        return false
      }
      if (activeAuthentication != null) {
        call.reject("Another biometric operation is already active")
        return false
      }
      activeAuthentication = call
      pending.add(call)
      return true
    }
  }

  private fun executeBiometricExclusive(invoke: Invoke, operation: () -> JSObject?) {
    val call = PendingInvoke(invoke)
    if (!reserveAuthentication(call)) return
    try {
      worker.execute {
        try {
          if (destroyed.get()) {
            throw IllegalStateException("Android Activity is no longer available")
          }
          val response = operation()
          finishAuthentication(call) { call.resolve(response) }
        } catch (error: Exception) {
          finishAuthentication(call) {
            call.reject(error.message ?: error.javaClass.simpleName)
          }
        }
      }
    } catch (error: Exception) {
      finishAuthentication(call) {
        call.reject(error.message ?: "Android wallet-native worker is unavailable")
      }
    }
  }

  private fun authenticateWithCipher(
    invoke: Invoke,
    reason: String,
    onComplete: () -> Unit = {},
    prepareCipher: () -> Cipher,
    useCipher: (Cipher) -> JSObject?,
  ) {
    val fragmentActivity = activity as? FragmentActivity
    if (fragmentActivity == null) {
      onComplete()
      invoke.reject("Android Activity does not support biometric authentication")
      return
    }
    val call = PendingInvoke(invoke, onComplete)
    if (!reserveAuthentication(call)) return

    try {
      worker.execute {
        try {
          if (destroyed.get()) {
            throw IllegalStateException("Android Activity is no longer available")
          }
          activity.runOnUiThread {
            try {
              if (destroyed.get() || call.isComplete()) {
                finishAuthentication(call) {
                  call.reject("Android Activity is no longer available")
                }
                return@runOnUiThread
              }
              val callback = object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(
                  result: BiometricPrompt.AuthenticationResult,
                ) {
                  // The Keystore key carries a bounded authentication window rather
                  // than a per-use requirement, which BiometricPrompt cannot bind to a
                  // CryptoObject. The prompt gates the interface and the window gates
                  // the key, so the cipher is created after a successful prompt.
                  synchronized(this@WalletNativePlugin) {
                    if (activeAuthentication === call) activePrompt = null
                  }
                  try {
                    worker.execute {
                      try {
                        if (destroyed.get() || call.isComplete()) {
                          throw IllegalStateException("Android Activity is no longer available")
                        }
                        val response = useCipher(prepareCipher())
                        finishAuthentication(call) { call.resolve(response) }
                      } catch (error: Exception) {
                        finishAuthentication(call) {
                          call.reject(error.message ?: "Biometric cryptographic operation failed")
                        }
                      }
                    }
                  } catch (error: Exception) {
                    finishAuthentication(call) {
                      call.reject(error.message ?: "Android wallet-native worker is unavailable")
                    }
                  }
                }

                override fun onAuthenticationError(
                  errorCode: Int,
                  errorMessage: CharSequence,
                ) {
                  finishAuthentication(call) {
                    call.reject(
                      errorMessage.toString().ifBlank { "Biometric authentication failed" },
                    )
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
                .setDescription(reason)
                .setConfirmationRequired(true)
                .setAllowedAuthenticators(unlockAuthenticators())
                .withCancelButton(unlockAuthenticators())
                .build()
              synchronized(this@WalletNativePlugin) {
                if (activeAuthentication === call) activePrompt = prompt
              }
              prompt.authenticate(promptInfo)
            } catch (error: Exception) {
              finishAuthentication(call) {
                call.reject(error.message ?: "Biometric authentication could not start")
              }
            }
          }
        } catch (error: Exception) {
          finishAuthentication(call) {
            call.reject(error.message ?: "Biometric cryptographic operation could not start")
          }
        }
      }
    } catch (error: Exception) {
      finishAuthentication(call) {
        call.reject(error.message ?: "Android wallet-native worker is unavailable")
      }
    }
  }

  @Command
  fun biometricIsConfigured(invoke: Invoke) {
    executeBiometricExclusive(invoke) {
      val status = BiometricSecretStore.status(activity)
      JSObject().apply {
        put("configured", status.configured)
        put("keySecurityLevel", status.keySecurityLevel)
        put("hardwareBacked", status.hardwareBacked)
        put("strongBoxBacked", status.strongBoxBacked)
        put(
          "authenticationEnforcedBySecureHardware",
          status.authenticationEnforcedBySecureHardware,
        )
        put("authPerUse", status.authPerUse)
      }
    }
  }

  @Command
  fun biometricStore(invoke: Invoke) {
    val args = invoke.parseArgs(StoreBiometricArgs::class.java)
    authenticateWithCipher(
      invoke = invoke,
      reason = "Enable biometric unlock for Hacash Wallet",
      onComplete = {
        // Kotlin strings cannot be wiped in place. Drop this reference on every
        // success, cancellation, and error path. Mutable byte buffers are wiped
        // inside BiometricSecretStore.
        args.passphrase = ""
      },
      prepareCipher = { BiometricSecretStore.prepareEncryption(activity) },
      useCipher = { cipher ->
        BiometricSecretStore.encryptAndStore(activity, cipher, args.passphrase)
        null
      },
    )
  }

  @Command
  fun biometricLoad(invoke: Invoke) {
    authenticateWithCipher(
      invoke = invoke,
      reason = "Unlock Hacash Wallet",
      prepareCipher = { BiometricSecretStore.prepareDecryption(activity) },
      useCipher = { cipher ->
        var passphrase = BiometricSecretStore.decrypt(activity, cipher)
        try {
          JSObject().apply { put("passphrase", passphrase) }
        } finally {
          // The JSON bridge requires an immutable String. Release our local
          // reference immediately after creating the response object.
          passphrase = ""
        }
      },
    )
  }

  @Command
  fun biometricClear(invoke: Invoke) {
    executeBiometricExclusive(invoke) {
      BiometricSecretStore.clear(activity)
      null
    }
  }

  @Command
  fun strongBiometricStatus(invoke: Invoke) {
    execute(invoke) {
      // Report on the strong biometric alone. A device with only a screen lock must
      // not be told it has a biometric sensor, and a device that passes this check
      // also passes the more permissive unlock check.
      val available = BiometricManager.from(activity)
        .canAuthenticate(signingAuthenticators()) == BiometricManager.BIOMETRIC_SUCCESS
      JSObject().apply {
        put("available", available)
        put(
          "kind",
          "Strong biometric",
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
          .setAllowedAuthenticators(signingAuthenticators())
          .withCancelButton(signingAuthenticators())
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

  @Command
  fun setColdVaultLifecycle(invoke: Invoke) {
    val args = invoke.parseArgs(SetColdVaultLifecycleArgs::class.java)
    val committed = activity.getSharedPreferences(
      COLD_VAULT_LIFECYCLE_PREFS,
      Activity.MODE_PRIVATE,
    ).edit().putBoolean(COLD_VAULT_BACKGROUND_KILL, args.enabled).commit()
    if (!committed) {
      invoke.reject("Cold Vault lifecycle policy could not be persisted")
      return
    }
    invoke.resolve()
  }

  @Command
  fun coldVaultLifecycleStatus(invoke: Invoke) {
    val enabled = activity.getSharedPreferences(
      COLD_VAULT_LIFECYCLE_PREFS,
      Activity.MODE_PRIVATE,
    ).getBoolean(COLD_VAULT_BACKGROUND_KILL, false)
    invoke.resolve(JSObject().apply { put("enabled", enabled) })
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

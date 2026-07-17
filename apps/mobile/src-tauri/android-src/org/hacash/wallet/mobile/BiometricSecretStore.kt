package org.hacash.wallet.mobile

import android.app.Activity
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.nio.charset.StandardCharsets
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

object BiometricSecretStore {
  private const val KEY_ALIAS = "hacash_wallet_biometric_unlock_v2"
  private const val PREFS = "hacash_wallet_secure_unlock"
  private const val PREF_CIPHERTEXT = "ciphertext"
  private const val PREF_IV = "iv"
  private const val AUTH_WINDOW_SECONDS = 30

  @JvmStatic
  @Synchronized
  fun store(activity: Activity, passphrase: String) {
    require(passphrase.isNotEmpty()) { "passphrase is empty" }
    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
    cipher.init(Cipher.ENCRYPT_MODE, getOrCreateKey())
    val encrypted = cipher.doFinal(passphrase.toByteArray(StandardCharsets.UTF_8))
    activity.applicationContext
      .getSharedPreferences(PREFS, Activity.MODE_PRIVATE)
      .edit()
      .putString(PREF_CIPHERTEXT, Base64.encodeToString(encrypted, Base64.NO_WRAP))
      .putString(PREF_IV, Base64.encodeToString(cipher.iv, Base64.NO_WRAP))
      .apply()
  }

  @JvmStatic
  @Synchronized
  fun load(activity: Activity): String {
    val prefs = activity.applicationContext.getSharedPreferences(PREFS, Activity.MODE_PRIVATE)
    val ciphertext = prefs.getString(PREF_CIPHERTEXT, null)
      ?: throw IllegalStateException("biometric unlock is not configured")
    val iv = prefs.getString(PREF_IV, null)
      ?: throw IllegalStateException("biometric unlock IV is missing")
    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
    cipher.init(
      Cipher.DECRYPT_MODE,
      getExistingKey(),
      GCMParameterSpec(128, Base64.decode(iv, Base64.NO_WRAP)),
    )
    val plain = cipher.doFinal(Base64.decode(ciphertext, Base64.NO_WRAP))
    return String(plain, StandardCharsets.UTF_8)
  }

  @JvmStatic
  @Synchronized
  fun isConfigured(activity: Activity): Boolean {
    val prefs = activity.applicationContext.getSharedPreferences(PREFS, Activity.MODE_PRIVATE)
    val keyStore = keyStore()
    return keyStore.containsAlias(KEY_ALIAS)
      && prefs.contains(PREF_CIPHERTEXT)
      && prefs.contains(PREF_IV)
  }

  @JvmStatic
  @Synchronized
  fun clear(activity: Activity) {
    activity.applicationContext
      .getSharedPreferences(PREFS, Activity.MODE_PRIVATE)
      .edit()
      .clear()
      .apply()
    val keyStore = keyStore()
    if (keyStore.containsAlias(KEY_ALIAS)) {
      keyStore.deleteEntry(KEY_ALIAS)
    }
  }

  private fun keyStore(): KeyStore = KeyStore.getInstance("AndroidKeyStore").apply {
    load(null)
  }

  private fun getExistingKey(): SecretKey {
    return keyStore().getKey(KEY_ALIAS, null) as? SecretKey
      ?: throw IllegalStateException("Android Keystore key is missing")
  }

  private fun getOrCreateKey(): SecretKey {
    val existing = keyStore().getKey(KEY_ALIAS, null) as? SecretKey
    if (existing != null) return existing

    val builder = KeyGenParameterSpec.Builder(
      KEY_ALIAS,
      KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
    )
      .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
      .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
      .setKeySize(256)
      .setUserAuthenticationRequired(true)
      .setInvalidatedByBiometricEnrollment(true)

    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
      builder.setUserAuthenticationParameters(
        AUTH_WINDOW_SECONDS,
        KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL,
      )
    } else {
      @Suppress("DEPRECATION")
      builder.setUserAuthenticationValidityDurationSeconds(AUTH_WINDOW_SECONDS)
    }

    val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
    generator.init(builder.build())
    return generator.generateKey()
  }
}

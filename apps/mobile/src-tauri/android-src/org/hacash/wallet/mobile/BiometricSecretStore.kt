package org.hacash.wallet.mobile

import android.app.Activity
import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import android.util.Base64
import java.nio.charset.StandardCharsets
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec

object BiometricSecretStore {
  private const val CURRENT_KEY_ALIAS = "hacash_wallet_biometric_unlock_v3"
  private const val LEGACY_KEY_ALIAS = "hacash_wallet_biometric_unlock_v2"
  private const val PREFS = "hacash_wallet_secure_unlock"
  private const val PREF_CIPHERTEXT = "ciphertext"
  private const val PREF_IV = "iv"
  private const val PREF_VERSION = "version"
  private const val CURRENT_VERSION = 3

  /**
   * Seconds one authentication covers, restored from the released v0.1.55 policy.
   *
   * A per-use key (window 0, biometric only) is stronger, but it did not work on
   * device: enabling it failed outright. This is the policy that shipped and
   * worked. The cost is stated plainly in docs/HOW-IT-WORKS.md: one biometric
   * covers key use for this many seconds, and the device credential is accepted,
   * so the phone PIN or pattern can unlock the wallet.
   */
  private const val AUTH_WINDOW_SECONDS = 30
  private val AAD = "HacashWallet|biometric-unlock|v3".toByteArray(StandardCharsets.UTF_8)

  data class Status(
    val configured: Boolean,
    val keySecurityLevel: String,
    val hardwareBacked: Boolean,
    val strongBoxBacked: Boolean,
    val authenticationEnforcedBySecureHardware: Boolean,
    val authPerUse: Boolean,
  )

  /**
   * Creates an AES-GCM operation which cannot be used until the matching
   * BiometricPrompt CryptoObject authenticates the user. The caller must pass
   * this exact Cipher instance to the prompt and then to [encryptAndStore].
   */
  @JvmStatic
  @Synchronized
  fun prepareEncryption(activity: Activity): Cipher {
    discardLegacyOrIncompleteState(activity)
    return Cipher.getInstance("AES/GCM/NoPadding").apply {
      init(Cipher.ENCRYPT_MODE, getOrCreateKey(activity))
      updateAAD(AAD)
    }
  }

  @JvmStatic
  @Synchronized
  fun encryptAndStore(activity: Activity, cipher: Cipher, passphrase: String) {
    require(passphrase.isNotEmpty()) { "passphrase is empty" }
    val plain = passphrase.toByteArray(StandardCharsets.UTF_8)
    try {
      val encrypted = cipher.doFinal(plain)
      val iv = cipher.iv
      try {
        val persisted = preferences(activity)
          .edit()
          .putInt(PREF_VERSION, CURRENT_VERSION)
          .putString(PREF_CIPHERTEXT, Base64.encodeToString(encrypted, Base64.NO_WRAP))
          .putString(PREF_IV, Base64.encodeToString(iv, Base64.NO_WRAP))
          .commit()
        if (!persisted) {
          clear(activity)
          throw IllegalStateException("Could not persist biometric unlock secret")
        }
      } finally {
        encrypted.fill(0)
        iv.fill(0)
      }
    } finally {
      plain.fill(0)
    }
  }

  /**
   * Initializes the decrypt operation before prompting. A missing, legacy, or
   * invalidated key is removed and fails closed; the user must re-enrol.
   */
  @JvmStatic
  @Synchronized
  fun prepareDecryption(activity: Activity): Cipher {
    if (!hasCompleteCurrentState(activity)) {
      clear(activity)
      throw IllegalStateException("Biometric unlock is not configured. Re-enable it in Security.")
    }

    val encodedIv = preferences(activity).getString(PREF_IV, null)
      ?: throw IllegalStateException("Biometric unlock IV is missing")
    val iv = try {
      Base64.decode(encodedIv, Base64.NO_WRAP)
    } catch (error: IllegalArgumentException) {
      clear(activity)
      throw IllegalStateException("Biometric unlock data is invalid. Re-enable it in Security.", error)
    }

    val key = try {
      getExistingKey()
    } catch (error: Exception) {
      clear(activity)
      throw IllegalStateException(
        "Biometric key policy is invalid. Re-enable biometric unlock in Security.",
        error,
      )
    }

    try {
      return Cipher.getInstance("AES/GCM/NoPadding").apply {
        try {
          init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, iv))
          updateAAD(AAD)
        } catch (error: KeyPermanentlyInvalidatedException) {
          clear(activity)
          throw IllegalStateException(
            "Biometric key was invalidated. Re-enable biometric unlock in Security.",
            error,
          )
        }
      }
    } finally {
      iv.fill(0)
    }
  }

  @JvmStatic
  @Synchronized
  fun decrypt(activity: Activity, cipher: Cipher): String {
    val encodedCiphertext = preferences(activity).getString(PREF_CIPHERTEXT, null)
      ?: throw IllegalStateException("Biometric unlock is not configured")
    val encrypted = try {
      Base64.decode(encodedCiphertext, Base64.NO_WRAP)
    } catch (error: IllegalArgumentException) {
      clear(activity)
      throw IllegalStateException("Biometric unlock data is invalid. Re-enable it in Security.", error)
    }

    try {
      val plain = cipher.doFinal(encrypted)
      try {
        return String(plain, StandardCharsets.UTF_8)
      } finally {
        plain.fill(0)
      }
    } catch (error: Exception) {
      clear(activity)
      throw IllegalStateException("Biometric unlock failed. Re-enable it in Security.", error)
    } finally {
      encrypted.fill(0)
    }
  }

  @JvmStatic
  @Synchronized
  fun status(activity: Activity): Status {
    discardLegacyOrIncompleteState(activity)
    if (!hasCompleteCurrentState(activity)) return unavailableStatus()

    val key = try {
      getExistingKey()
    } catch (_: Exception) {
      clear(activity)
      return unavailableStatus()
    }
    val keyInfo = try {
      keyInfo(key)
    } catch (_: Exception) {
      clear(activity)
      return unavailableStatus()
    }

    val authPerUse = isAuthPerUse(keyInfo)
    val authHardware = keyInfo.isUserAuthenticationRequirementEnforcedBySecureHardware
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
      val level = when (keyInfo.securityLevel) {
        KeyProperties.SECURITY_LEVEL_STRONGBOX -> "strongbox"
        KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT -> "trusted_environment"
        KeyProperties.SECURITY_LEVEL_UNKNOWN_SECURE -> "unknown_secure"
        KeyProperties.SECURITY_LEVEL_SOFTWARE -> "software"
        else -> "unknown"
      }
      val hardware = keyInfo.securityLevel == KeyProperties.SECURITY_LEVEL_STRONGBOX ||
        keyInfo.securityLevel == KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT ||
        keyInfo.securityLevel == KeyProperties.SECURITY_LEVEL_UNKNOWN_SECURE
      return Status(
        true,
        level,
        hardware,
        keyInfo.securityLevel == KeyProperties.SECURITY_LEVEL_STRONGBOX,
        authHardware,
        authPerUse,
      )
    }

    @Suppress("DEPRECATION")
    val hardware = keyInfo.isInsideSecureHardware
    return Status(
      true,
      if (hardware) "secure_hardware" else "software",
      hardware,
      false,
      authHardware,
      authPerUse,
    )
  }

  @JvmStatic
  @Synchronized
  fun clear(activity: Activity) {
    val cleared = preferences(activity).edit().clear().commit()
    check(cleared) { "Could not clear biometric unlock secret" }
    val keyStore = keyStore()
    for (alias in arrayOf(CURRENT_KEY_ALIAS, LEGACY_KEY_ALIAS)) {
      if (keyStore.containsAlias(alias)) keyStore.deleteEntry(alias)
    }
  }

  private fun unavailableStatus() = Status(false, "unavailable", false, false, false, false)

  private fun preferences(activity: Activity) = activity.applicationContext
    .getSharedPreferences(PREFS, Activity.MODE_PRIVATE)

  private fun keyStore(): KeyStore = KeyStore.getInstance("AndroidKeyStore").apply {
    load(null)
  }

  private fun getExistingKey(): SecretKey {
    val key = keyStore().getKey(CURRENT_KEY_ALIAS, null) as? SecretKey
      ?: throw IllegalStateException("Android Keystore key is missing")
    check(isPolicyAcceptable(keyInfo(key))) { "Android Keystore key policy does not match this build" }
    return key
  }

  private fun keyInfo(key: SecretKey): KeyInfo {
    return SecretKeyFactory.getInstance(key.algorithm, "AndroidKeyStore")
      .getKeySpec(key, KeyInfo::class.java) as KeyInfo
  }

  /** Reported to the UI: does every single use need a fresh authentication? */
  private fun isAuthPerUse(keyInfo: KeyInfo): Boolean {
    return keyInfo.isUserAuthenticationRequired &&
      keyInfo.userAuthenticationValidityDurationSeconds <= 0
  }

  /**
   * Does this key match the policy this build creates?
   *
   * Callers delete the key when this is false, so it must accept the policy in
   * `generateKey` exactly, on every supported API level. Too strict is the
   * destructive direction: an earlier build paired a `== -1` check with a key it
   * generated as window 0, so it wiped the key it had just created. Comparing
   * against the window avoids that whole -1 versus 0 ambiguity.
   *
   * A window longer than intended is rejected, which is the only direction that
   * could weaken the policy: it would let one authentication cover more key use
   * than the interface implies.
   *
   * It also accepts a per-use key, which is strictly stronger and so cannot
   * weaken anything. That is forward compatibility, not recovery: this build
   * does not bind a CryptoObject to the prompt, so a per-use key would fail at
   * `doFinal` and be cleared anyway. An earlier version of this comment claimed
   * such a key "keeps working", which was wrong.
   */
  private fun isPolicyAcceptable(keyInfo: KeyInfo): Boolean {
    if (!keyInfo.isUserAuthenticationRequired) return false
    val window = keyInfo.userAuthenticationValidityDurationSeconds
    return window <= AUTH_WINDOW_SECONDS
  }

  private fun hasCompleteCurrentState(activity: Activity): Boolean {
    val prefs = preferences(activity)
    return prefs.getInt(PREF_VERSION, 0) == CURRENT_VERSION &&
      prefs.contains(PREF_CIPHERTEXT) &&
      prefs.contains(PREF_IV) &&
      keyStore().containsAlias(CURRENT_KEY_ALIAS)
  }

  private fun discardLegacyOrIncompleteState(activity: Activity) {
    val prefs = preferences(activity)
    val keyStore = keyStore()
    if (keyStore.containsAlias(LEGACY_KEY_ALIAS)) keyStore.deleteEntry(LEGACY_KEY_ALIAS)

    val hasAnyPayload = prefs.contains(PREF_CIPHERTEXT) || prefs.contains(PREF_IV) ||
      prefs.contains(PREF_VERSION)
    val valid = hasCompleteCurrentState(activity)
    if (hasAnyPayload && !valid) {
      val cleared = prefs.edit().clear().commit()
      check(cleared) { "Could not clear legacy biometric unlock secret" }
      if (keyStore.containsAlias(CURRENT_KEY_ALIAS)) keyStore.deleteEntry(CURRENT_KEY_ALIAS)
    } else if (!hasAnyPayload && keyStore.containsAlias(CURRENT_KEY_ALIAS)) {
      keyStore.deleteEntry(CURRENT_KEY_ALIAS)
    }
  }

  private fun getOrCreateKey(activity: Activity): SecretKey {
    val keyStore = keyStore()
    val existing = keyStore.getKey(CURRENT_KEY_ALIAS, null) as? SecretKey
    if (existing != null) {
      try {
        check(isPolicyAcceptable(keyInfo(existing))) { "Android Keystore key policy does not match this build" }
        return existing
      } catch (_: Exception) {
        clear(activity)
      }
    }
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P &&
      activity.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)
    ) {
      try {
        return generateKey(strongBox = true)
      } catch (_: StrongBoxUnavailableException) {
        // Some devices advertise StrongBox but do not support this exact AES
        // and auth-per-use combination. Fall back to the TEE-backed provider.
        val keyStore = keyStore()
        if (keyStore.containsAlias(CURRENT_KEY_ALIAS)) keyStore.deleteEntry(CURRENT_KEY_ALIAS)
      }
    }
    return generateKey(strongBox = false)
  }

  private fun generateKey(strongBox: Boolean): SecretKey {
    val builder = KeyGenParameterSpec.Builder(
      CURRENT_KEY_ALIAS,
      KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
    )
      .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
      .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
      .setKeySize(256)
      .setRandomizedEncryptionRequired(true)
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
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P && strongBox) {
      builder.setIsStrongBoxBacked(true)
    }

    val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
    generator.init(builder.build())
    return generator.generateKey()
  }
}

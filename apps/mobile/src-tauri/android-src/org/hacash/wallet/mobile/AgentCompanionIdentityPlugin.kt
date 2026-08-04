package org.hacash.wallet.mobile

import android.app.Activity
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import android.util.Base64
import android.util.Log
import androidx.appcompat.app.AppCompatActivity
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import app.tauri.annotation.Command
import app.tauri.annotation.InvokeArg
import app.tauri.annotation.TauriPlugin
import app.tauri.plugin.Invoke
import app.tauri.plugin.JSObject
import app.tauri.plugin.Plugin
import java.math.BigInteger
import java.security.InvalidKeyException
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

private const val LOG_TAG = "HPAYAgentIdentity"
private const val ANDROID_KEYSTORE = "AndroidKeyStore"
private const val COMPANION_KEY_ALIAS = "hpay_agent_companion_identity_v1"
private const val SIGNATURE_ALGORITHM = "SHA256withECDSA"
private const val MAX_CANONICAL_PAYLOAD_BYTES = 256 * 1024
private const val MAX_CANONICAL_PAYLOAD_BASE64_CHARS =
  ((MAX_CANONICAL_PAYLOAD_BYTES + 2) / 3) * 4
private val P256_ORDER =
  BigInteger("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16)
private val PAIRING_REQUEST_DOMAIN =
  "HPAY/COMPANION/PAIRING-REQUEST/V1".toByteArray(Charsets.US_ASCII)
private val PAIRING_MOBILE_PROOF_DOMAIN =
  "HPAY/COMPANION/PAIRING-MOBILE-PROOF/V1".toByteArray(Charsets.US_ASCII)
private val SESSION_RESPONSE_DOMAIN =
  "HPAY/COMPANION/SESSION-RESPONSE/V1".toByteArray(Charsets.US_ASCII)
private val APPROVAL_DECISION_DOMAIN =
  "HPAY/COMPANION/APPROVAL-DECISION/V2".toByteArray(Charsets.US_ASCII)
private val WITNESS_RECEIPT_DOMAIN =
  "HPAY/COMPANION/WITNESS-RECEIPT/V1".toByteArray(Charsets.US_ASCII)
private val WITNESS_ROTATION_DOMAIN =
  "HPAY/COMPANION/WITNESS-ROTATION/V1".toByteArray(Charsets.US_ASCII)
private val ROTATION_CANDIDATE_ACCEPTANCE_DOMAIN =
  "HPAY/COMPANION/ROTATION-CANDIDATE-ACCEPTANCE/V1".toByteArray(Charsets.US_ASCII)
private val WITNESS_ROTATION_BASELINE_DOMAIN =
  "HPAY/COMPANION/WITNESS-ROTATION-BASELINE/V1".toByteArray(Charsets.US_ASCII)

@InvokeArg
class CompanionIdentitySignArgs {
  var payloadBase64: String = ""
}

/**
 * Dedicated native boundary for the mobile companion identity.
 *
 * This plugin cannot access Personal Wallet keys and has no generic sign method.
 * Its only private key is generated non-exportably inside Android Keystore.
 */
@TauriPlugin
class AgentCompanionIdentityPlugin(private val activity: Activity) : Plugin(activity) {
  private class PendingSignature(
    val invoke: Invoke,
    val canonicalPayload: ByteArray,
  ) {
    private val complete = AtomicBoolean(false)

    fun resolve(signatureDer: ByteArray) {
      if (!complete.compareAndSet(false, true)) return
      try {
        invoke.resolve(
          JSObject().apply {
            put(
              "signatureDerBase64",
              Base64.encodeToString(signatureDer, Base64.NO_WRAP),
            )
          },
        )
      } finally {
        signatureDer.fill(0)
        canonicalPayload.fill(0)
      }
    }

    fun reject(message: String) {
      if (!complete.compareAndSet(false, true)) return
      try {
        invoke.reject(message)
      } finally {
        canonicalPayload.fill(0)
      }
    }
  }

  private enum class SigningKeyState {
    Usable,
    Invalidated,
    Unavailable,
  }

  private data class IdentityInspection(
    val nonExportable: Boolean,
    val hardwareBacked: Boolean,
    val strongBoxBacked: Boolean,
    val authenticationEnforcedBySecureHardware: Boolean,
    val authPerUse: Boolean,
    val exactKeyPolicy: Boolean,
    val invalidatedByBiometricEnrollment: Boolean,
    val signingKeyState: SigningKeyState,
    val publicKeySec1: ByteArray?,
    val preparedSignature: Signature?,
  ) {
    val policyAccepted: Boolean
      get() =
        nonExportable &&
          hardwareBacked &&
          authenticationEnforcedBySecureHardware &&
          authPerUse &&
          exactKeyPolicy &&
          invalidatedByBiometricEnrollment &&
          publicKeySec1 != null

    val ready: Boolean
      get() =
        policyAccepted &&
          signingKeyState == SigningKeyState.Usable &&
          preparedSignature != null

    val recreationRequired: Boolean
      get() = !policyAccepted || signingKeyState == SigningKeyState.Invalidated
  }

  private val worker: ExecutorService = Executors.newSingleThreadExecutor { task ->
    Thread(task, "hpay-agent-companion-identity").apply { isDaemon = true }
  }
  private val destroyed = AtomicBoolean(false)
  private var activePrompt: BiometricPrompt? = null
  private var activeSignature: PendingSignature? = null

  @Command
  fun identityStatus(invoke: Invoke) {
    execute(invoke) { identityStatus(create = false) }
  }

  @Command
  fun createIdentity(invoke: Invoke) {
    execute(invoke) { identityStatus(create = true) }
  }

  @Command
  fun signPairingRequest(invoke: Invoke) {
    signTyped(invoke, PAIRING_REQUEST_DOMAIN, "Pair this phone with HPAY Desktop")
  }

  @Command
  fun signPairingMobileProof(invoke: Invoke) {
    signTyped(
      invoke,
      PAIRING_MOBILE_PROOF_DOMAIN,
      "Confirm this phone's HPAY pairing",
    )
  }

  @Command
  fun signSessionResponse(invoke: Invoke) {
    signTyped(
      invoke,
      SESSION_RESPONSE_DOMAIN,
      "Authenticate this phone to HPAY Desktop",
    )
  }

  @Command
  fun signApprovalDecisionApprove(invoke: Invoke) {
    signTyped(
      invoke,
      APPROVAL_DECISION_DOMAIN,
      "Approve this exact HPAY testnet payment",
    )
  }

  @Command
  fun signApprovalDecisionReject(invoke: Invoke) {
    signTyped(
      invoke,
      APPROVAL_DECISION_DOMAIN,
      "Reject this exact HPAY testnet payment",
    )
  }

  @Command
  fun signWitnessReceipt(invoke: Invoke) {
    signTyped(
      invoke,
      WITNESS_RECEIPT_DOMAIN,
      "Witness this HPAY Agent Wallet testnet state",
    )
  }

  @Command
  fun signWitnessRotationAuthorization(invoke: Invoke) {
    signTyped(
      invoke,
      WITNESS_ROTATION_DOMAIN,
      "Authorize replacement of the HPAY witness phone",
    )
  }

  @Command
  fun signRotationCandidateAcceptance(invoke: Invoke) {
    signTyped(
      invoke,
      ROTATION_CANDIDATE_ACCEPTANCE_DOMAIN,
      "Accept restricted HPAY witness rotation pairing",
    )
  }

  @Command
  fun signWitnessRotationBaselineReceipt(invoke: Invoke) {
    signTyped(
      invoke,
      WITNESS_ROTATION_BASELINE_DOMAIN,
      "Accept this HPAY witness recovery baseline",
    )
  }


  private fun execute(invoke: Invoke, operation: () -> JSObject) {
    if (destroyed.get()) {
      invoke.reject("Android Activity is no longer available")
      return
    }
    try {
      worker.execute {
        try {
          if (destroyed.get()) {
            invoke.reject("Android Activity is no longer available")
          } else {
            invoke.resolve(operation())
          }
        } catch (error: Exception) {
          invoke.reject(error.message ?: "Android companion identity operation failed")
        }
      }
    } catch (error: Exception) {
      invoke.reject(error.message ?: "Android companion identity worker is unavailable")
    }
  }

  private fun signTyped(invoke: Invoke, expectedDomain: ByteArray, description: String) {
    val args = invoke.parseArgs(CompanionIdentitySignArgs::class.java)
    val encodedPayload = args.payloadBase64
    args.payloadBase64 = ""
    if (encodedPayload.length > MAX_CANONICAL_PAYLOAD_BASE64_CHARS) {
      invoke.reject("Companion signing payload is too large")
      return
    }
    val payload = try {
      Base64.decode(encodedPayload, Base64.NO_WRAP)
    } catch (_: IllegalArgumentException) {
      invoke.reject("Companion signing payload is not valid base64")
      return
    }
    if (!hasCanonicalDomain(payload, expectedDomain)) {
      payload.fill(0)
      Log.w(LOG_TAG, "sign request rejected: protocol domain")
      invoke.reject("Companion signing payload has the wrong protocol domain")
      return
    }
    Log.i(LOG_TAG, "sign request accepted: $description")
    val fragmentActivity = AgentCompanionActivity.currentResumed()
    if (fragmentActivity == null) {
      payload.fill(0)
      Log.w(LOG_TAG, "sign request rejected: Agent Activity is not resumed")
      invoke.reject("Open the Agent Wallet before companion authentication")
      return
    }
    if (BiometricManager.from(fragmentActivity).canAuthenticate(
        BiometricManager.Authenticators.BIOMETRIC_STRONG,
      ) != BiometricManager.BIOMETRIC_SUCCESS
    ) {
      payload.fill(0)
      Log.w(LOG_TAG, "sign request rejected: Class 3 biometric unavailable")
      invoke.reject("A Class 3 biometric is required for companion authentication")
      return
    }
    val pending = PendingSignature(invoke, payload)
    synchronized(this) {
      if (destroyed.get()) {
        pending.reject("Android Activity is no longer available")
        return
      }
      if (activeSignature != null) {
        pending.reject("Another Agent Wallet signature is already active")
        return
      }
      activeSignature = pending
    }
    Log.i(LOG_TAG, "hardware signing slot reserved: $description")

    try {
      worker.execute {
        try {
          val signature = prepareSignature()
          Log.i(LOG_TAG, "Keystore signature prepared: $description")
          fragmentActivity.runOnUiThread {
            presentSignaturePrompt(fragmentActivity, pending, signature, description)
          }
        } catch (error: Exception) {
          Log.w(LOG_TAG, "Keystore signature preparation failed: ${error.javaClass.simpleName}")
          finishSignature(pending) {
            pending.reject(error.message ?: "Agent companion signing key is unavailable")
          }
        }
      }
    } catch (error: Exception) {
      finishSignature(pending) {
        pending.reject(error.message ?: "Android companion identity worker is unavailable")
      }
    }
  }

  private fun presentSignaturePrompt(
    fragmentActivity: AgentCompanionActivity,
    pending: PendingSignature,
    preparedSignature: Signature,
    description: String,
  ) {
    if (destroyed.get()) {
      finishSignature(pending) {
        pending.reject("Android Activity is no longer available")
      }
      return
    }
    val callback = object : BiometricPrompt.AuthenticationCallback() {
      override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
        Log.i(LOG_TAG, "biometric callback succeeded: $description")
        val authorizedSignature = result.cryptoObject?.signature
        if (authorizedSignature !== preparedSignature) {
          finishSignature(pending) {
            pending.reject("Biometric result was not bound to the companion signature")
          }
          return
        }
        try {
          worker.execute {
            try {
              authorizedSignature.update(pending.canonicalPayload)
              val signatureDer = authorizedSignature.sign()
              finishSignature(pending) { pending.resolve(signatureDer) }
            } catch (error: Exception) {
              finishSignature(pending) {
                pending.reject(error.message ?: "Agent companion signature failed")
              }
            }
          }
        } catch (error: Exception) {
          finishSignature(pending) {
            pending.reject(error.message ?: "Android companion identity worker is unavailable")
          }
        }
      }

      override fun onAuthenticationError(errorCode: Int, errorMessage: CharSequence) {
        Log.w(LOG_TAG, "biometric callback error code=$errorCode: $description")
        finishSignature(pending) {
          pending.reject(
            errorMessage.toString().ifBlank { "Biometric authentication failed" },
          )
        }
      }
    }
    try {
      val prompt = BiometricPrompt(
        fragmentActivity,
        ContextCompat.getMainExecutor(fragmentActivity),
        callback,
      )
      val promptInfo = BiometricPrompt.PromptInfo.Builder()
        .setTitle("HPAY Agent Wallet")
        .setDescription(description)
        .setConfirmationRequired(true)
        .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
        .setNegativeButtonText("Cancel")
        .build()
      val mayPresent = synchronized(this) {
        if (
          destroyed.get() ||
          activeSignature !== pending ||
          AgentCompanionActivity.currentResumed() !== fragmentActivity
        ) {
          false
        } else {
          activePrompt = prompt
          true
        }
      }
      if (!mayPresent) {
        finishSignature(pending) {
          pending.reject("The Agent Wallet is not in the foreground")
        }
        return
      }
      Log.i(LOG_TAG, "biometric prompt requested: $description")
      prompt.authenticate(promptInfo, BiometricPrompt.CryptoObject(preparedSignature))
    } catch (error: Exception) {
      Log.w(LOG_TAG, "biometric prompt failed to start: ${error.javaClass.simpleName}")
      finishSignature(pending) {
        pending.reject(error.message ?: "Biometric signature prompt could not start")
      }
    }
  }

  private fun prepareSignature(): Signature {
    val entry = keyStore().getEntry(COMPANION_KEY_ALIAS, null)
      as? KeyStore.PrivateKeyEntry
      ?: throw IllegalStateException("Agent companion identity has not been created")
    val inspection = inspectIdentity(entry)
    if (!inspection.ready) {
      val reason =
        if (inspection.signingKeyState == SigningKeyState.Invalidated) {
          "Agent companion identity was invalidated; recreate it explicitly"
        } else {
          "Agent companion identity does not satisfy the hardware biometric policy"
        }
      throw IllegalStateException(reason)
    }
    return inspection.preparedSignature
      ?: throw IllegalStateException("Agent companion signing key is unavailable")
  }

  private fun identityStatus(create: Boolean): JSObject {
    val store = keyStore()
    if (!store.containsAlias(COMPANION_KEY_ALIAS)) {
      if (!create) return unavailableIdentityStatus()
      recreateIdentity(store)
    }

    var entry = store.getEntry(COMPANION_KEY_ALIAS, null) as? KeyStore.PrivateKeyEntry
    if (entry == null) {
      if (!create) return unavailableIdentityStatus()
      recreateIdentity(store)
      entry = store.getEntry(COMPANION_KEY_ALIAS, null) as? KeyStore.PrivateKeyEntry
        ?: throw IllegalStateException("Agent companion identity recreation failed")
    }

    var inspection = inspectIdentity(entry)
    if (create && !inspection.ready) {
      if (!inspection.recreationRequired) {
        throw IllegalStateException(
          "Agent companion identity is temporarily unavailable; no key was replaced",
        )
      }
      recreateIdentity(store)
      entry = store.getEntry(COMPANION_KEY_ALIAS, null) as? KeyStore.PrivateKeyEntry
        ?: throw IllegalStateException("Agent companion identity recreation failed")
      inspection = inspectIdentity(entry)
    }
    return identityStatusObject(inspection)
  }

  private fun inspectIdentity(entry: KeyStore.PrivateKeyEntry): IdentityInspection {
    val nonExportable = entry.privateKey.encoded == null
    val keyFactory = KeyFactory.getInstance(entry.privateKey.algorithm, ANDROID_KEYSTORE)
    val info = keyFactory.getKeySpec(entry.privateKey, KeyInfo::class.java)
    val strongBoxBacked =
      Build.VERSION.SDK_INT >= Build.VERSION_CODES.S &&
        info.securityLevel == KeyProperties.SECURITY_LEVEL_STRONGBOX
    val hardwareBacked =
      if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
        info.securityLevel == KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT || strongBoxBacked
      } else {
        @Suppress("DEPRECATION")
        val insideSecureHardware = info.isInsideSecureHardware
        insideSecureHardware
      }
    val authenticationEnforcedBySecureHardware =
      info.isUserAuthenticationRequirementEnforcedBySecureHardware
    val authPerUse = isAuthenticationPerUse(info)
    val publicKey = entry.certificate.publicKey as? ECPublicKey
    val expectedPurposes = KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
    val p256PublicKey =
      publicKey != null &&
        publicKey.params.curve.field.fieldSize == 256 &&
        publicKey.params.order == P256_ORDER
    val exactKeyPolicy =
      entry.privateKey.algorithm == KeyProperties.KEY_ALGORITHM_EC &&
        info.keySize == 256 &&
        info.purposes == expectedPurposes &&
        runCatching {
          info.digests.toSet() == setOf(KeyProperties.DIGEST_SHA256)
        }.getOrDefault(false) &&
        p256PublicKey
    val invalidatedByBiometricEnrollment = info.isInvalidatedByBiometricEnrollment
    val publicKeySec1 = publicKey?.let { runCatching { compressedSec1(it) }.getOrNull() }
    var preparedSignature: Signature? = null
    val signingKeyState =
      if (!nonExportable) {
        SigningKeyState.Unavailable
      } else {
        try {
          preparedSignature = Signature.getInstance(SIGNATURE_ALGORITHM).apply {
            initSign(entry.privateKey)
          }
          SigningKeyState.Usable
        } catch (_: KeyPermanentlyInvalidatedException) {
          SigningKeyState.Invalidated
        } catch (_: InvalidKeyException) {
          SigningKeyState.Unavailable
        }
      }
    return IdentityInspection(
      nonExportable = nonExportable,
      hardwareBacked = hardwareBacked,
      strongBoxBacked = strongBoxBacked,
      authenticationEnforcedBySecureHardware = authenticationEnforcedBySecureHardware,
      authPerUse = authPerUse,
      exactKeyPolicy = exactKeyPolicy,
      invalidatedByBiometricEnrollment = invalidatedByBiometricEnrollment,
      signingKeyState = signingKeyState,
      publicKeySec1 = publicKeySec1,
      preparedSignature = preparedSignature,
    )
  }

  @Suppress("DEPRECATION")
  private fun isAuthenticationPerUse(info: KeyInfo): Boolean {
    if (!info.isUserAuthenticationRequired) return false
    return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
      info.userAuthenticationValidityDurationSeconds == 0 &&
        info.userAuthenticationType == KeyProperties.AUTH_BIOMETRIC_STRONG
    } else {
      info.userAuthenticationValidityDurationSeconds == -1
    }
  }

  private fun recreateIdentity(store: KeyStore) {
    requireStrongBiometric()
    if (store.containsAlias(COMPANION_KEY_ALIAS)) {
      store.deleteEntry(COMPANION_KEY_ALIAS)
    }
    try {
      generateIdentityWithStrongBoxFallback(store)
      val entry = store.getEntry(COMPANION_KEY_ALIAS, null) as? KeyStore.PrivateKeyEntry
        ?: throw IllegalStateException("Agent companion identity generation failed")
      if (!inspectIdentity(entry).ready) {
        throw IllegalStateException(
          "Generated Agent companion identity does not satisfy the hardware biometric policy",
        )
      }
    } catch (error: Exception) {
      runCatching {
        if (store.containsAlias(COMPANION_KEY_ALIAS)) {
          store.deleteEntry(COMPANION_KEY_ALIAS)
        }
      }
      throw error
    }
  }

  private fun identityStatusObject(inspection: IdentityInspection): JSObject =
    JSObject().apply {
      put("configured", inspection.ready)
      inspection.publicKeySec1
        ?.takeIf { inspection.ready }
        ?.let { put("publicKeySec1Hex", it.toHex()) }
      put(
        "keySecurityLevel",
        when {
          inspection.strongBoxBacked -> "strongbox"
          inspection.hardwareBacked -> "trusted_environment"
          else -> "software"
        },
      )
      put("hardwareBacked", inspection.hardwareBacked)
      put("strongBoxBacked", inspection.strongBoxBacked)
      put(
        "authenticationEnforcedBySecureHardware",
        inspection.authenticationEnforcedBySecureHardware,
      )
      put("authPerUse", inspection.authPerUse)
    }

  private fun unavailableIdentityStatus(): JSObject =
    JSObject().apply {
      put("configured", false)
      put("keySecurityLevel", "unavailable")
      put("hardwareBacked", false)
      put("strongBoxBacked", false)
      put("authenticationEnforcedBySecureHardware", false)
      put("authPerUse", false)
    }

  private fun requireStrongBiometric() {
    if (BiometricManager.from(activity).canAuthenticate(
        BiometricManager.Authenticators.BIOMETRIC_STRONG,
      ) != BiometricManager.BIOMETRIC_SUCCESS
    ) {
      throw IllegalStateException(
        "A Class 3 biometric must be enrolled before creating the Agent companion identity",
      )
    }
  }

  private fun generateIdentityWithStrongBoxFallback(store: KeyStore) {
    try {
      generateIdentity(useStrongBox = true)
      return
    } catch (_: StrongBoxUnavailableException) {
      store.deleteEntry(COMPANION_KEY_ALIAS)
    }
    generateIdentity(useStrongBox = false)
  }

  private fun generateIdentity(useStrongBox: Boolean) {
    val builder = KeyGenParameterSpec.Builder(
      COMPANION_KEY_ALIAS,
      KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY,
    )
      .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
      .setDigests(KeyProperties.DIGEST_SHA256)
      .setUserAuthenticationRequired(true)
      .setInvalidatedByBiometricEnrollment(true)
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
      builder.setUserAuthenticationParameters(
        0,
        KeyProperties.AUTH_BIOMETRIC_STRONG,
      )
    } else {
      @Suppress("DEPRECATION")
      builder.setUserAuthenticationValidityDurationSeconds(-1)
    }
    builder.setIsStrongBoxBacked(useStrongBox)
    KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE).apply {
      initialize(builder.build())
      generateKeyPair()
    }
  }

  private fun keyStore(): KeyStore =
    KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

  private fun finishSignature(pending: PendingSignature, finish: () -> Unit) {
    synchronized(this) {
      if (activeSignature === pending) {
        activePrompt = null
        activeSignature = null
      }
    }
    finish()
  }

  override fun onDestroy(activity: AppCompatActivity) {
    if (activity !== this.activity && activity !is AgentCompanionActivity) return
    val pending = synchronized(this) {
      activePrompt?.cancelAuthentication()
      activePrompt = null
      activeSignature.also { activeSignature = null }
    }
    if (activity !== this.activity) {
      pending?.reject("The Agent Wallet was closed before signing completed")
      return
    }
    destroyed.set(true)
    pending?.reject("The Android host Activity was destroyed before signing completed")
    worker.shutdownNow()
  }
}

private fun hasCanonicalDomain(payload: ByteArray, expectedDomain: ByteArray): Boolean {
  if (payload.size > MAX_CANONICAL_PAYLOAD_BYTES || payload.size < 4 + expectedDomain.size) {
    return false
  }
  val length =
    ((payload[0].toInt() and 0xff) shl 24) or
      ((payload[1].toInt() and 0xff) shl 16) or
      ((payload[2].toInt() and 0xff) shl 8) or
      (payload[3].toInt() and 0xff)
  if (length != expectedDomain.size) return false
  return expectedDomain.indices.all { index -> payload[index + 4] == expectedDomain[index] }
}

private fun compressedSec1(publicKey: ECPublicKey): ByteArray {
  val x = publicKey.w.affineX.toUnsignedFixed(32)
  val prefix = if (publicKey.w.affineY.testBit(0)) 0x03 else 0x02
  return byteArrayOf(prefix.toByte()) + x
}

private fun BigInteger.toUnsignedFixed(size: Int): ByteArray {
  val raw = toByteArray()
  val unsigned = if (raw.size > 1 && raw[0] == 0.toByte()) raw.copyOfRange(1, raw.size) else raw
  require(unsigned.size <= size) { "EC coordinate is too large" }
  return ByteArray(size).also { output ->
    unsigned.copyInto(output, destinationOffset = size - unsigned.size)
  }
}

private fun ByteArray.toHex(): String = joinToString(separator = "") { byte ->
  "%02x".format(byte.toInt() and 0xff)
}

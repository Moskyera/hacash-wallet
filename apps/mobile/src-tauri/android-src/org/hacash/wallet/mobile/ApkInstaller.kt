package org.hacash.wallet.mobile

import android.app.Activity
import android.content.Intent
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Looper
import android.provider.Settings
import android.util.Base64
import androidx.core.content.FileProvider
import java.io.File
import java.security.MessageDigest
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

object ApkInstaller {
    @JvmStatic
    fun install(activity: Activity, apkPath: String) {
        val source = verifiedSource(activity, apkPath)
        if (Looper.myLooper() == Looper.getMainLooper()) {
            installOnMain(activity, source)
            return
        }
        val latch = CountDownLatch(1)
        var error: Exception? = null
        activity.runOnUiThread {
            try {
                installOnMain(activity, source)
            } catch (e: Exception) {
                error = e
            } finally {
                latch.countDown()
            }
        }
        if (!latch.await(15, TimeUnit.SECONDS)) {
            throw IllegalStateException("Android installer did not respond in time. The wallet is still running.")
        }
        error?.let { throw it }
    }

    private fun verifiedSource(activity: Activity, apkPath: String): File {
        val source = File(apkPath).canonicalFile
        val updateRoot = File(activity.cacheDir, "updates").canonicalFile
        if (!source.exists()) {
            throw IllegalArgumentException("APK not found: $apkPath")
        }
        if (!source.isFile || source.length() < 100_000L) {
            throw IllegalArgumentException("APK file is missing or too small to install")
        }
        val rootPrefix = updateRoot.path + File.separator
        if (!source.path.startsWith(rootPrefix)) {
            throw IllegalArgumentException("APK must be a verified wallet update")
        }
        verifyPackageIdentityAndSigner(activity, source)
        return source
    }

    private data class SignerIdentity(
        val hasMultipleSigners: Boolean,
        val currentCertificateSha256: Set<String>,
        val certificateHistorySha256: Set<String>,
    )

    private fun verifyPackageIdentityAndSigner(activity: Activity, source: File) {
        val packageManager = activity.packageManager
        val candidate = archivePackageInfo(packageManager, source)
        if (candidate.packageName != activity.packageName) {
            throw SecurityException("Downloaded APK package does not match Hacash Wallet")
        }

        val installed = installedPackageInfo(packageManager, activity.packageName)
        val candidateVersion = packageVersionCode(candidate)
        val installedVersion = packageVersionCode(installed)
        if (candidateVersion <= installedVersion) {
            throw SecurityException("Downloaded APK is not a newer Hacash Wallet version")
        }

        val candidateIdentity = signerIdentity(candidate)
        val installedIdentity = signerIdentity(installed)
        val signerMatches = if (
            candidateIdentity.hasMultipleSigners || installedIdentity.hasMultipleSigners
        ) {
            candidateIdentity.hasMultipleSigners &&
                installedIdentity.hasMultipleSigners &&
                candidateIdentity.currentCertificateSha256 ==
                installedIdentity.currentCertificateSha256
        } else {
            candidateIdentity.certificateHistorySha256
                .intersect(installedIdentity.currentCertificateSha256)
                .isNotEmpty()
        }
        if (!signerMatches) {
            throw SecurityException("Downloaded APK signing certificate does not match this app")
        }
    }

    private fun archivePackageInfo(
        packageManager: PackageManager,
        source: File,
    ): PackageInfo {
        val info = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            packageManager.getPackageArchiveInfo(
                source.path,
                PackageManager.PackageInfoFlags.of(
                    PackageManager.GET_SIGNING_CERTIFICATES.toLong(),
                ),
            )
        } else {
            @Suppress("DEPRECATION")
            packageManager.getPackageArchiveInfo(
                source.path,
                PackageManager.GET_SIGNING_CERTIFICATES,
            )
        }
        return info ?: throw SecurityException("Downloaded APK could not be parsed")
    }

    private fun installedPackageInfo(
        packageManager: PackageManager,
        packageName: String,
    ): PackageInfo {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            packageManager.getPackageInfo(
                packageName,
                PackageManager.PackageInfoFlags.of(
                    PackageManager.GET_SIGNING_CERTIFICATES.toLong(),
                ),
            )
        } else {
            @Suppress("DEPRECATION")
            packageManager.getPackageInfo(
                packageName,
                PackageManager.GET_SIGNING_CERTIFICATES,
            )
        }
    }

    private fun packageVersionCode(info: PackageInfo): Long {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            info.longVersionCode
        } else {
            @Suppress("DEPRECATION")
            info.versionCode.toLong()
        }
    }

    private fun signerIdentity(info: PackageInfo): SignerIdentity {
        val signingInfo = info.signingInfo
            ?: throw SecurityException("Package signing information is unavailable")
        val currentSignatures = signingInfo.apkContentsSigners
        if (currentSignatures.isNullOrEmpty()) {
            throw SecurityException("Package has no current signing certificate")
        }
        val history = if (signingInfo.hasMultipleSigners()) {
            currentSignatures
        } else {
            signingInfo.signingCertificateHistory
        }
        if (history.isNullOrEmpty()) {
            throw SecurityException("Package has no verified signing history")
        }
        return SignerIdentity(
            signingInfo.hasMultipleSigners(),
            certificateDigests(currentSignatures),
            certificateDigests(history),
        )
    }

    private fun certificateDigests(
        signatures: Array<android.content.pm.Signature>,
    ): Set<String> {
        return signatures.mapTo(linkedSetOf()) { signature ->
            val certificate = signature.toByteArray()
            try {
                Base64.encodeToString(
                    MessageDigest.getInstance("SHA-256").digest(certificate),
                    Base64.NO_WRAP,
                )
            } finally {
                certificate.fill(0)
            }
        }
    }

    private fun installOnMain(activity: Activity, source: File) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            if (!activity.packageManager.canRequestPackageInstalls()) {
                val settings = Intent(Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES).apply {
                    data = Uri.parse("package:${activity.packageName}")
                    addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                }
                activity.startActivity(settings)
                throw IllegalStateException(
                    "Allow \"Install unknown apps\" for Hacash Wallet, then tap Download & install again."
                )
            }
        }

        val authority = "${activity.packageName}.fileprovider"
        val uri = FileProvider.getUriForFile(activity, authority, source)
        val intent = Intent(Intent.ACTION_VIEW).apply {
            setDataAndType(uri, "application/vnd.android.package-archive")
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        }

        val handlers = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            activity.packageManager.queryIntentActivities(
                intent,
                PackageManager.ResolveInfoFlags.of(PackageManager.MATCH_DEFAULT_ONLY.toLong()),
            )
        } else {
            @Suppress("DEPRECATION")
            activity.packageManager.queryIntentActivities(intent, PackageManager.MATCH_DEFAULT_ONLY)
        }

        if (handlers.isEmpty()) {
            throw IllegalStateException(
                "No package installer found. Use \"Open in browser\" to download the APK."
            )
        }

        for (handler in handlers) {
            val pkg = handler.activityInfo.packageName
            activity.grantUriPermission(pkg, uri, Intent.FLAG_GRANT_READ_URI_PERMISSION)
        }

        val chooser = Intent.createChooser(intent, "Install Hacash Wallet update")
        activity.startActivity(chooser)
    }
}

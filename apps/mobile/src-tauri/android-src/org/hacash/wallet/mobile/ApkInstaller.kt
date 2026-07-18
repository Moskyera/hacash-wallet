package org.hacash.wallet.mobile

import android.app.Activity
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Looper
import android.provider.Settings
import androidx.core.content.FileProvider
import java.io.File
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
        return source
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

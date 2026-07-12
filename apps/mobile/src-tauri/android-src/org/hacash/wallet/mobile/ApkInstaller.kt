package org.hacash.wallet.mobile

import android.app.Activity
import android.content.Intent
import androidx.core.content.FileProvider
import java.io.File

object ApkInstaller {
    @JvmStatic
    fun install(activity: Activity, apkPath: String) {
        val file = File(apkPath)
        if (!file.exists()) {
            throw IllegalArgumentException("APK not found: $apkPath")
        }
        val authority = activity.packageName + ".fileprovider"
        val uri = FileProvider.getUriForFile(activity, authority, file)
        val intent = Intent(Intent.ACTION_VIEW).apply {
            setDataAndType(uri, "application/vnd.android.package-archive")
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        }
        activity.startActivity(intent)
    }
}
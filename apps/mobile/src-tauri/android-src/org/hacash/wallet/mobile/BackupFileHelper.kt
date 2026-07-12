package org.hacash.wallet.mobile

import android.app.Activity
import android.net.Uri
import java.io.File

object BackupFileHelper {
    @JvmStatic
    fun deleteBackupSource(activity: Activity, source: String): Boolean {
        if (source.isBlank()) return false
        return when {
            source.startsWith("content://") -> {
                try {
                    activity.contentResolver.delete(Uri.parse(source), null, null) > 0
                } catch (_: Exception) {
                    false
                }
            }
            else -> {
                val file = File(source)
                if (!file.exists() || !file.isFile) return false
                if (!file.name.endsWith(".json", ignoreCase = true)) return false
                try {
                    file.delete()
                } catch (_: Exception) {
                    false
                }
            }
        }
    }
}
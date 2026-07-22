package org.hacash.wallet.mobile

import android.app.Activity
import android.content.ContentValues
import android.net.Uri
import android.os.Build
import android.os.Environment
import android.provider.MediaStore
import java.io.File

object BackupExportHelper {
    @JvmStatic
    fun copyFileToDownloads(activity: Activity, sourcePath: String, displayName: String): String {
        if (displayName.isBlank() ||
            displayName.length > 128 ||
            displayName != displayName.trim() ||
            File(displayName).name != displayName ||
            displayName.any { it == '/' || it.code == 92 || it.isISOControl() } ||
            !displayName.endsWith(".json", ignoreCase = true)
        ) {
            throw IllegalArgumentException("Backup filename must be a safe .json basename")
        }
        val source = File(sourcePath)
        if (!source.isFile) {
            throw IllegalArgumentException("Backup source missing: $sourcePath")
        }
        if (source.length() > 2L * 1024L * 1024L) {
            throw IllegalArgumentException("Backup file exceeds the 2 MiB safety limit")
        }
        val bytes = source.readBytes()
        if (bytes.isEmpty()) {
            throw IllegalArgumentException("Backup file is empty")
        }
        return try {
            writeBytesToDownloads(activity, displayName, bytes)
        } finally {
            bytes.fill(0)
        }
    }

    private fun writeBytesToDownloads(activity: Activity, filename: String, bytes: ByteArray): String {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            var uri: Uri? = null
            try {
                val values = ContentValues().apply {
                    put(MediaStore.Downloads.DISPLAY_NAME, filename)
                    put(MediaStore.MediaColumns.MIME_TYPE, "application/json")
                    put(MediaStore.Downloads.RELATIVE_PATH, Environment.DIRECTORY_DOWNLOADS)
                    put(MediaStore.Downloads.IS_PENDING, 1)
                }
                val resolver = activity.contentResolver
                uri = resolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, values)
                    ?: throw IllegalStateException("Could not create backup in Downloads")
                resolver.openOutputStream(uri)?.use { stream ->
                    stream.write(bytes)
                    stream.flush()
                } ?: throw IllegalStateException("Could not write backup file")
                values.clear()
                values.put(MediaStore.Downloads.IS_PENDING, 0)
                resolver.update(uri, values, null, null)
                return "Downloads/$filename"
            } catch (e: Exception) {
                uri?.let { activity.contentResolver.delete(it, null, null) }
                throw e
            }
        }
        @Suppress("DEPRECATION")
        val dir = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS)
        if (!dir.exists() && !dir.mkdirs()) {
            throw IllegalStateException("Downloads folder unavailable")
        }
        val file = File(dir, filename)
        file.writeBytes(bytes)
        return file.absolutePath
    }
}

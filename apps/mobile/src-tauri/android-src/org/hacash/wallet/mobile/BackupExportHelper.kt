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
        if (displayName.isBlank() || !displayName.endsWith(".json", ignoreCase = true)) {
            throw IllegalArgumentException("Backup filename must end with .json")
        }
        val source = File(sourcePath)
        if (!source.isFile) {
            throw IllegalArgumentException("Backup source missing: $sourcePath")
        }
        val bytes = source.readBytes()
        if (bytes.isEmpty()) {
            throw IllegalArgumentException("Backup file is empty")
        }
        return writeBytesToDownloads(activity, displayName, bytes)
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
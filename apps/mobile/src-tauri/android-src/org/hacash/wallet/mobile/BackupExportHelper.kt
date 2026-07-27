package org.hacash.wallet.mobile

import android.app.Activity
import android.content.ContentValues
import android.net.Uri
import android.os.Build
import android.os.Environment
import android.provider.MediaStore
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.nio.file.Files
import java.util.UUID

object BackupExportHelper {
    private const val MAX_BACKUP_BYTES = 64L * 1024L * 1024L
    private const val COPY_BUFFER_BYTES = 64 * 1024

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
        val requestedSource = File(sourcePath)
        val source = requestedSource.canonicalFile
        val cacheRoot = activity.cacheDir.canonicalFile
        // Each rejection reports its own reason. Collapsing them into one "source
        // missing" message hid a real bug for a whole release: the Rust side staged
        // the file in the external cache, so the parent never matched and every
        // export failed while appearing to be a missing-file problem.
        if (Files.isSymbolicLink(requestedSource.toPath())) {
            throw IllegalArgumentException("Backup source must not be a symbolic link: $sourcePath")
        }
        if (source.parentFile != cacheRoot) {
            throw IllegalArgumentException(
                "Backup source must be staged in the app private cache directory " +
                    "$cacheRoot, got ${source.parent}. The Rust side must use " +
                    "app_cache_dir(), not cache_dir()",
            )
        }
        if (!source.isFile) {
            throw IllegalArgumentException("Backup source missing: $sourcePath")
        }
        val expectedLength = source.length()
        if (expectedLength !in 1L..MAX_BACKUP_BYTES) {
            throw IllegalArgumentException("Backup file size is outside the 64 MiB safety limit")
        }
        return writeFileToDownloads(activity, displayName, source, expectedLength)
    }

    private fun writeFileToDownloads(activity: Activity, filename: String, source: File, expectedLength: Long): String {
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
                    FileInputStream(source).use { input ->
                        if (copyBounded(input, stream) != expectedLength) {
                            throw IllegalStateException("Backup source length changed during export")
                        }
                        stream.flush()
                    }
                } ?: throw IllegalStateException("Could not write backup file")
                verifySourceUnchanged(source, expectedLength)
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
        val destination = File(dir, filename)
        if (destination.exists()) {
            throw IllegalStateException("A backup with this name already exists")
        }
        val temporary = File(dir, ".$filename.${UUID.randomUUID()}.part")
        if (!temporary.createNewFile()) {
            throw IllegalStateException("Could not create temporary backup in Downloads")
        }
        try {
            FileInputStream(source).use { input ->
                FileOutputStream(temporary, false).use { output ->
                    if (copyBounded(input, output) != expectedLength) {
                        throw IllegalStateException("Backup source length changed during export")
                    }
                    output.flush()
                    output.fd.sync()
                }
            }
            verifySourceUnchanged(source, expectedLength)
            if (!temporary.renameTo(destination)) {
                throw IllegalStateException("Could not finalize backup in Downloads")
            }
            return destination.absolutePath
        } finally {
            if (temporary.exists() && !temporary.delete()) {
                temporary.deleteOnExit()
            }
        }
    }

    private fun copyBounded(input: InputStream, output: OutputStream): Long {
        val buffer = ByteArray(COPY_BUFFER_BYTES)
        var total = 0L
        try {
            while (true) {
                val read = input.read(buffer)
                if (read < 0) break
                if (read == 0) continue
                total = Math.addExact(total, read.toLong())
                if (total > MAX_BACKUP_BYTES) {
                    throw IllegalArgumentException("Backup grew beyond the 64 MiB safety limit")
                }
                output.write(buffer, 0, read)
            }
            if (total == 0L) throw IllegalArgumentException("Backup file is empty")
            return total
        } finally {
            buffer.fill(0)
        }
    }

    private fun verifySourceUnchanged(source: File, expectedLength: Long) {
        if (!source.isFile || source.length() != expectedLength) {
            throw IllegalStateException("Backup source changed while it was being exported")
        }
    }
}

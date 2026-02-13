package eu.kanade.tachiyomi.extension.en.kagane

import android.util.Base64
import java.security.MessageDigest

fun ByteArray.toBase64(): String = Base64.encodeToString(this, Base64.NO_WRAP or Base64.NO_PADDING)

fun String.sha256(): ByteArray = MessageDigest.getInstance("SHA-256").digest(toByteArray(Charsets.UTF_8))

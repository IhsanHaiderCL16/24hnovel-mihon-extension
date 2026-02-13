package eu.kanade.tachiyomi.extension.en.kagane

import okhttp3.Interceptor
import okhttp3.Protocol
import okhttp3.Response
import okhttp3.ResponseBody.Companion.toResponseBody
import java.io.IOException
import java.math.BigInteger
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

open class ImageInterceptor : Interceptor {
    override fun intercept(chain: Interceptor.Chain): Response {
        val url = chain.request().url
        return if (url.queryParameterNames.contains("token")) {
            val seriesId = url.pathSegments[3]
            val chapterId = url.pathSegments[5]
            val index = url.queryParameter("index")!!.toInt()

            val imageResp = chain.proceed(chain.request())
            val imageBytes = imageResp.body.bytes()

            val decrypted = decryptImage(imageBytes, seriesId, chapterId)
                ?: throw IOException("Unable to decrypt data")
            val unscrambled = processData(decrypted, index, seriesId, chapterId)
                ?: throw IOException("Unable to unscramble data")

            Response.Builder().body(unscrambled.toResponseBody())
                .request(chain.request())
                .protocol(Protocol.HTTP_1_0)
                .code(200)
                .message("")
                .build()
        } else chain.proceed(chain.request())
    }

    data class WordArray(val words: IntArray, val sigBytes: Int)

    private fun wordArrayToBytes(e: WordArray): ByteArray {
        val result = ByteArray(e.sigBytes)
        for (i in 0 until e.sigBytes) {
            val word = e.words[i ushr 2]
            val shift = 24 - (i % 4) * 8
            result[i] = ((word ushr shift) and 0xFF).toByte()
        }
        return result
    }

    // GCM auth tag length is 128-bit (standard). IV is expected to be 12 bytes.
    private fun aesGcmDecrypt(keyWordArray: WordArray, ivWordArray: WordArray, cipherWordArray: WordArray): ByteArray? =
        try {
            val keyBytes = wordArrayToBytes(keyWordArray)
            val iv = wordArrayToBytes(ivWordArray)
            val cipherBytes = wordArrayToBytes(cipherWordArray)

            val secretKey: SecretKey = SecretKeySpec(keyBytes, "AES")
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            val spec = GCMParameterSpec(128, iv)

            cipher.init(Cipher.DECRYPT_MODE, secretKey, spec)
            cipher.doFinal(cipherBytes)
        } catch (_: Exception) {
            null
        }

    private fun toWordArray(bytes: ByteArray): WordArray {
        val words = IntArray((bytes.size + 3) / 4)
        for (i in bytes.indices) {
            val wordIndex = i / 4
            val shift = 24 - (i % 4) * 8
            words[wordIndex] = words[wordIndex] or ((bytes[i].toInt() and 0xFF) shl shift)
        }
        return WordArray(words, bytes.size)
    }

    // Payload layout: [0..127] = header (128 bytes), [128..139] = IV (12 bytes), [140..] = ciphertext
    private fun decryptImage(payload: ByteArray, keyPart1: String, keyPart2: String): ByteArray? {
        if (payload.size < PAYLOAD_MIN_SIZE) return null
        val iv = payload.sliceArray(HEADER_SIZE until IV_END)
        val ciphertext = payload.sliceArray(IV_END until payload.size)
        val keyHash = "$keyPart1:$keyPart2".sha256()
        return aesGcmDecrypt(toWordArray(keyHash), toWordArray(iv), toWordArray(ciphertext))
    }

    private fun processData(input: ByteArray, index: Int, seriesId: String, chapterId: String): ByteArray? {
        fun isValidImage(data: ByteArray): Boolean {
            return when {
                data.size >= 2 && data[0] == 0xFF.toByte() && data[1] == 0xD8.toByte() -> true
                data.size >= 6 && (data.copyOfRange(0, 6).contentEquals("GIF87a".encodeToByteArray()) ||
                        data.copyOfRange(0, 6).contentEquals("GIF89a".encodeToByteArray())) -> true
                data.size >= 8 && data.copyOfRange(0, 8).contentEquals(byteArrayOf(
                    0x89.toByte(), 'P'.code.toByte(), 'N'.code.toByte(), 'G'.code.toByte(),
                    0x0D, 0x0A, 0x1A, 0x0A)) -> true
                else -> false
            }
        }

        return try {
            var processed: ByteArray = input
            if (!isValidImage(processed)) {
                // Page filenames are 1-based (e.g. 0001.jpg for page index 0)
                val seed = generateSeed(seriesId, chapterId, "%04d.jpg".format(index + 1))
                val scrambler = Scrambler(seed, 10)
                val scrambleMapping = scrambler.getScrambleMapping()
                processed = unscramble(processed, scrambleMapping, true)
                if (!isValidImage(processed)) return null
            }
            processed
        } catch (_: Exception) {
            null
        }
    }

    // Uses first SEED_BYTES bytes of SHA-256 hash to build a 64-bit unsigned seed
    private fun generateSeed(t: String, n: String, e: String): BigInteger {
        val sha256 = "$t:$n:$e".sha256()
        var a = BigInteger.ZERO
        for (i in 0 until SEED_BYTES) a = a.shiftLeft(8).or(BigInteger.valueOf((sha256[i].toInt() and 0xFF).toLong()))
        return a
    }

    private fun unscramble(data: ByteArray, mapping: List<Pair<Int, Int>>, n: Boolean): ByteArray {
        val s = mapping.size
        val a = data.size
        val l = a / s
        val o = a % s

        // When n=true  remainder is a prefix of data; chunks follow it.
        // When n=false remainder is a suffix of data; chunks precede it.
        val (r, i) = if (n) {
            if (o > 0) Pair(data.copyOfRange(0, o), data.copyOfRange(o, a)) else Pair(ByteArray(0), data)
        } else {
            if (o > 0) Pair(data.copyOfRange(a - o, a), data.copyOfRange(0, a - o)) else Pair(ByteArray(0), data)
        }

        val chunks = (0 until s).map { idx ->
            val start = idx * l
            val end = (idx + 1) * l
            i.copyOfRange(start, end)
        }.toMutableList()

        val u = Array(s) { ByteArray(0) }
        if (n) {
            for ((e, m) in mapping) if (e < s && m < s) u[e] = chunks[m]
        } else {
            for ((e, m) in mapping) if (e < s && m < s) u[m] = chunks[e]
        }

        val h = u.fold(ByteArray(0)) { acc, chunk -> acc + chunk }
        // Remainder always stays on the side it was taken from:
        // n=true  → remainder was a prefix → restore as suffix after reassembled chunks
        // n=false → remainder was a suffix → restore as suffix after reassembled chunks
        return h + r
    }

    companion object {
        private const val HEADER_SIZE = 128
        private const val IV_SIZE = 12
        private const val IV_END = HEADER_SIZE + IV_SIZE       // 140
        private const val PAYLOAD_MIN_SIZE = IV_END            // must have at least header + IV
        private const val SEED_BYTES = 8                       // first 8 bytes of SHA-256 → 64-bit seed
    }
}

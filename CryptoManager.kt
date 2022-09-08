package com.tasks.decryption_encryption

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.annotation.RequiresApi
import java.io.InputStream
import java.io.OutputStream
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.IvParameterSpec

@RequiresApi(Build.VERSION_CODES.M)
class CryptoManager {


    private val keyStore: KeyStore = KeyStore.getInstance("AndroidKeyStore")
    private val encryptCipher: Cipher = Cipher.getInstance(TRANSFORMATION)


    init {
        keyStore.load(null)

        encryptCipher.init(Cipher.ENCRYPT_MODE, getExistingKey())
    }

    companion object {
        const val ALGORITHM = KeyProperties.KEY_ALGORITHM_AES
        const val BLOCK_MODE = KeyProperties.BLOCK_MODE_CBC
        const val PADDING = KeyProperties.ENCRYPTION_PADDING_PKCS7
        const val TRANSFORMATION = "$ALGORITHM/$BLOCK_MODE/$PADDING"

    }


    private fun getExistingKey(): SecretKey {
        val existingKey = keyStore.getEntry("secret", null) as? KeyStore.SecretKeyEntry
        return existingKey?.secretKey ?: createKey()
    }

    private fun createKey(): SecretKey {
        val instance = KeyGenerator.getInstance(ALGORITHM)
        instance.init(
            KeyGenParameterSpec.Builder(
                "secret",
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            ).setBlockModes(BLOCK_MODE)
                .setEncryptionPaddings(PADDING)
                .setUserAuthenticationRequired(true)
                .setRandomizedEncryptionRequired(true).build()
        )
        return instance.generateKey()
    }

    private fun getDecryptedForIv(byteArray: ByteArray): Cipher {
        val instance = Cipher.getInstance(TRANSFORMATION)
        instance.init(Cipher.DECRYPT_MODE, getExistingKey(), IvParameterSpec(byteArray))
        return instance
    }


      fun encrypt(byteArray: ByteArray, outputStream: OutputStream): ByteArray {
        val encryptedByte = encryptCipher.doFinal(byteArray)
        outputStream.use {
            it.write(encryptCipher.iv.size)
            it.write(encryptCipher.iv)
            it.write(encryptedByte.size)
            it.write(encryptedByte)
        }
        return encryptedByte;
    }

      fun decrypt(inputStream: InputStream): ByteArray {
        return inputStream.use {
            val ivSize = it.read()
            val iv = ByteArray(ivSize)
            it.read(iv)
            val encryptedBytesSize = it.read()
            val encryptedBytesArray = ByteArray(encryptedBytesSize)
            it.read(encryptedBytesArray)
            getDecryptedForIv(iv).doFinal(encryptedBytesArray)
        }
    }


}
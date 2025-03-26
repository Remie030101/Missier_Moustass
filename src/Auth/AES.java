package Auth;


import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class AES {

    private static final String ALGORITHM = "AES";
    private static final int KEY_SIZE = 256;

    // Custom exception for AES operations
    public static class AESException extends Exception {
        public AESException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    // Generate a secret key for AES
    public static SecretKey generateSecretKey() throws AESException {
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance(ALGORITHM);
            keyGen.init(KEY_SIZE);
            return keyGen.generateKey();
        } catch (Exception e) {
            throw new AESException("Error generating secret key", e);
        }
    }

    // Encrypt data using AES
    public static byte[] encrypt(byte[] data, SecretKey key) throws AESException {
        try {
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, key);
            return cipher.doFinal(data);
        } catch (Exception e) {
            throw new AESException("Encryption failed", e);
        }
    }

    // Decrypt data using AES
    public static byte[] decrypt(byte[] encryptedData, SecretKey key) throws AESException {
        try {
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, key);
            return cipher.doFinal(encryptedData);
        } catch (Exception e) {
            throw new AESException("Decryption failed", e);
        }
    }

    // Convert SecretKey to a Base64 string (to store or transfer the key)
    public static String encodeKeyToBase64(SecretKey key) {
        return Base64.getEncoder().encodeToString(key.getEncoded());
    }

    // Convert Base64 string to SecretKey
    public static SecretKey decodeKeyFromBase64(String keyBase64) throws AESException {
        try {
            byte[] decodedKey = Base64.getDecoder().decode(keyBase64);
            return new SecretKeySpec(decodedKey, 0, decodedKey.length, ALGORITHM);
        } catch (Exception e) {
            throw new AESException("Failed to decode Base64 key", e);
        }
    }
}


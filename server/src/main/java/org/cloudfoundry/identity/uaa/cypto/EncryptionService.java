package org.cloudfoundry.identity.uaa.cypto;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.Arrays;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

public class EncryptionService {
    private Logger logger = LoggerFactory.getLogger(EncryptionService.class);
    private String passphrase;

    private final int GCM_AUTHENTICATION_TAG_SIZE_BITS = 128;
    private final int GCM_IV_NONCE_SIZE_BYTES = 12;
    private final int PBKDF2_ITERATIONS = 65536;
    private final int PBKDF2_SALT_SIZE_BYTES = 32;
    private final int AES_KEY_LENGTH_BITS = 256;
    private final String CIPHER = "AES";
    private final String CIPHERSCHEME = "AES/GCM/NoPadding";
    private SecureRandom random = new SecureRandom();


    public EncryptionService(String passphrase) {
        this.passphrase = passphrase;
    }

    public byte[] encrypt(String plaintext) throws EncryptionServiceException {
        try {
            byte[] newSalt = generateRandomArray(PBKDF2_SALT_SIZE_BYTES);

            SecretKey key = new SecretKeySpec(generateKey(newSalt), CIPHER);

            Cipher myCipher = Cipher.getInstance(CIPHERSCHEME);
            byte[] newNonce = generateRandomArray(GCM_IV_NONCE_SIZE_BYTES);

            GCMParameterSpec spec = new GCMParameterSpec(GCM_AUTHENTICATION_TAG_SIZE_BITS, newNonce);
            myCipher.init(Cipher.ENCRYPT_MODE, key, spec);

            byte[] bytes = plaintext.getBytes();

            return Arrays.concatenate(newNonce, newSalt, myCipher.doFinal(bytes));
        } catch (Exception e) {
            logger.error("Encryption failed", e);
            throw new EncryptionServiceException(e);
        }
    }

    public byte[] decrypt(byte[] encrypt) throws EncryptionServiceException {
        try {
            byte[] myNonce = new byte[GCM_IV_NONCE_SIZE_BYTES];
            byte[] mySalt = new byte[PBKDF2_SALT_SIZE_BYTES];

            ByteArrayInputStream fileInputStream = new ByteArrayInputStream(encrypt);
            int count = fileInputStream.read(myNonce);
            if (count != GCM_IV_NONCE_SIZE_BYTES) {
                throw new IllegalArgumentException();
            }
            count = fileInputStream.read(mySalt);
            if (count != PBKDF2_SALT_SIZE_BYTES) {
                throw new IllegalArgumentException();
            }

            SecretKey key = new SecretKeySpec(generateKey(mySalt), CIPHER);

            Cipher myCipher = Cipher.getInstance(CIPHERSCHEME);
            GCMParameterSpec spec = new GCMParameterSpec(GCM_AUTHENTICATION_TAG_SIZE_BITS, myNonce);

            myCipher.init(Cipher.DECRYPT_MODE, key, spec);
            return myCipher.doFinal(Arrays.copyOfRange(encrypt, GCM_IV_NONCE_SIZE_BYTES + PBKDF2_SALT_SIZE_BYTES, encrypt.length));
        } catch (Exception e) {
            logger.error("Decryption failed", e);
            throw new EncryptionServiceException(e);
        }
    }

    private byte[] generateRandomArray(int sizeInBytes) {
        final byte[] randomArray = new byte[sizeInBytes];
        random.nextBytes(randomArray);
        return randomArray;
    }

    private byte[] generateKey(byte[] salt) {
        PKCS5S2ParametersGenerator gen = new PKCS5S2ParametersGenerator(new SHA256Digest());

        gen.init(this.passphrase.getBytes(StandardCharsets.UTF_8), salt, PBKDF2_ITERATIONS);
        return ((KeyParameter) gen.generateDerivedParameters(AES_KEY_LENGTH_BITS)).getKey();
    }
}

package org.cloudfoundry.identity.uaa.cypto;

import org.bouncycastle.crypto.PasswordBasedDeriver;
import org.bouncycastle.crypto.PasswordConverter;
import org.bouncycastle.crypto.fips.FipsPBKD;
import org.bouncycastle.crypto.fips.FipsSHS;
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.bouncycastle.util.Arrays;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.security.SecureRandom;
import java.util.Optional;

public class EncryptionService {
    private Logger logger = LoggerFactory.getLogger(EncryptionService.class);
    private String passphrase;

    private static final int GCM_AUTHENTICATION_TAG_SIZE_BITS = 128;
    private static final int GCM_IV_NONCE_SIZE_BYTES = 12;
    private static final int PBKDF2_ITERATIONS = 65536;
    private static final int PBKDF2_SALT_SIZE_BYTES = 32;
    private static final int AES_KEY_LENGTH_BITS = 256;
    private static final String CIPHER = "AES";
    private static final String CIPHERSCHEME = "AES/GCM/NoPadding";
    private SecureRandom random = new SecureRandom();


    public EncryptionService(EncryptionKeyService passphrase) {
        this.passphrase = Optional.ofNullable(passphrase.getActiveKey()).map(EncryptionKeyService.EncryptionKey::getPassphrase).orElse(null);
    }

    protected EncryptionService(String passphrase) {
        this.passphrase = passphrase;
    }

    public byte[] encrypt(String plaintext) throws EncryptionServiceException {
        try {
            byte[] newSalt = generateRandomArray(PBKDF2_SALT_SIZE_BYTES);

            SecretKey key = new SecretKeySpec(generateKey(newSalt), CIPHER);

            Cipher myCipher = Cipher.getInstance(CIPHERSCHEME, BouncyCastleFipsProvider.PROVIDER_NAME);
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
            fileInputStream.read(myNonce);
            fileInputStream.read(mySalt);

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
        PasswordBasedDeriver<FipsPBKD.Parameters> gen = new FipsPBKD.DeriverFactory().createDeriver(
                FipsPBKD.PBKDF2.using(FipsSHS.Algorithm.SHA256_HMAC,
                        PasswordConverter.UTF8.convert(this.passphrase.toCharArray()))
                        .withIterationCount(PBKDF2_ITERATIONS)
                        .withSalt(salt)
        );
        return gen.deriveKey(PasswordBasedDeriver.KeyType.CIPHER, (AES_KEY_LENGTH_BITS + 7) / 8);
    }
}

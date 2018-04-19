package org.cloudfoundry.identity.uaa.cypto;

import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import java.security.Security;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.not;

public class EncryptionServiceTest {
    private EncryptionService service;
    @BeforeClass
    public static void key() {
        Security.setProperty("crypto.policy", "unlimited");
    }

    @Before
    public void setup() {
        service = new EncryptionService("some-password");
    }

    @Test
    public void encrypt_shouldEncrypt() throws EncryptionServiceException {
        byte[] ciphertext = service.encrypt("bob");
        assertThat(ciphertext, is(notNullValue()));
        byte[] decrypt = service.decrypt(ciphertext);
        assertThat(new String(decrypt), is("bob"));
    }

    @Test
    public void encrypt_shouldReturnDifferentCiphertextEachTime() throws EncryptionServiceException {
        byte[] ciphertext1 = service.encrypt("bob");
        byte[] ciphertext2 = service.encrypt("bob");
        assertThat(ciphertext1, not(ciphertext2));
    }

    @Test(expected = EncryptionServiceException.class)
    public void decrypt_shouldNotDecryptWithInvalidPassphrase() throws EncryptionServiceException {
        byte[] ciphertext = service.encrypt("bob");
        assertThat(ciphertext, is(notNullValue()));
        new EncryptionService("invalid-password").decrypt(ciphertext);
    }
}
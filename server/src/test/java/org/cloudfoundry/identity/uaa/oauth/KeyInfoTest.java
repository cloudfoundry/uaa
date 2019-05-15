package org.cloudfoundry.identity.uaa.oauth;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.*;

public class KeyInfoTest {
    @Rule
    public ExpectedException expectedException = ExpectedException.none();

    private static final String sampleRsaPrivateKey = "-----BEGIN RSA PRIVATE KEY-----\n" +
      "MIICXgIBAAKBgQDfTLadf6QgJeS2XXImEHMsa+1O7MmIt44xaL77N2K+J/JGpfV3\n" +
      "AnkyB06wFZ02sBLB7hko42LIsVEOyTuUBird/3vlyHFKytG7UEt60Fl88SbAEfsU\n" +
      "JN1i1aSUlunPS/NCz+BKwwKFP9Ss3rNImE9Uc2LMvGy153LHFVW2zrjhTwIDAQAB\n" +
      "AoGBAJDh21LRcJITRBQ3CUs9PR1DYZPl+tUkE7RnPBMPWpf6ny3LnDp9dllJeHqz\n" +
      "a3ACSgleDSEEeCGzOt6XHnrqjYCKa42Z+Opnjx/OOpjyX1NAaswRtnb039jwv4gb\n" +
      "RlwT49Y17UAQpISOo7JFadCBoMG0ix8xr4ScY+zCSoG5v0BhAkEA8llNsiWBJF5r\n" +
      "LWQ6uimfdU2y1IPlkcGAvjekYDkdkHiRie725Dn4qRiXyABeaqNm2bpnD620Okwr\n" +
      "sf7LY+BMdwJBAOvgt/ZGwJrMOe/cHhbujtjBK/1CumJ4n2r5V1zPBFfLNXiKnpJ6\n" +
      "J/sRwmjgg4u3Anu1ENF3YsxYabflBnvOP+kCQCQ8VBCp6OhOMcpErT8+j/gTGQUL\n" +
      "f5zOiPhoC2zTvWbnkCNGlqXDQTnPUop1+6gILI2rgFNozoTU9MeVaEXTuLsCQQDC\n" +
      "AGuNpReYucwVGYet+LuITyjs/krp3qfPhhByhtndk4cBA5H0i4ACodKyC6Zl7Tmf\n" +
      "oYaZoYWi6DzbQQUaIsKxAkEA2rXQjQFsfnSm+w/9067ChWg46p4lq5Na2NpcpFgH\n" +
      "waZKhM1W0oB8MX78M+0fG3xGUtywTx0D4N7pr1Tk2GTgNw==\n" +
      "-----END RSA PRIVATE KEY-----";


    @Test
    public void HmacKeyShouldSetFieldsCorrectly() {
        HmacKeyInfo hmacKeyInfo = new HmacKeyInfo("key-id", "secret", "https://localhost");

        assertThat(hmacKeyInfo.type(), is("MAC"));
    }

    @Test
    public void HmacKeyShouldSetKeyUrlWithASecureProtocol() {
        HmacKeyInfo hmacKeyInfo = new HmacKeyInfo("key-id", "secret", "http://localhost/path2");

        assertThat(hmacKeyInfo.keyURL(), is("https://localhost/path2/token_keys"));
    }

    @Test
    public void RsaKeyShouldSetFieldsCorrectly() {
        RsaKeyInfo hmacKeyInfo = new RsaKeyInfo("key-id", sampleRsaPrivateKey, "https://localhost");

        assertThat(hmacKeyInfo.type(), is("RSA"));
    }

    @Test
    public void RsaKeyShouldSetKeyUrlWithASecureProtocol() {
        RsaKeyInfo hmacKeyInfo = new RsaKeyInfo("key-id", sampleRsaPrivateKey, "http://localhost/path");

        assertThat(hmacKeyInfo.keyURL(), is("https://localhost/path/token_keys"));
    }

    @Test
    public void creatingHmacKeyWithInvalidUrlShouldFail() {
        expectedException.expect(IllegalArgumentException.class);
        expectedException.expectMessage("Invalid Key URL");

        new HmacKeyInfo("id", "secret", "foo bar");
    }


    @Test
    public void creatingRsaKeyWithInvalidUrlShouldFail() {
        expectedException.expect(IllegalArgumentException.class);
        expectedException.expectMessage("Invalid Key URL");

        new RsaKeyInfo("id", "secret", "foo bar");
    }
}
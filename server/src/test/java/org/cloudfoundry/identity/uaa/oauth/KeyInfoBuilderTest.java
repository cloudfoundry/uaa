package org.cloudfoundry.identity.uaa.oauth;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertEquals;

public class KeyInfoBuilderTest {
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

    private static final String sampleEcKeyPair = "-----BEGIN PRIVATE KEY-----\n"
        + "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgevZzL1gdAFr88hb2\n"
        + "OF/2NxApJCzGCEDdfSp6VQO30hyhRANCAAQRWz+jn65BtOMvdyHKcvjBeBSDZH2r\n"
        + "1RTwjmYSi9R/zpBnuQ4EiMnCqfMPWiZqB4QdbAd0E7oH50VpuZ1P087G\n"
        + "-----END PRIVATE KEY-----\n"
        + "-----BEGIN PUBLIC KEY-----\n"
        + "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEEVs/o5+uQbTjL3chynL4wXgUg2R9\n"
        + "q9UU8I5mEovUf86QZ7kOBIjJwqnzD1omageEHWwHdBO6B+dFabmdT9POxg==\n"
        + "-----END PUBLIC KEY-----";

    @Rule
    public ExpectedException expectedException = ExpectedException.none();

    @Test
    public void whenProvidingSecret_ShouldBuildHmacKey() {
        KeyInfo keyInfo = KeyInfoBuilder.build("key-id", "secret", "https://localhost");

        assertThat(keyInfo.type(), is("MAC"));
    }

    @Test
    public void whenProvidingSecret_ShouldBuildRsaKey() {
        KeyInfo keyInfo = KeyInfoBuilder.build("key-id", sampleRsaPrivateKey, "https://localhost");

        assertThat(keyInfo.type(), is("RSA"));
    }

    @Test
    public void whenProvidingNoSigningKey_shouldError() {
        expectedException.expect(IllegalArgumentException.class);

        KeyInfoBuilder.build("key-id", null, "https://localhost");
    }

    @Test
    public void whenProvidingECKey_ShouldBuildJwkMap() {
        KeyInfo keyInfo = KeyInfoBuilder.build("key-id", sampleEcKeyPair, "https://localhost");
        assertThat(keyInfo.type(), is("EC"));
        assertThat(keyInfo.algorithm(), is("ES256"));
        assertEquals(8, keyInfo.getJwkMap().size());
    }
}

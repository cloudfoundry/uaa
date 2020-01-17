package org.cloudfoundry.identity.uaa.oauth.token;

import org.cloudfoundry.identity.uaa.impl.config.LegacyTokenKey;
import org.cloudfoundry.identity.uaa.oauth.KeyInfo;
import org.cloudfoundry.identity.uaa.oauth.KeyInfoService;
import org.cloudfoundry.identity.uaa.extensions.PollutionPreventionExtension;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneConfiguration;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneProvisioning;
import org.cloudfoundry.identity.uaa.zone.TokenPolicy;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;

import java.util.Collections;
import java.util.Map;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith(PollutionPreventionExtension.class)
class KeyInfoServiceTests {
    private static final String SIGNING_KEY = "-----BEGIN RSA PRIVATE KEY-----\n" +
      "MIICXAIBAAKBgQDErZsZY70QAa7WdDD6eOv3RLBA4I5J0zZOiXMzoFB5yh64q0sm\n" +
      "ESNtV4payOYE5TnHxWjMo0y7gDsGjI1omAG6wgfyp63I9WcLX7FDLyee43fG5+b9\n" +
      "roofosL+OzJSXESSulsT9Y1XxSFFM5RMu4Ie9uM4/izKLCsAKiggMhnAmQIDAQAB\n" +
      "AoGAAs2OllALk7zSZxAE2qz6f+2krWgF3xt5fKkM0UGJpBKzWWJnkcVQwfArcpvG\n" +
      "W2+A4U347mGtaEatkKxUH5d6/s37jfRI7++HFXcLf6QJPmuE3+FtB2mX0lVJoaJb\n" +
      "RLh+tOtt4ZJRAt/u6RjUCVNpDnJB6NZ032bpL3DijfNkRuECQQDkJR+JJPUpQGoI\n" +
      "voPqcLl0i1tLX93XE7nu1YuwdQ5SmRaS0IJMozoBLBfFNmCWlSHaQpBORc38+eGC\n" +
      "J9xsOrBNAkEA3LD1JoNI+wPSo/o71TED7BoVdwCXLKPqm0TnTr2EybCUPLNoff8r\n" +
      "Ngm51jXc8mNvUkBtYiPfMKzpdqqFBWXXfQJAQ7D0E2gAybWQAHouf7/kdrzmYI3Y\n" +
      "L3lt4HxBzyBcGIvNk9AD6SNBEZn4j44byHIFMlIvqNmzTY0CqPCUyRP8vQJBALXm\n" +
      "ANmygferKfXP7XsFwGbdBO4mBXRc0qURwNkMqiMXMMdrVGftZq9Oiua9VJRQUtPn\n" +
      "mIC4cmCLVI5jc+qEC30CQE+eOXomzxNNPxVnIp5k5f+savOWBBu83J2IoT2znnGb\n" +
      "wTKZHjWybPHsW2q8Z6Moz5dvE+XMd11c5NtIG2/L97I=\n" +
      "-----END RSA PRIVATE KEY-----";
    private RandomValueStringGenerator generator = new RandomValueStringGenerator();

    private KeyInfoService keyInfoService;

    @BeforeAll
    static void setupLegacyKey() {
        LegacyTokenKey.setLegacySigningKey("testLegacyKey", "https://localhost/uaa");
    }

    @BeforeEach
    void setup() {
        keyInfoService = new KeyInfoService("https://localhost/uaa");
    }

    @Test
    void testSignedProviderSymmetricKeys() {
        String keyId = generator.generate();
        configureDefaultZoneKeys(Collections.singletonMap(keyId, "testkey"));

        KeyInfo key = keyInfoService.getKey(keyId);
        assertNotNull(key.getSigner());
        assertNotNull(key.getVerifier());

        byte[] signedValue = key.getSigner().sign("joel".getBytes());
        key.getVerifier().verify("joel".getBytes(), signedValue);
    }

    @Test
    void testSignedProviderAsymmetricKeys() {
        String signingKey = "-----BEGIN RSA PRIVATE KEY-----\n" +
                "MIICXAIBAAKBgQDErZsZY70QAa7WdDD6eOv3RLBA4I5J0zZOiXMzoFB5yh64q0sm\n" +
                "ESNtV4payOYE5TnHxWjMo0y7gDsGjI1omAG6wgfyp63I9WcLX7FDLyee43fG5+b9\n" +
                "roofosL+OzJSXESSulsT9Y1XxSFFM5RMu4Ie9uM4/izKLCsAKiggMhnAmQIDAQAB\n" +
                "AoGAAs2OllALk7zSZxAE2qz6f+2krWgF3xt5fKkM0UGJpBKzWWJnkcVQwfArcpvG\n" +
                "W2+A4U347mGtaEatkKxUH5d6/s37jfRI7++HFXcLf6QJPmuE3+FtB2mX0lVJoaJb\n" +
                "RLh+tOtt4ZJRAt/u6RjUCVNpDnJB6NZ032bpL3DijfNkRuECQQDkJR+JJPUpQGoI\n" +
                "voPqcLl0i1tLX93XE7nu1YuwdQ5SmRaS0IJMozoBLBfFNmCWlSHaQpBORc38+eGC\n" +
                "J9xsOrBNAkEA3LD1JoNI+wPSo/o71TED7BoVdwCXLKPqm0TnTr2EybCUPLNoff8r\n" +
                "Ngm51jXc8mNvUkBtYiPfMKzpdqqFBWXXfQJAQ7D0E2gAybWQAHouf7/kdrzmYI3Y\n" +
                "L3lt4HxBzyBcGIvNk9AD6SNBEZn4j44byHIFMlIvqNmzTY0CqPCUyRP8vQJBALXm\n" +
                "ANmygferKfXP7XsFwGbdBO4mBXRc0qURwNkMqiMXMMdrVGftZq9Oiua9VJRQUtPn\n" +
                "mIC4cmCLVI5jc+qEC30CQE+eOXomzxNNPxVnIp5k5f+savOWBBu83J2IoT2znnGb\n" +
                "wTKZHjWybPHsW2q8Z6Moz5dvE+XMd11c5NtIG2/L97I=\n" +
                "-----END RSA PRIVATE KEY-----";
        String keyId = generator.generate();
        configureDefaultZoneKeys(Collections.singletonMap(keyId, signingKey));
        KeyInfo key = keyInfoService.getKey(keyId);
        assertNotNull(key.getSigner());
        assertNotNull(key.getVerifier());

        byte[] signedValue = key.getSigner().sign("joel".getBytes());
        key.getVerifier().verify("joel".getBytes(), signedValue);
    }

    @Test
    void testSignedProviderAsymmetricKeysShouldAddKeyURL() {
        String keyId = generator.generate();
        configureDefaultZoneKeys(Collections.singletonMap(keyId, SIGNING_KEY));

        KeyInfo key = keyInfoService.getKey(keyId);
        assertNotNull(key.getSigner());
        assertNotNull(key.getVerifier());

        assertThat(key.keyURL(), is("https://localhost/uaa/token_keys"));
    }

    @Test
    void testSignedProviderAsymmetricKeysShouldAddKeyURL_ForCorrectZone() {
        String keyId = generator.generate();
        IdentityZoneHolder.clear();
        IdentityZoneProvisioning provisioning = mock(IdentityZoneProvisioning.class);
        IdentityZoneHolder.setProvisioning(provisioning);

        IdentityZone zone = IdentityZone.getUaa();
        zone.setSubdomain("subdomain");

        IdentityZoneConfiguration config = new IdentityZoneConfiguration();
        TokenPolicy tokenPolicy = new TokenPolicy();
        tokenPolicy.setKeys(Collections.singletonMap(keyId, SIGNING_KEY));
        config.setTokenPolicy(tokenPolicy);
        zone.setConfig(config);
        when(provisioning.retrieve("uaa")).thenReturn(zone);

        KeyInfo key = keyInfoService.getKey(keyId);
        assertNotNull(key.getSigner());
        assertNotNull(key.getVerifier());

        assertThat(key.keyURL(), is("https://subdomain.localhost/uaa/token_keys"));
    }

    @Test
    void testActiveKeyFallsBackToLegacyKey() {
        configureDefaultZoneKeys(Collections.emptyMap());

        assertEquals(keyInfoService.getActiveKey().keyId(), LegacyTokenKey.LEGACY_TOKEN_KEY_ID);
        assertEquals(keyInfoService.getActiveKey().verifierKey(), "testLegacyKey");
    }

    private void configureDefaultZoneKeys(Map<String,String> keys) {
        IdentityZoneHolder.clear();
        IdentityZoneProvisioning provisioning = mock(IdentityZoneProvisioning.class);
        IdentityZoneHolder.setProvisioning(provisioning);
        IdentityZone zone = IdentityZone.getUaa();
        IdentityZoneConfiguration config = new IdentityZoneConfiguration();
        TokenPolicy tokenPolicy = new TokenPolicy();
        tokenPolicy.setKeys(keys);
        config.setTokenPolicy(tokenPolicy);
        zone.setConfig(config);
        when(provisioning.retrieve("uaa")).thenReturn(zone);
    }
}

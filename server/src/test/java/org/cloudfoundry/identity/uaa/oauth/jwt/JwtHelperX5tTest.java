package org.cloudfoundry.identity.uaa.oauth.jwt;

import org.cloudfoundry.identity.uaa.oauth.KeyInfo;
import org.cloudfoundry.identity.uaa.oauth.KeyInfoBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatExceptionOfType;
import static org.cloudfoundry.identity.uaa.test.ModelTestUtils.getResourceAsString;

public class JwtHelperX5tTest {
    public static final String SIGNING_KEY_1 = getResourceAsString(JwtHelperX5tTest.class, "privatekey.pem");
    public static final String CERTIFICATE_1 = getResourceAsString(JwtHelperX5tTest.class, "certificate.pem");
    public static final String EXPIRED_CERTIFICATE_1 = getResourceAsString(JwtHelperX5tTest.class, "expired_certificate.pem");
    private static final String THUMBPRINT = "RkckJulawIoaTm0iaziJBwFh7Nc";

    private KeyInfo keyInfo;

    @BeforeEach
    void setUp() {
        keyInfo = KeyInfoBuilder.build("testKid", SIGNING_KEY_1, "http://localhost/uaa", "RS256", CERTIFICATE_1);
    }

    @Test
    void jwtHeaderShouldContainX5tInTheHeader() {
        Jwt jwt = JwtHelper.encodePlusX5t(Map.of("sub", "testJwtContent"), keyInfo, keyInfo.verifierCertificate().orElse(null));
        assertThat(jwt.getHeader().getX5t()).isEqualTo(THUMBPRINT);
    }

    @Test
    void jwtHeaderMustNotContainJkuInTheHeader() {
        Jwt jwt = JwtHelper.encodePlusX5t(Map.of("sub", "testJwtContent"), keyInfo, keyInfo.verifierCertificate().orElse(null));
        assertThat(jwt.getHeader().getX5t()).isEqualTo(THUMBPRINT);
        assertThat(jwt.getHeader().getJku()).isNull();
    }

    @Test
    void jwtKeysMustNotContainX5t() {
        Map<String, Object> tokenKey = KeyInfoBuilder.build("testKid", SIGNING_KEY_1, "http://localhost/uaa", "RS256", "test")
                .getJwkMap();
        validateThatNoX509InformationInMap(tokenKey);
    }

    @Test
    void jwtKeysShouldContainX5t() {
        Map<String, Object> keys = keyInfo.getJwkMap();
        assertThat(keys).containsEntry("x5t", THUMBPRINT);
    }

    @Test
    void jwtHeaderShouldFailWithInvalidCert() {
        KeyInfo keyInfo1 = KeyInfoBuilder.build("testKid", SIGNING_KEY_1, "http://localhost/uaa", "RS256", "X");
        assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() ->
                JwtHelper.encodePlusX5t(Map.of("key", new Object()), keyInfo1, keyInfo1.verifierCertificate().orElse(null)));
    }

    @Test
    void getX509CertThumbprintInvalidAlg() {
        assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() ->
                JwtHelper.getX509CertThumbprint("test".getBytes(), "unknown"));
    }

    @Test
    void jwtKeysShouldIgnoreExpiredCertificatesAndNotContainX5t() {
        Map<String, Object> tokenKey = KeyInfoBuilder.build("testKid", SIGNING_KEY_1, "http://localhost/uaa", "RS256",
                EXPIRED_CERTIFICATE_1).getJwkMap();
        validateThatNoX509InformationInMap(tokenKey);
    }

    @Test
    void jwtKeysShouldIgnoreNullCertificatesAndNotContainX5t() {
        Map<String, Object> tokenKey = KeyInfoBuilder.build("testKid", SIGNING_KEY_1, "http://localhost/uaa", "RS256", null).getJwkMap();
        validateThatNoX509InformationInMap(tokenKey);
    }

    private static void validateThatNoX509InformationInMap(Map<String, Object> tokenKey) {
        assertThat(tokenKey).doesNotContainKey("x5t")
                .doesNotContainKey("x5c")
                .containsKey("value")
                .containsEntry("kid", "testKid")
                .containsEntry("alg", "RS256");
    }
}

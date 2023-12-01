package org.cloudfoundry.identity.uaa.oauth.jwt;

import org.cloudfoundry.identity.uaa.oauth.KeyInfo;
import org.cloudfoundry.identity.uaa.oauth.KeyInfoBuilder;
import org.junit.Before;
import org.junit.Test;

import java.util.Map;

import static org.cloudfoundry.identity.uaa.test.ModelTestUtils.getResourceAsString;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

public class JwtHelperX5tTest {
  public static final String SIGNING_KEY_1 = getResourceAsString(JwtHelperX5tTest.class, "privatekey.pem");
  public static final String CERTIFICATE_1 = getResourceAsString(JwtHelperX5tTest.class, "certificate.pem");
  public static final String EXPIRED_CERTIFICATE_1 = getResourceAsString(JwtHelperX5tTest.class, "expired_certificate.pem");
  private static final String THUMBPRINT = "RkckJulawIoaTm0iaziJBwFh7Nc";

  private KeyInfo keyInfo;

  @Before
  public void setUp() {
    keyInfo = KeyInfoBuilder.build("testKid", SIGNING_KEY_1, "http://localhost/uaa", "RS256", CERTIFICATE_1);
  }

  @Test
  public void jwtHeaderShouldContainX5tInTheHeader() {
    Jwt jwt = JwtHelper.encodePlusX5t(Map.of("sub", "testJwtContent"), keyInfo, keyInfo.verifierCertificate().orElse(null));
    assertThat(THUMBPRINT, is(jwt.getHeader().getX5t()));
  }

  @Test
  public void jwtHeaderMustNotContainJkuInTheHeader() {
    Jwt jwt = JwtHelper.encodePlusX5t(Map.of("sub", "testJwtContent"), keyInfo, keyInfo.verifierCertificate().orElse(null));
    assertThat(jwt.getHeader().getX5t(), is(THUMBPRINT));
    assertNull(jwt.getHeader().getJku());
  }

  @Test
  public void jwtKeysMustNotContainX5t() {
    Map<String, Object> tokenKey = KeyInfoBuilder.build("testKid", SIGNING_KEY_1, "http://localhost/uaa", "RS256", "test")
        .getJwkMap();
    validateThatNoX509InformationInMap(tokenKey);
  }

  @Test
  public void jwtKeysShouldContainX5t() {
    Map<String, Object> keys = keyInfo.getJwkMap();
    assertThat(keys.get("x5t"), is(THUMBPRINT));
  }

  @Test(expected = IllegalArgumentException.class)
  public void jwtHeaderShouldFailWithInvalidCert() {
    KeyInfo keyInfo1 = KeyInfoBuilder.build("testKid", SIGNING_KEY_1, "http://localhost/uaa", "RS256", "X");
    JwtHelper.encodePlusX5t(Map.of("key", new Object()), keyInfo1, keyInfo1.verifierCertificate().orElse(null));
  }

  @Test(expected = IllegalArgumentException.class)
  public void getX509CertThumbprintInvalidAlg() {
    JwtHelper.getX509CertThumbprint("test".getBytes(), "unknown");
  }

  @Test
  public void jwtKeysShouldIgnoreExpiredCertificatesAndNotContainX5t() {
    Map<String, Object> tokenKey = KeyInfoBuilder.build("testKid", SIGNING_KEY_1, "http://localhost/uaa", "RS256",
            EXPIRED_CERTIFICATE_1).getJwkMap();
    validateThatNoX509InformationInMap(tokenKey);
  }

  @Test
  public void jwtKeysShouldIgnoreNullCertificatesAndNotContainX5t() {
    Map<String, Object> tokenKey = KeyInfoBuilder.build("testKid", SIGNING_KEY_1, "http://localhost/uaa", "RS256", null).getJwkMap();
    validateThatNoX509InformationInMap(tokenKey);
  }

  private static void validateThatNoX509InformationInMap(Map<String, Object> tokenKey) {
    assertNull(tokenKey.get("x5t"));
    assertNull(tokenKey.get("x5c"));
    assertNotNull(tokenKey.get("value"));
    assertEquals("testKid", tokenKey.get("kid"));
    assertEquals("RS256", tokenKey.get("alg"));
  }
}

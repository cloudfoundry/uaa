package org.cloudfoundry.identity.uaa.oauth.jwt;

import org.cloudfoundry.identity.uaa.oauth.KeyInfo;
import org.cloudfoundry.identity.uaa.oauth.KeyInfoBuilder;
import org.junit.Before;
import org.junit.Test;

import java.util.Map;

import static org.cloudfoundry.identity.uaa.test.ModelTestUtils.getResourceAsString;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertNull;

public class JwtHelperX5tTest {
  public static final String SIGNING_KEY_1 = getResourceAsString(JwtHelperX5tTest.class, "privatekey.pem");
  public static final String CERTIFICATE_1 = getResourceAsString(JwtHelperX5tTest.class, "certificate.pem");
  private static final String THUMBPRINT = "RkckJulawIoaTm0iaziJBwFh7Nc";

  private KeyInfo keyInfo;

  @Before
  public void setUp() {
    keyInfo = KeyInfoBuilder.build("testKid", SIGNING_KEY_1, "http://localhost/uaa", "RS256", CERTIFICATE_1);
  }

  @Test
  public void jwtHeaderShouldContainX5tInTheHeader() {
    Jwt jwt = JwtHelper.encodePlusX5t("testJwtContent", keyInfo, keyInfo.verifierCertificate().orElse(null));
    assertThat(THUMBPRINT, is(jwt.getHeader().getX5t()));
  }

  @Test
  public void jwtHeaderMustNotContainJkuInTheHeader() {
    Jwt jwt = JwtHelper.encodePlusX5t("testJwtContent", keyInfo, keyInfo.verifierCertificate().orElse(null));
    assertThat(jwt.getHeader().getX5t(), is(THUMBPRINT));
    assertNull(jwt.getHeader().getJku());
  }

  @Test
  public void jwtKeysMustNotContainX5t() {
    Map<String, Object> keys = KeyInfoBuilder.build("testKid", SIGNING_KEY_1, "http://localhost/uaa", "RS256", "test")
        .getJwkMap();
    assertNull(keys.get("x5t"));
  }

  @Test
  public void jwtKeysShouldContainX5t() {
    Map<String, Object> keys = keyInfo.getJwkMap();
    assertThat(keys.get("x5t"), is(THUMBPRINT));
  }

  @Test(expected = IllegalArgumentException.class)
  public void jwtHeaderShouldFailWithInvalidCert() {
    KeyInfo keyInfo1 = KeyInfoBuilder.build("testKid", SIGNING_KEY_1, "http://localhost/uaa", "RS256", "X");
    JwtHelper.encodePlusX5t("testJwtContent", keyInfo1, keyInfo1.verifierCertificate().orElse(null));
  }

  @Test(expected = IllegalArgumentException.class)
  public void getX509CertThumbprintInvalidAlg() {
    JwtHelper.getX509CertThumbprint("test".getBytes(), "unknown");
  }
}

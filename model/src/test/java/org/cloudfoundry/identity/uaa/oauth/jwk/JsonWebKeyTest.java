package org.cloudfoundry.identity.uaa.oauth.jwk;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.PublicKey;
import java.util.Map;

import static org.cloudfoundry.identity.uaa.test.ModelTestUtils.getResourceAsString;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

class JsonWebKeyTest {

  private JsonWebKey jsonWebKey;
  private static final String uaaLegacyJwkSet = getResourceAsString(JsonWebKeyTest.class, "JwkSet-LegacyUaa.json");

  @BeforeEach
  void setup() {
    jsonWebKey = new JsonWebKey(Map.of(
        "kty", "RSA",
        "e", "AQAB",
        "n", "zTZO3L-XiJMFeJD0x7Xeg4LvI5Ke3AwhNH2XNZl5oTPgiN75yWY7Co56vEueBBhzWZ4TKF4DYt4LcqIVTF3xbqbv8dkfQhDuRY5y_YNbZk_d-NidOSBz77wgQl9DzQ4ocBXSq4I1RPBSDXJzqu-nl36oyIYZdvFil7pzhMv-dOEpWb5ZDQngh30ZSKkde-JTFygEoZt2yuMF29PVjHPTfxqAKxFHjAPuLA9C53d98od1hwsfFXiCQSka-DiqTZbGH7xnQJ9qDs94YbT2xmSJxEHq7xlq93chCHA20U8-n10xYlDy-AlIbyJCCGTvc_4ShOHCdgxf54c4qff6zjqY2Q")
    );
  }

  @Test
  void testNullPublicKey() {
    assertNull(JsonWebKey.pemEncodePublicKey(null));
  }

  @Test
  void testPublicKey() {
    assertNotNull(jsonWebKey);
    PublicKey publicKey = JsonWebKey.getRsaPublicKey(jsonWebKey);
    assertNotNull(publicKey);
    assertEquals("RSA", publicKey.getAlgorithm());
  }

  @Test
  void testInvalidPublicKey() {
    JsonWebKey jsonWebKeyDummy = new JsonWebKey(Map.of(
        "kty", "RSA",
        "e", "AQAB",
        "n", "AQAB")
    );
    assertNotNull(jsonWebKeyDummy);
    assertThrows(IllegalStateException.class, () -> JsonWebKey.getRsaPublicKey(jsonWebKeyDummy));
  }

  @Test
  void testPublicKeyIsNull() {
    JsonWebKey jsonWebKeyDummy = new JsonWebKey(Map.of(
        "kty", "RSA",
        "e", "AQAB")
    );
    assertNull(JsonWebKey.getRsaPublicKey(jsonWebKeyDummy));
  }
}

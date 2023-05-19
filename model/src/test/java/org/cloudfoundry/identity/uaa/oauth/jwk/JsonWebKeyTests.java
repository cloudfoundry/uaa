package org.cloudfoundry.identity.uaa.oauth.jwk;

import com.fasterxml.jackson.core.type.TypeReference;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.junit.jupiter.api.Test;

import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.util.Map;

import static org.cloudfoundry.identity.uaa.test.ModelTestUtils.getResourceAsString;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThrows;

class JsonWebKeyTests {

  private static final String samplKeys = getResourceAsString(JsonWebKeyDeserializerTest.class, "JwkSet-Microsoft.json");
  JsonWebKeySet<JsonWebKey> samlKeySet = JsonUtils.readValue(samplKeys, new TypeReference<JsonWebKeySet<JsonWebKey>>() {
  });

  @Test
  void testWebKeyPublic() {
    // given
    Map<String, Object> jsonMap = Map.of("kid", "uaa-key", "kty", "RSA");
    JsonWebKey jsonWebKey = new JsonWebKey(jsonMap);
    jsonWebKey.setKid(samlKeySet.getKeys().get(0).getKid());
    jsonWebKey.setX5t(samlKeySet.getKeys().get(0).getX5t());
    // then
    assertEquals(samlKeySet.getKeys().get(0).getKid(), jsonWebKey.getKid());
    assertEquals(samlKeySet.getKeys().get(0).getX5t(), jsonWebKey.getX5t());
  }

  @Test
  void testWebKeyPublicNoTypeException() {
    // given
    Map<String, Object> jsonMap = Map.of("kid", "uaa-key");
    assertThrows(IllegalArgumentException.class, () -> new JsonWebKey(jsonMap));
  }

  @Test
  void testGetRsaPublicKeyFromConfig() throws GeneralSecurityException {
    // given
    String tokenKey = "-----BEGIN PUBLIC KEY----- MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxMi4Z4FBfQEOdNYLmzxk YJvP02TSeapZMKMQo90JQRL07ttIKcDMP6pGcirOGSQWWBBpvdo5EnVOiNzViu9J CJP2IWbHJ4sRe0S1dySYdBRVV/ZkgWOrj7Cr2yT0ZVvCCzH7NAWmlA6LUV19Mnp+ ugeGoxK+fsk8SRLS/Z9JdyxgOb3tPxdDas3MZweMZ6HqujoAAG9NASBGjFNXbhMc krEfecwm3OJzsjGFxhqXRqkTsGEHvzETMxfvSkTkldOzmErnjpwyoOPLrXcWIs1w vdXHakfVHSvyb3T4gm3ZfOOoUf6lrd2w1pF/PkA88NkjN2+W9fQmbUzNgVjEQiXo 4wIDAQAB -----END PUBLIC KEY-----";
    // when
    PublicKey key = JsonWebKey.getRsaPublicKey(tokenKey);
    // then
    assertNotNull(key);
    assertEquals("RSA", key.getAlgorithm());
  }

  @Test
  void testGetRsaPublicKeyFromConfigFails() throws GeneralSecurityException {
    // given
    String tokenKey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA";
    // when
    assertThrows(IllegalArgumentException.class, () -> JsonWebKey.getRsaPublicKey(tokenKey));
  }
}

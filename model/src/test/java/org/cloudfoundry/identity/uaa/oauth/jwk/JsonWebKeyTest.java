package org.cloudfoundry.identity.uaa.oauth.jwk;

import com.fasterxml.jackson.core.type.TypeReference;
import com.nimbusds.jose.JWSAlgorithm;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.junit.Test;

import java.util.Set;

import static org.cloudfoundry.identity.uaa.test.ModelTestUtils.getResourceAsString;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

public class JsonWebKeyTest {

  // Azure AD jwks_uri : https://login.microsoftonline.com/9bc40aaf-e150-4c30-bb3c-a8b3b677266e/discovery/v2.0/keys
  private static final String microsoftJwKSet = getResourceAsString(JsonWebKeyTest.class, "JwkSet-Microsoft.json");
  // UAA jwks_uri: https://login.uaa-acceptance.cf-app.com/token_keys
  private static final String uaaLegacyJwkSet = getResourceAsString(JsonWebKeyTest.class, "JwkSet-LegacyUaa.json");
  // Keycloak server configuration https://www.keycloak.org/docs/latest/server_admin/, e.g. jwks_uri: http://localhost:8080/realms/{realm-name}/protocol/openid-connect/certs
  private static final String keyCloakJwkSet = getResourceAsString(JsonWebKeyTest.class, "JwkSet-Keycloak.json");

  private static final String keyHMacRfc7518 = getResourceAsString(JsonWebKeyTest.class, "JwkSet-Hmac.json");

  @Test
  public void testWebKeysMicrosoft() {
    JsonWebKeySet<JsonWebKey> keys = JsonUtils.readValue(microsoftJwKSet, new TypeReference<JsonWebKeySet<JsonWebKey>>() {
    });
    assertNotNull(keys);
    assertNotNull(keys.getKeys());
    assertEquals(3, keys.getKeys().size());
    for (JsonWebKey key : keys.getKeys()) {
      assertNotNull(key);
      assertNotNull(JsonWebKey.getRsaPublicKey(key));
      assertNotNull(key.getValue());
    }
  }

  @Test
  public void testWebKeysUaa() {
    JsonWebKeySet<JsonWebKey> keys = JsonUtils.readValue(uaaLegacyJwkSet, new TypeReference<JsonWebKeySet<JsonWebKey>>() {
    });
    assertNotNull(keys);
    assertNotNull(keys.getKeys());
    assertEquals(1, keys.getKeys().size());
    for (JsonWebKey key : keys.getKeys()) {
      assertNotNull(key);
      assertNotNull(JsonWebKey.getRsaPublicKey(key));
      assertNotNull(key.getValue());
      assertEquals(JsonWebKey.KeyUse.sig.name(), key.getUse().name());
    }
  }

  @Test
  public void testWebKeysKeycloak() {
    JsonWebKeySet<JsonWebKey> keys = JsonUtils.readValue(keyCloakJwkSet, new TypeReference<JsonWebKeySet<JsonWebKey>>() {
    });
    assertNotNull(keys);
    assertNotNull(keys.getKeys());
    assertEquals(1, keys.getKeys().size());
    for (JsonWebKey key : keys.getKeys()) {
      assertNotNull(key);
      assertNotNull(JsonWebKey.getRsaPublicKey(key));
      assertNotNull(key.getValue());
    }
  }

  @Test
  public void testWebKeysKeyHMac() {
    JsonWebKeySet<JsonWebKey> keys = JsonUtils.readValue(keyHMacRfc7518, new TypeReference<JsonWebKeySet<JsonWebKey>>() {
    });
    assertNotNull(keys);
    assertNotNull(keys.getKeys());
    assertEquals(1, keys.getKeys().size());
    for (JsonWebKey key : keys.getKeys()) {
      assertNotNull(key);
      assertNull(JsonWebKey.getRsaPublicKey(key));
      assertNull(JsonWebKey.pemEncodePublicKey(null));
      assertNotNull(key.getValue());
      assertEquals(JWSAlgorithm.HS256.getName(), key.getAlgorithm());
      assertEquals(Set.of(JsonWebKey.KeyOperation.verify), key.getKeyOps());
      assertEquals("legacy-token-key", key.getKid());
    }
  }
}
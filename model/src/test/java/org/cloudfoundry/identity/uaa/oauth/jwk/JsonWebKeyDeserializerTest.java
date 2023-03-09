package org.cloudfoundry.identity.uaa.oauth.jwk;

import com.fasterxml.jackson.core.type.TypeReference;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.junit.Test;

import static org.cloudfoundry.identity.uaa.test.ModelTestUtils.getResourceAsString;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

public class JsonWebKeyDeserializerTest {

  // Azure AD jwks_uri : https://login.microsoftonline.com/9bc40aaf-e150-4c30-bb3c-a8b3b677266e/discovery/v2.0/keys
  private static final String microsoftJwKSet = getResourceAsString(JsonWebKeyDeserializerTest.class, "JwkSet-Microsoft.json");
  // UAA jwks_uri: https://login.uaa-acceptance.cf-app.com/token_keys
  private static final String uaaLegacyJwkSet = getResourceAsString(JsonWebKeyDeserializerTest.class, "JwkSet-LegacyUaa.json");
  // Keycloak server configuration https://www.keycloak.org/docs/latest/server_admin/, e.g. jwks_uri: http://localhost:8080/realms/{realm-name}/protocol/openid-connect/certs
  private static final String keyCloakJwkSet = getResourceAsString(JsonWebKeyDeserializerTest.class, "JwkSet-Keycloak.json");

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
      assertNotNull(key.getX5t());
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
      assertNull(key.getX5t());
      assertNull(key.getX5c());
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
      assertNotNull(key.getX5t());
    }
  }

  @Test
  public void testWebKeysCustom() {
    JsonWebKeySet<JsonWebKey> uaaKeys = JsonUtils.readValue(uaaLegacyJwkSet, new TypeReference<JsonWebKeySet<JsonWebKey>>() {
    });
    JsonWebKeySet<JsonWebKey> keys = new JsonWebKeySet<>(uaaKeys.getKeys());
    keys.getKeys().forEach(k -> k.setX5t("x509Thumbprint"));
    keys.getKeys().forEach(k -> k.setX5c(new String[] { "x509-Certificate" } ));
    assertEquals(1, keys.getKeys().size());
    for (JsonWebKey key : keys.getKeys()) {
      assertNotNull(key);
      assertEquals("x509Thumbprint", key.getX5t());
      assertEquals("x509-Certificate", key.getX5c()[0]);
    }
  }
}

package org.cloudfoundry.identity.uaa.oauth.jwk;

import com.fasterxml.jackson.core.type.TypeReference;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.junit.jupiter.api.Test;

import static org.cloudfoundry.identity.uaa.oauth.jwk.JsonWebKey.KeyType.EC;
import static org.cloudfoundry.identity.uaa.oauth.jwk.JsonWebKey.KeyType.oct;
import static org.cloudfoundry.identity.uaa.test.ModelTestUtils.getResourceAsString;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

class JsonWebKeyDeserializerTest {

    // Azure AD jwks_uri : https://login.microsoftonline.com/9bc40aaf-e150-4c30-bb3c-a8b3b677266e/discovery/v2.0/keys
    private static final String microsoftJwKSet = getResourceAsString(JsonWebKeyDeserializerTest.class, "JwkSet-Microsoft.json");
    // UAA jwks_uri: https://login.uaa-acceptance.cf-app.com/token_keys
    private static final String uaaLegacyJwkSet = getResourceAsString(JsonWebKeyDeserializerTest.class, "JwkSet-LegacyUaa.json");
    // Keycloak server configuration https://www.keycloak.org/docs/latest/server_admin/, e.g. jwks_uri: http://localhost:8080/realms/{realm-name}/protocol/openid-connect/certs
    private static final String keyCloakJwkSet = getResourceAsString(JsonWebKeyDeserializerTest.class, "JwkSet-Keycloak.json");
    // HMAC standard attributes
    private static final String keyOctedJwkSet = getResourceAsString(JsonWebKeyDeserializerTest.class, "JwkSet-Hmac.json");
    // elliptic cure
    private static final String keyECJwkSet = getResourceAsString(JsonWebKeyDeserializerTest.class, "JwkSet-ECProvider.json");

    @Test
    void testWebKeysMicrosoft() {
        JsonWebKeySet<JsonWebKey> keys = JsonUtils.readValue(microsoftJwKSet, new TypeReference<JsonWebKeySet<JsonWebKey>>() {
        });
        assertNotNull(keys);
        assertNotNull(keys.getKeys());
        assertEquals(3, keys.getKeys().size());
        for (JsonWebKey key : keys.getKeys()) {
            assertNotNull(key);
            assertNotNull(JsonWebKey.getRsaPublicKey(key));
            assertNotNull(key.getKid());
            assertEquals(key.getKid(), key.getX5t());
        }
    }

    @Test
    void testWebKeysUaa() {
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
    void testWebKeysKeycloak() {
        JsonWebKeySet<JsonWebKey> keys = JsonUtils.readValue(keyCloakJwkSet, new TypeReference<JsonWebKeySet<JsonWebKey>>() {
        });
        assertNotNull(keys);
        assertNotNull(keys.getKeys());
        assertEquals(1, keys.getKeys().size());
        for (JsonWebKey key : keys.getKeys()) {
            assertNotNull(key);
            assertNotNull(JsonWebKey.getRsaPublicKey(key));
            assertNotNull(key.getX5t());
            assertEquals("m-ERKoK9FRe8S9gP0eMI3OP4oljfQMOa3bukzi8ASmM", key.getKid());
            assertEquals("Zv-dxo0VbAZrjp7gBP97yyjdxC8", key.getX5t());
        }
    }

    @Test
    void testWebKeysOcted() {
        JsonWebKeySet<JsonWebKey> keys = JsonUtils.readValue(keyOctedJwkSet, new TypeReference<JsonWebKeySet<JsonWebKey>>() {
        });
        assertNotNull(keys);
        assertNotNull(keys.getKeys());
        assertEquals(1, keys.getKeys().size());
        for (JsonWebKey key : keys.getKeys()) {
            assertNotNull(key);
            assertEquals(oct, key.getKty());
            assertEquals("tokenKey", key.getValue());
            assertEquals("legacy-token-key", key.getKid());
        }
    }

    @Test
    void testWebKeysEllipticCurve() {
        JsonWebKeySet<JsonWebKey> keys = JsonUtils.readValue(keyECJwkSet, new TypeReference<JsonWebKeySet<JsonWebKey>>() {
        });
        assertNotNull(keys);
        assertNotNull(keys.getKeys());
        assertEquals(1, keys.getKeys().size());
        for (JsonWebKey key : keys.getKeys()) {
            assertNotNull(key);
            assertNull(key.getValue());
            assertEquals(EC, key.getKty());
            assertEquals("ES256", key.getAlgorithm());
            assertEquals("ec-key-1", key.getKid());
            assertEquals("gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0", key.getKeyProperties().get("x"));
            assertEquals("SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps", key.getKeyProperties().get("y"));
            assertEquals("P-256", key.getKeyProperties().get("crv"));
        }
    }
}

package org.cloudfoundry.identity.uaa.oauth.jwk;

import com.fasterxml.jackson.core.type.TypeReference;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.cloudfoundry.identity.uaa.oauth.jwk.JsonWebKey.KeyType.EC;
import static org.cloudfoundry.identity.uaa.oauth.jwk.JsonWebKey.KeyType.oct;
import static org.cloudfoundry.identity.uaa.test.ModelTestUtils.getResourceAsString;

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
    void webKeysMicrosoft() {
        JsonWebKeySet<JsonWebKey> keys = JsonUtils.readValue(microsoftJwKSet, new TypeReference<JsonWebKeySet<JsonWebKey>>() {
        });
        assertThat(keys).isNotNull();
        assertThat(keys.getKeys()).hasSize(3);
        for (JsonWebKey key : keys.getKeys()) {
            assertThat(key).isNotNull();
            assertThat(JsonWebKey.getRsaPublicKey(key)).isNotNull();
            assertThat(key.getKid()).isNotNull();
            assertThat(key.getX5t()).isEqualTo(key.getKid());
        }
    }

    @Test
    void webKeysUaa() {
        JsonWebKeySet<JsonWebKey> keys = JsonUtils.readValue(uaaLegacyJwkSet, new TypeReference<JsonWebKeySet<JsonWebKey>>() {
        });
        assertThat(keys).isNotNull();
        assertThat(keys.getKeys()).isNotNull()
                .hasSize(1);
        for (JsonWebKey key : keys.getKeys()) {
            assertThat(key).isNotNull();
            assertThat(JsonWebKey.getRsaPublicKey(key)).isNotNull();
            assertThat(key.getX5t()).isNull();
            assertThat(key.getX5c()).isNull();
        }
    }

    @Test
    void webKeysKeycloak() {
        JsonWebKeySet<JsonWebKey> keys = JsonUtils.readValue(keyCloakJwkSet, new TypeReference<JsonWebKeySet<JsonWebKey>>() {
        });
        assertThat(keys).isNotNull();
        assertThat(keys.getKeys()).isNotNull()
                .hasSize(1);
        for (JsonWebKey key : keys.getKeys()) {
            assertThat(key).isNotNull();
            assertThat(JsonWebKey.getRsaPublicKey(key)).isNotNull();
            assertThat(key.getX5t()).isNotNull();
            assertThat(key.getKid()).isEqualTo("m-ERKoK9FRe8S9gP0eMI3OP4oljfQMOa3bukzi8ASmM");
            assertThat(key.getX5t()).isEqualTo("Zv-dxo0VbAZrjp7gBP97yyjdxC8");
        }
    }

    @Test
    void webKeysOcted() {
        JsonWebKeySet<JsonWebKey> keys = JsonUtils.readValue(keyOctedJwkSet, new TypeReference<JsonWebKeySet<JsonWebKey>>() {
        });
        assertThat(keys).isNotNull();
        assertThat(keys.getKeys()).isNotNull()
                .hasSize(1);
        for (JsonWebKey key : keys.getKeys()) {
            assertThat(key).isNotNull();
            assertThat(key.getKty()).isEqualTo(oct);
            assertThat(key.getValue()).isEqualTo("tokenKey");
            assertThat(key.getKid()).isEqualTo("legacy-token-key");
        }
    }

    @Test
    void webKeysEllipticCurve() {
        JsonWebKeySet<JsonWebKey> keys = JsonUtils.readValue(keyECJwkSet, new TypeReference<JsonWebKeySet<JsonWebKey>>() {
        });
        assertThat(keys).isNotNull();
        assertThat(keys.getKeys()).hasSize(1);
        for (JsonWebKey key : keys.getKeys()) {
            assertThat(key).isNotNull();
            assertThat(key.getValue()).isNull();
            assertThat(key.getKty()).isEqualTo(EC);
            assertThat(key.getAlgorithm()).isEqualTo("ES256");
            assertThat(key.getKid()).isEqualTo("ec-key-1");
            assertThat(key.getKeyProperties()).containsEntry("x", "gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0")
                    .containsEntry("y", "SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps")
                    .containsEntry("crv", "P-256");
        }
    }
}

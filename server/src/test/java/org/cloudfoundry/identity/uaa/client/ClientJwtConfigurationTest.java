package org.cloudfoundry.identity.uaa.client;

import org.cloudfoundry.identity.uaa.oauth.jwk.JsonWebKey;
import org.cloudfoundry.identity.uaa.oauth.jwk.JsonWebKeySet;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.junit.jupiter.api.Test;

import java.text.ParseException;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class ClientJwtConfigurationTest {

    private final String nValue = "u_A1S-WoVAnHlNQ_1HJmOPBVxIdy1uSNsp5JUF5N4KtOjir9EgG9HhCFRwz48ykEukrgaK4ofyy_wRXSUJKW7Q";
    private final String jsonWebKey = "{\"kty\":\"RSA\",\"e\":\"AQAB\",\"kid\":\"key-1\",\"alg\":\"RS256\",\"n\":\"u_A1S-WoVAnHlNQ_1HJmOPBVxIdy1uSNsp5JUF5N4KtOjir9EgG9HhCFRwz48ykEukrgaK4ofyy_wRXSUJKW7Q\"}";
    private final String jsonWebKeyDifferentValue = "{\"kty\":\"RSA\",\"e\":\"AQAB\",\"kid\":\"key-1\",\"alg\":\"RS256\",\"n\":\"new\"}";
    private final String jsonWebKey2 = "{\"kty\":\"RSA\",\"e\":\"AQAB\",\"kid\":\"key-2\",\"alg\":\"RS256\",\"n\":\"u_A1S-WoVAnHlNQ_1HJmOPBVxIdy1uSNsp5JUF5N4KtOjir9EgG9HhCFRwz48ykEukrgaK4ofyy_wRXSUJKW7Q\"}";
    private final String jsonWebKeyNoId = "{\"kty\":\"RSA\",\"e\":\"AQAB\",\"kid\":\"\",\"alg\":\"RS256\",\"n\":\"u_A1S-WoVAnHlNQ_1HJmOPBVxIdy1uSNsp5JUF5N4KtOjir9EgG9HhCFRwz48ykEukrgaK4ofyy_wRXSUJKW7Q\"}";
    private final String jsonJwkSet = "{\"keys\":[{\"kty\":\"RSA\",\"e\":\"AQAB\",\"kid\":\"key-1\",\"alg\":\"RS256\",\"n\":\"u_A1S-WoVAnHlNQ_1HJmOPBVxIdy1uSNsp5JUF5N4KtOjir9EgG9HhCFRwz48ykEukrgaK4ofyy_wRXSUJKW7Q\"}]}";
    private final String jsonJwkSetEmtpy = "{\"keys\":[]}";
    private final String defaultJsonUri = "{\"jwks_uri\":\"http://localhost:8080/uaa\"} ";
    private final String defaultJsonKey = "{\"jwks\":{\"keys\":[{\"kty\":\"RSA\",\"e\":\"AQAB\",\"alg\":\"RS256\",\"n\":\"u_A1S-WoVAnHlNQ_1HJmOPBVxIdy1uSNsp5JUF5N4KtOjir9EgG9HhCFRwz48ykEukrgaK4ofyy_wRXSUJKW7Q\",\"kid\":\"key-1\"}]}}";

    @Test
    void testJwksValidity() {
        assertNotNull(ClientJwtConfiguration.parse("https://any.domain.net/openid/jwks-uri"));
        assertNotNull(ClientJwtConfiguration.parse("http://any.localhost/openid/jwks-uri"));
    }

    @Test
    void testJwksInvalid() {
        assertThrows(InvalidClientDetailsException.class, () -> ClientJwtConfiguration.parse("custom://any.domain.net/openid/jwks-uri", null));
        assertThrows(InvalidClientDetailsException.class, () -> ClientJwtConfiguration.parse("test", null));
        assertThrows(InvalidClientDetailsException.class, () -> ClientJwtConfiguration.parse("http://any.domain.net/openid/jwks-uri"));
        assertThrows(InvalidClientDetailsException.class, () -> ClientJwtConfiguration.parse("https://"));
        assertThrows(InvalidClientDetailsException.class, () -> ClientJwtConfiguration.parse("ftp://any.domain.net/openid/jwks-uri"));
    }

    @Test
    void testJwkSetValidity() {
        assertNotNull(ClientJwtConfiguration.parse(jsonWebKey));
        assertNotNull(ClientJwtConfiguration.parse(jsonJwkSet));
    }

    @Test
    void testJwkSetInvalid() {
        assertThrows(InvalidClientDetailsException.class, () -> ClientJwtConfiguration.parse(jsonJwkSetEmtpy));
        assertThrows(InvalidClientDetailsException.class, () -> ClientJwtConfiguration.parse(jsonWebKeyNoId));
        assertThrows(InvalidClientDetailsException.class, () -> ClientJwtConfiguration.parse("{\"keys\": \"x\"}"));
    }

    @Test
    void testJwkSetInvalidSize() throws ParseException {
        assertThrows(InvalidClientDetailsException.class, () -> new ClientJwtConfiguration(null, new JsonWebKeySet(Collections.emptyList())));
    }

    @Test
    void testGetCleanConfig() {
        assertNotNull(ClientJwtConfiguration.parse("https://any.domain.net/openid/jwks-uri").getCleanString());
        assertNotNull(ClientJwtConfiguration.parse(jsonWebKey).getCleanString());
    }

    @Test
    void testGetCleanConfigInvalid() {
        JsonWebKeySet<JsonWebKey> mockedKey = mock(JsonWebKeySet.class);
        List<JsonWebKey> keyList = ClientJwtConfiguration.parse(jsonJwkSet).getJwkSet().getKeys();
        when(mockedKey.getKeys()).thenReturn(keyList);
        ClientJwtConfiguration privateKey = new ClientJwtConfiguration(null, mockedKey);
        when(mockedKey.getKeySetMap()).thenThrow(new IllegalStateException("error"));
        assertThrows(InvalidClientDetailsException.class, privateKey::getCleanString);
        ClientJwtConfiguration privateKey2 = new ClientJwtConfiguration("hello", null);
        assertNull(privateKey2.getCleanString());
    }

    @Test
    void testJwtSetValidate() {
        JsonWebKeySet<JsonWebKey> mockedKey = mock(JsonWebKeySet.class);
        List<JsonWebKey> keyList = ClientJwtConfiguration.parse(jsonJwkSet).getJwkSet().getKeys();
        when(mockedKey.getKeys()).thenReturn(Arrays.asList(keyList.get(0), keyList.get(0)));
        assertThrows(InvalidClientDetailsException.class, () -> new ClientJwtConfiguration(null, mockedKey));
    }

    @Test
    void testConfigMerge() {
        ClientJwtConfiguration configuration = ClientJwtConfiguration.parse(jsonJwkSet);
        assertEquals(1, configuration.getJwkSet().getKeys().size());
        ClientJwtConfiguration addKey = ClientJwtConfiguration.parse(jsonWebKey2);
        configuration = ClientJwtConfiguration.merge(configuration, addKey, false);
        assertEquals(2, configuration.getJwkSet().getKeys().size());
        assertEquals(nValue, configuration.getJwkSet().getKeys().get(0).getKeyProperties().get("n"));
        assertEquals(nValue, configuration.getJwkSet().getKeys().get(1).getKeyProperties().get("n"));

        configuration = ClientJwtConfiguration.merge(configuration, addKey, true);
        assertEquals(2, configuration.getJwkSet().getKeys().size());

        configuration = ClientJwtConfiguration.parse(jsonJwkSet);
        assertEquals(1, configuration.getJwkSet().getKeys().size());
        assertEquals(nValue, configuration.getJwkSet().getKeys().get(0).getKeyProperties().get("n"));

        configuration = ClientJwtConfiguration.merge(ClientJwtConfiguration.parse(jsonJwkSet), ClientJwtConfiguration.parse(jsonWebKeyDifferentValue), true);
        assertEquals(1, configuration.getJwkSet().getKeys().size());
        assertEquals("new", configuration.getJwkSet().getKeys().get(0).getKeyProperties().get("n"));

        configuration = ClientJwtConfiguration.merge(ClientJwtConfiguration.parse(jsonJwkSet), ClientJwtConfiguration.parse(jsonWebKeyDifferentValue), false);
        assertEquals(1, configuration.getJwkSet().getKeys().size());
        assertEquals(nValue, configuration.getJwkSet().getKeys().get(0).getKeyProperties().get("n"));
    }

    @Test
    void testConfigMergeDifferentType() {
        ClientJwtConfiguration configuration = ClientJwtConfiguration.parse(jsonJwkSet);
        assertEquals(1, configuration.getJwkSet().getKeys().size());
        assertNull(configuration.getJwksUri());
        configuration = ClientJwtConfiguration.merge(configuration, ClientJwtConfiguration.parse("https://any/jwks-uri"), false);
        assertEquals(1, configuration.getJwkSet().getKeys().size());
        assertNull(configuration.getJwksUri());

        configuration = ClientJwtConfiguration.merge(configuration, ClientJwtConfiguration.parse("https://any/jwks-uri"), true);
        assertNull(configuration.getJwkSet());
        assertNotNull(configuration.getJwksUri());

        configuration = ClientJwtConfiguration.merge(ClientJwtConfiguration.parse("https://any/jwks-uri"), ClientJwtConfiguration.parse("https://new/jwks-uri"), false);
        assertNull(configuration.getJwkSet());
        assertEquals("https://any/jwks-uri", configuration.getJwksUri());

        configuration = ClientJwtConfiguration.merge(ClientJwtConfiguration.parse("https://any/jwks-uri"), ClientJwtConfiguration.parse("https://new/jwks-uri"), true);
        assertNull(configuration.getJwkSet());
        assertEquals("https://new/jwks-uri", configuration.getJwksUri());

        configuration = ClientJwtConfiguration.merge(ClientJwtConfiguration.parse("https://any/jwks-uri"), ClientJwtConfiguration.parse(jsonJwkSet), false);
        assertNull(configuration.getJwkSet());
        assertEquals("https://any/jwks-uri", configuration.getJwksUri());

        configuration = ClientJwtConfiguration.merge(ClientJwtConfiguration.parse("https://any/jwks-uri"), ClientJwtConfiguration.parse(jsonJwkSet), true);
        assertNull(configuration.getJwksUri());
        assertEquals(1, configuration.getJwkSet().getKeys().size());
        assertEquals(nValue, configuration.getJwkSet().getKeys().get(0).getKeyProperties().get("n"));
    }

    @Test
    void testConfigMergeNulls() {
        ClientJwtConfiguration configuration = ClientJwtConfiguration.parse(jsonJwkSet);
        ClientJwtConfiguration existingKeyConfig = ClientJwtConfiguration.merge(configuration, null, true);
        assertTrue(configuration.equals(existingKeyConfig));
        assertEquals(configuration, existingKeyConfig);

        ClientJwtConfiguration newKeyConfig = ClientJwtConfiguration.parse("https://any/jwks-uri");
        configuration = ClientJwtConfiguration.merge(null, newKeyConfig, true);
        assertTrue(configuration.equals(newKeyConfig));
        assertTrue(configuration.equals(newKeyConfig));
    }

    @Test
    void testConfigDelete() {
        ClientJwtConfiguration configuration = ClientJwtConfiguration.parse(jsonJwkSet);
        assertEquals(1, configuration.getJwkSet().getKeys().size());
        assertNull(configuration.getJwksUri());
        ClientJwtConfiguration addKey = ClientJwtConfiguration.parse(jsonWebKey2);
        configuration = ClientJwtConfiguration.merge(configuration, addKey, false);
        assertEquals(2, configuration.getJwkSet().getKeys().size());
        configuration = ClientJwtConfiguration.delete(configuration, addKey);
        assertEquals(1, configuration.getJwkSet().getKeys().size());
        configuration = ClientJwtConfiguration.delete(configuration, addKey);
        configuration = ClientJwtConfiguration.delete(configuration, addKey);
        assertEquals(1, configuration.getJwkSet().getKeys().size());
        configuration = ClientJwtConfiguration.merge(configuration, addKey, false);
        configuration = ClientJwtConfiguration.delete(configuration, addKey);
        assertEquals(1, configuration.getJwkSet().getKeys().size());
        configuration = ClientJwtConfiguration.merge(configuration, addKey, false);
        configuration = ClientJwtConfiguration.delete(configuration, new ClientJwtConfiguration("key-2", null));
        configuration = ClientJwtConfiguration.delete(configuration, new ClientJwtConfiguration("key-1", null));
        assertNull(configuration);
        configuration = ClientJwtConfiguration.delete(ClientJwtConfiguration.parse(jsonJwkSet), ClientJwtConfiguration.parse(jsonWebKey));
        assertNull(configuration);

        configuration = ClientJwtConfiguration.delete(ClientJwtConfiguration.parse("https://any/jwks-uri"), ClientJwtConfiguration.parse("https://any/jwks-uri"));
        assertNull(configuration);
        configuration = ClientJwtConfiguration.delete(ClientJwtConfiguration.parse("https://any/jwks-uri"), ClientJwtConfiguration.parse("https://other/jwks-uri"));
        assertNotNull(configuration);
    }

    @Test
    void testConfigDeleteNull() {
        assertNull(ClientJwtConfiguration.delete(null, ClientJwtConfiguration.parse("https://other/jwks-uri")));
        assertNotNull(ClientJwtConfiguration.delete(ClientJwtConfiguration.parse("https://any/jwks-uri"), null));
    }

    @Test
    void testHashCode() {
        ClientJwtConfiguration key1 = ClientJwtConfiguration.parse("http://localhost:8080/uaa");
        ClientJwtConfiguration key2 = ClientJwtConfiguration.parse("http://localhost:8080/uaa");
        assertNotEquals(key1.hashCode(), key2.hashCode());
        assertEquals(key1.hashCode(), key1.hashCode());
        assertEquals(key2.hashCode(), key2.hashCode());
    }

    @Test
    void testEquals() throws CloneNotSupportedException {
        ClientJwtConfiguration key1 = ClientJwtConfiguration.parse("http://localhost:8080/uaa");
        ClientJwtConfiguration key2 = (ClientJwtConfiguration) key1.clone();
        assertEquals(key1, key2);
    }

    @Test
    void testSerializableObjectCalls() throws CloneNotSupportedException {
        ClientJwtConfiguration key1 = JsonUtils.readValue(defaultJsonUri, ClientJwtConfiguration.class);
        ClientJwtConfiguration key2 = (ClientJwtConfiguration) key1.clone();
        assertEquals(key1, key2);

        key1 = JsonUtils.readValue(defaultJsonKey, ClientJwtConfiguration.class);
        key2 = (ClientJwtConfiguration) key1.clone();
        assertEquals(key1, key2);
    }

    @Test
    void testConfiguration() {
        ClientJwtConfiguration configUri = JsonUtils.readValue(defaultJsonUri, ClientJwtConfiguration.class);
        ClientJwtConfiguration configKey = JsonUtils.readValue(defaultJsonKey, ClientJwtConfiguration.class);
        UaaClientDetails uaaClientDetails = new UaaClientDetails();
        uaaClientDetails.setClientJwtConfig(JsonUtils.writeValueAsString(configUri));

        configUri.writeValue(uaaClientDetails);
        ClientJwtConfiguration readUriConfig = ClientJwtConfiguration.readValue(uaaClientDetails);
        assertEquals(configUri, readUriConfig);

        ClientJwtConfiguration.resetConfiguration(uaaClientDetails);
        assertNull(ClientJwtConfiguration.readValue(uaaClientDetails));
        configKey.writeValue(uaaClientDetails);
        ClientJwtConfiguration readKeyConfig = ClientJwtConfiguration.readValue(uaaClientDetails);
        assertEquals(configKey, readKeyConfig);
    }
}

package org.cloudfoundry.identity.uaa.client;

import org.cloudfoundry.identity.uaa.oauth.client.ClientConstants;
import org.cloudfoundry.identity.uaa.oauth.jwk.JsonWebKey;
import org.cloudfoundry.identity.uaa.oauth.jwk.JsonWebKeySet;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;

import java.text.ParseException;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class PrivateKeyJwtConfigurationTest {

  private final String nValue = "u_A1S-WoVAnHlNQ_1HJmOPBVxIdy1uSNsp5JUF5N4KtOjir9EgG9HhCFRwz48ykEukrgaK4ofyy_wRXSUJKW7Q";
  private final String jsonWebKey  = "{\"kty\":\"RSA\",\"e\":\"AQAB\",\"kid\":\"key-1\",\"alg\":\"RS256\",\"n\":\"u_A1S-WoVAnHlNQ_1HJmOPBVxIdy1uSNsp5JUF5N4KtOjir9EgG9HhCFRwz48ykEukrgaK4ofyy_wRXSUJKW7Q\"}";
  private final String jsonWebKeyDifferentValue  = "{\"kty\":\"RSA\",\"e\":\"AQAB\",\"kid\":\"key-1\",\"alg\":\"RS256\",\"n\":\"new\"}";
  private final String jsonWebKey2  = "{\"kty\":\"RSA\",\"e\":\"AQAB\",\"kid\":\"key-2\",\"alg\":\"RS256\",\"n\":\"u_A1S-WoVAnHlNQ_1HJmOPBVxIdy1uSNsp5JUF5N4KtOjir9EgG9HhCFRwz48ykEukrgaK4ofyy_wRXSUJKW7Q\"}";
  private final String jsonWebKeyNoId  = "{\"kty\":\"RSA\",\"e\":\"AQAB\",\"kid\":\"\",\"alg\":\"RS256\",\"n\":\"u_A1S-WoVAnHlNQ_1HJmOPBVxIdy1uSNsp5JUF5N4KtOjir9EgG9HhCFRwz48ykEukrgaK4ofyy_wRXSUJKW7Q\"}";
  private final String jsonJwkSet = "{\"keys\":[{\"kty\":\"RSA\",\"e\":\"AQAB\",\"kid\":\"key-1\",\"alg\":\"RS256\",\"n\":\"u_A1S-WoVAnHlNQ_1HJmOPBVxIdy1uSNsp5JUF5N4KtOjir9EgG9HhCFRwz48ykEukrgaK4ofyy_wRXSUJKW7Q\"}]}";
  private final String jsonJwkSetEmtpy = "{\"keys\":[]}";
  private final String defaultJsonUri = "{\"jwks_uri\":\"http://localhost:8080/uaa\"} ";
  private final String defaultJsonKey = "{\"jwks\":{\"keys\":[{\"kty\":\"RSA\",\"e\":\"AQAB\",\"alg\":\"RS256\",\"n\":\"u_A1S-WoVAnHlNQ_1HJmOPBVxIdy1uSNsp5JUF5N4KtOjir9EgG9HhCFRwz48ykEukrgaK4ofyy_wRXSUJKW7Q\",\"kid\":\"key-1\"}]}}";

  @Test
  void testJwksValidity() {
    assertNotNull(PrivateKeyJwtConfiguration.parse("https://any.domain.net/openid/jwks-uri"));
    assertNotNull(PrivateKeyJwtConfiguration.parse("http://any.localhost/openid/jwks-uri"));
  }

  @Test
  void testJwksInvalid() {
    assertThrows(InvalidClientDetailsException.class, () -> PrivateKeyJwtConfiguration.parse("custom://any.domain.net/openid/jwks-uri", null));
    assertThrows(InvalidClientDetailsException.class, () -> PrivateKeyJwtConfiguration.parse("test", null));
    assertThrows(InvalidClientDetailsException.class, () -> PrivateKeyJwtConfiguration.parse("http://any.domain.net/openid/jwks-uri"));
    assertThrows(InvalidClientDetailsException.class, () -> PrivateKeyJwtConfiguration.parse("https://"));
    assertThrows(InvalidClientDetailsException.class, () -> PrivateKeyJwtConfiguration.parse("ftp://any.domain.net/openid/jwks-uri"));
  }

  @Test
  void testJwkSetValidity() {
    assertNotNull(PrivateKeyJwtConfiguration.parse(jsonWebKey));
    assertNotNull(PrivateKeyJwtConfiguration.parse(jsonJwkSet));
  }

  @Test
  void testJwkSetInvalid() {
    assertThrows(InvalidClientDetailsException.class, () -> PrivateKeyJwtConfiguration.parse(jsonJwkSetEmtpy));
    assertThrows(InvalidClientDetailsException.class, () -> PrivateKeyJwtConfiguration.parse(jsonWebKeyNoId));
    assertThrows(InvalidClientDetailsException.class, () -> PrivateKeyJwtConfiguration.parse("{\"keys\": \"x\"}"));
  }

  @Test
  void testJwkSetInvalidSize() throws ParseException {
    assertThrows(InvalidClientDetailsException.class, () -> new PrivateKeyJwtConfiguration(null, new JsonWebKeySet(Collections.emptyList())));
  }

  @Test
  void testGetCleanConfig() {
    assertNotNull(PrivateKeyJwtConfiguration.parse("https://any.domain.net/openid/jwks-uri").getCleanString());
    assertNotNull(PrivateKeyJwtConfiguration.parse(jsonWebKey).getCleanString());
  }

  @Test
  void testGetCleanConfigInvalid() {
    JsonWebKeySet<JsonWebKey> mockedKey = mock(JsonWebKeySet.class);
    List<JsonWebKey> keyList = PrivateKeyJwtConfiguration.parse(jsonJwkSet).getPrivateKeyJwt().getKeys();
    when(mockedKey.getKeys()).thenReturn(keyList);
    PrivateKeyJwtConfiguration privateKey = new PrivateKeyJwtConfiguration(null, mockedKey);
    when(mockedKey.getKeySetMap()).thenThrow(new IllegalStateException("error"));
    assertThrows(InvalidClientDetailsException.class, () -> privateKey.getCleanString());
    PrivateKeyJwtConfiguration privateKey2 = new PrivateKeyJwtConfiguration("hello", null);
    assertNull(privateKey2.getCleanString());
  }

  @Test
  void testJwtSetValidate() {
    JsonWebKeySet<JsonWebKey> mockedKey = mock(JsonWebKeySet.class);
    List<JsonWebKey> keyList = PrivateKeyJwtConfiguration.parse(jsonJwkSet).getPrivateKeyJwt().getKeys();
    when(mockedKey.getKeys()).thenReturn(Arrays.asList(keyList.get(0), keyList.get(0)));
    assertThrows(InvalidClientDetailsException.class, () -> new PrivateKeyJwtConfiguration(null, mockedKey));
  }

  @Test
  void testConfigMerge() {
    PrivateKeyJwtConfiguration configuration = PrivateKeyJwtConfiguration.parse(jsonJwkSet);
    assertEquals(1, configuration.getPrivateKeyJwt().getKeys().size());
    PrivateKeyJwtConfiguration addKey = PrivateKeyJwtConfiguration.parse(jsonWebKey2);
    configuration = PrivateKeyJwtConfiguration.merge(configuration, addKey, false);
    assertEquals(2, configuration.getPrivateKeyJwt().getKeys().size());
    assertEquals(nValue, configuration.getPrivateKeyJwt().getKeys().get(0).getKeyProperties().get("n"));
    assertEquals(nValue, configuration.getPrivateKeyJwt().getKeys().get(1).getKeyProperties().get("n"));

    configuration = PrivateKeyJwtConfiguration.merge(configuration, addKey, true);
    assertEquals(2, configuration.getPrivateKeyJwt().getKeys().size());

    configuration = PrivateKeyJwtConfiguration.parse(jsonJwkSet);
    assertEquals(1, configuration.getPrivateKeyJwt().getKeys().size());
    assertEquals(nValue, configuration.getPrivateKeyJwt().getKeys().get(0).getKeyProperties().get("n"));

    configuration = PrivateKeyJwtConfiguration.merge(PrivateKeyJwtConfiguration.parse(jsonJwkSet), PrivateKeyJwtConfiguration.parse(jsonWebKeyDifferentValue), true);
    assertEquals(1, configuration.getPrivateKeyJwt().getKeys().size());
    assertEquals("new", configuration.getPrivateKeyJwt().getKeys().get(0).getKeyProperties().get("n"));

    configuration = PrivateKeyJwtConfiguration.merge(PrivateKeyJwtConfiguration.parse(jsonJwkSet), PrivateKeyJwtConfiguration.parse(jsonWebKeyDifferentValue), false);
    assertEquals(1, configuration.getPrivateKeyJwt().getKeys().size());
    assertEquals(nValue, configuration.getPrivateKeyJwt().getKeys().get(0).getKeyProperties().get("n"));
  }

  @Test
  void testConfigMergeDifferentType() {
    PrivateKeyJwtConfiguration configuration = PrivateKeyJwtConfiguration.parse(jsonJwkSet);
    assertEquals(1, configuration.getPrivateKeyJwt().getKeys().size());
    assertNull(configuration.getPrivateKeyJwtUrl());
    configuration = PrivateKeyJwtConfiguration.merge(configuration, PrivateKeyJwtConfiguration.parse("https://any/jwks-uri"), false);
    assertEquals(1, configuration.getPrivateKeyJwt().getKeys().size());
    assertNull(configuration.getPrivateKeyJwtUrl());

    configuration = PrivateKeyJwtConfiguration.merge(configuration, PrivateKeyJwtConfiguration.parse("https://any/jwks-uri"), true);
    assertNull(configuration.getPrivateKeyJwt());
    assertNotNull(configuration.getPrivateKeyJwtUrl());

    configuration = PrivateKeyJwtConfiguration.merge(PrivateKeyJwtConfiguration.parse("https://any/jwks-uri"), PrivateKeyJwtConfiguration.parse("https://new/jwks-uri"), false);
    assertNull(configuration.getPrivateKeyJwt());
    assertEquals("https://any/jwks-uri", configuration.getPrivateKeyJwtUrl());

    configuration = PrivateKeyJwtConfiguration.merge(PrivateKeyJwtConfiguration.parse("https://any/jwks-uri"), PrivateKeyJwtConfiguration.parse("https://new/jwks-uri"), true);
    assertNull(configuration.getPrivateKeyJwt());
    assertEquals("https://new/jwks-uri", configuration.getPrivateKeyJwtUrl());

    configuration = PrivateKeyJwtConfiguration.merge(PrivateKeyJwtConfiguration.parse("https://any/jwks-uri"), PrivateKeyJwtConfiguration.parse(jsonJwkSet), false);
    assertNull(configuration.getPrivateKeyJwt());
    assertEquals("https://any/jwks-uri", configuration.getPrivateKeyJwtUrl());

    configuration = PrivateKeyJwtConfiguration.merge(PrivateKeyJwtConfiguration.parse("https://any/jwks-uri"), PrivateKeyJwtConfiguration.parse(jsonJwkSet), true);
    assertNull(configuration.getPrivateKeyJwtUrl());
    assertEquals(1, configuration.getPrivateKeyJwt().getKeys().size());
    assertEquals(nValue, configuration.getPrivateKeyJwt().getKeys().get(0).getKeyProperties().get("n"));
  }

  @Test
  void testConfigMergeNulls() {
    PrivateKeyJwtConfiguration configuration = PrivateKeyJwtConfiguration.parse(jsonJwkSet);
    PrivateKeyJwtConfiguration existingKeyConfig = PrivateKeyJwtConfiguration.merge(configuration, null, true);
    assertTrue(configuration.equals(existingKeyConfig));
    assertEquals(configuration, existingKeyConfig);

    PrivateKeyJwtConfiguration newKeyConfig = PrivateKeyJwtConfiguration.parse("https://any/jwks-uri");
    configuration = PrivateKeyJwtConfiguration.merge(null, newKeyConfig, true);
    assertTrue(configuration.equals(newKeyConfig));
    assertTrue(configuration.equals(newKeyConfig));
  }

  @Test
  void testConfigDelete() {
    PrivateKeyJwtConfiguration configuration = PrivateKeyJwtConfiguration.parse(jsonJwkSet);
    assertEquals(1, configuration.getPrivateKeyJwt().getKeys().size());
    assertNull(configuration.getPrivateKeyJwtUrl());
    PrivateKeyJwtConfiguration addKey = PrivateKeyJwtConfiguration.parse(jsonWebKey2);
    configuration = PrivateKeyJwtConfiguration.merge(configuration, addKey, false);
    assertEquals(2, configuration.getPrivateKeyJwt().getKeys().size());
    configuration = PrivateKeyJwtConfiguration.delete(configuration, addKey);
    assertEquals(1, configuration.getPrivateKeyJwt().getKeys().size());
    configuration = PrivateKeyJwtConfiguration.delete(configuration, addKey);
    configuration = PrivateKeyJwtConfiguration.delete(configuration, addKey);
    assertEquals(1, configuration.getPrivateKeyJwt().getKeys().size());
    configuration = PrivateKeyJwtConfiguration.merge(configuration, addKey, false);
    configuration = PrivateKeyJwtConfiguration.delete(configuration, addKey);
    assertEquals(1, configuration.getPrivateKeyJwt().getKeys().size());
    configuration = PrivateKeyJwtConfiguration.merge(configuration, addKey, false);
    configuration = PrivateKeyJwtConfiguration.delete(configuration, new PrivateKeyJwtConfiguration("key-2", null));
    configuration = PrivateKeyJwtConfiguration.delete(configuration, new PrivateKeyJwtConfiguration("key-1", null));
    assertNull(configuration);
    configuration = PrivateKeyJwtConfiguration.delete(PrivateKeyJwtConfiguration.parse(jsonJwkSet), PrivateKeyJwtConfiguration.parse(jsonWebKey));
    assertNull(configuration);

    configuration = PrivateKeyJwtConfiguration.delete(PrivateKeyJwtConfiguration.parse("https://any/jwks-uri"), PrivateKeyJwtConfiguration.parse("https://any/jwks-uri"));
    assertNull(configuration);
    configuration = PrivateKeyJwtConfiguration.delete(PrivateKeyJwtConfiguration.parse("https://any/jwks-uri"), PrivateKeyJwtConfiguration.parse("https://other/jwks-uri"));
    assertNotNull(configuration);
  }
  @Test
  void testConfigDeleteNull() {
    assertNull(PrivateKeyJwtConfiguration.delete(null, PrivateKeyJwtConfiguration.parse("https://other/jwks-uri")));
    assertNotNull(PrivateKeyJwtConfiguration.delete(PrivateKeyJwtConfiguration.parse("https://any/jwks-uri"), null));
  }

  @Test
  void testHashCode() {
    PrivateKeyJwtConfiguration key1 = PrivateKeyJwtConfiguration.parse("http://localhost:8080/uaa");
    PrivateKeyJwtConfiguration key2 = PrivateKeyJwtConfiguration.parse("http://localhost:8080/uaa");
    assertNotEquals(key1.hashCode(), key2.hashCode());
    assertEquals(key1.hashCode(), key1.hashCode());
    assertEquals(key2.hashCode(), key2.hashCode());
  }

  @Test
  void testEquals() throws CloneNotSupportedException {
    PrivateKeyJwtConfiguration key1 = PrivateKeyJwtConfiguration.parse("http://localhost:8080/uaa");
    PrivateKeyJwtConfiguration key2 = (PrivateKeyJwtConfiguration) key1.clone();
    assertEquals(key1, key2);
  }

  @Test
  void testSerializableObjectCalls() throws CloneNotSupportedException {
    PrivateKeyJwtConfiguration key1 = JsonUtils.readValue(defaultJsonUri, PrivateKeyJwtConfiguration.class);
    PrivateKeyJwtConfiguration key2 = (PrivateKeyJwtConfiguration) key1.clone();
    assertEquals(key1, key2);

    key1 = JsonUtils.readValue(defaultJsonKey, PrivateKeyJwtConfiguration.class);
    key2 = (PrivateKeyJwtConfiguration) key1.clone();
    assertEquals(key1, key2);
  }

  @Test
  void testConfiguration() {
    PrivateKeyJwtConfiguration configUri = JsonUtils.readValue(defaultJsonUri, PrivateKeyJwtConfiguration.class);
    PrivateKeyJwtConfiguration configKey = JsonUtils.readValue(defaultJsonKey, PrivateKeyJwtConfiguration.class);
    BaseClientDetails baseClientDetails = new BaseClientDetails();
    HashMap<String, Object> additionalInformation = new HashMap<>();
    additionalInformation.put(ClientConstants.PRIVATE_KEY_CONFIG, configUri);
    baseClientDetails.setAdditionalInformation(additionalInformation);

    configUri.writeValue(baseClientDetails);
    PrivateKeyJwtConfiguration readUriConfig = PrivateKeyJwtConfiguration.readValue(baseClientDetails);
    assertEquals(configUri, readUriConfig);

    PrivateKeyJwtConfiguration.resetConfiguration(baseClientDetails);
    assertNull(PrivateKeyJwtConfiguration.readValue(baseClientDetails));
    configKey.writeValue(baseClientDetails);
    PrivateKeyJwtConfiguration readKeyConfig = PrivateKeyJwtConfiguration.readValue(baseClientDetails);
    assertEquals(configKey, readKeyConfig);
  }
}

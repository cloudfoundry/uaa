package org.cloudfoundry.identity.uaa.client;

import org.cloudfoundry.identity.uaa.oauth.client.ClientJwtCredential;
import org.cloudfoundry.identity.uaa.oauth.jwk.JsonWebKey;
import org.cloudfoundry.identity.uaa.oauth.jwk.JsonWebKeySet;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatExceptionOfType;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatThrownBy;
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
    void jwksValidity() {
        assertThat(ClientJwtConfiguration.parse("https://any.domain.net/openid/jwks-uri")).isNotNull();
        assertThat(ClientJwtConfiguration.parse("http://any.localhost/openid/jwks-uri")).isNotNull();
    }

    @Test
    void jwksInvalid() {
        assertThatExceptionOfType(InvalidClientDetailsException.class).isThrownBy(() -> ClientJwtConfiguration.parse("custom://any.domain.net/openid/jwks-uri", null));
        assertThatExceptionOfType(InvalidClientDetailsException.class).isThrownBy(() -> ClientJwtConfiguration.parse("test", null));
        assertThatExceptionOfType(InvalidClientDetailsException.class).isThrownBy(() -> ClientJwtConfiguration.parse("http://any.domain.net/openid/jwks-uri"));
        assertThatExceptionOfType(InvalidClientDetailsException.class).isThrownBy(() -> ClientJwtConfiguration.parse("https://"));
        assertThatExceptionOfType(InvalidClientDetailsException.class).isThrownBy(() -> ClientJwtConfiguration.parse("ftp://any.domain.net/openid/jwks-uri"));
    }

    @Test
    void jwkSetValidity() {
        assertThat(ClientJwtConfiguration.parse(jsonWebKey)).isNotNull();
        assertThat(ClientJwtConfiguration.parse(jsonJwkSet)).isNotNull();
    }

    @Test
    void jwkSetInvalid() {
        assertThatExceptionOfType(InvalidClientDetailsException.class).isThrownBy(() -> ClientJwtConfiguration.parse(jsonJwkSetEmtpy));
        assertThatExceptionOfType(InvalidClientDetailsException.class).isThrownBy(() -> ClientJwtConfiguration.parse(jsonWebKeyNoId));
        assertThatExceptionOfType(InvalidClientDetailsException.class).isThrownBy(() -> ClientJwtConfiguration.parse("{\"keys\": \"x\"}"));
    }

    @Test
    void jwkSetInvalidSize() {
        assertThatExceptionOfType(InvalidClientDetailsException.class).isThrownBy(() -> new ClientJwtConfiguration(null, new JsonWebKeySet<>(Collections.emptyList())));
    }

    @Test
    void hasConfiguration() {
        assertThat(ClientJwtConfiguration.parse("https://any.domain.net/openid/jwks-uri").hasConfiguration()).isTrue();
        assertThat(ClientJwtConfiguration.parse(null).hasConfiguration()).isFalse();
        assertThat(new ClientJwtConfiguration().hasConfiguration()).isFalse();
        assertThat(ClientJwtConfiguration.parse(jsonJwkSet).hasConfiguration()).isTrue();
        assertThat(ClientJwtConfiguration.parse(jsonWebKey).hasConfiguration()).isTrue();
    }

    @Test
    void jwtCredentials() {
        ClientJwtConfiguration config = new ClientJwtConfiguration(ClientJwtCredential.parse("[{\"iss\":\"http://localhost:8080/uaa\",\"sub\":\"client_with_jwks_trust\"}]"));
        assertThat(config.getClientJwtCredentials()).hasSize(1);
        assertThat(config.hasConfiguration()).isTrue();
        ClientJwtConfiguration mergeConfig = ClientJwtConfiguration.merge(ClientJwtConfiguration.parse("https://any.domain.net/openid/jwks-uri"), config, false);
        assertThat(mergeConfig.getClientJwtCredentials()).isNotNull();
        assertThat(mergeConfig.getJwksUri()).isNotNull();
        assertThat(mergeConfig.getJwkSet()).isNull();
    }

    @Test
    void addAndDeleteJwtCredentials() {
        ClientJwtConfiguration config = new ClientJwtConfiguration(ClientJwtCredential.parse("[{\"iss\":\"http://localhost:8080/uaa\",\"sub\":\"client_with_jwks_trust\"}]"));
        assertThat(config.getClientJwtCredentials()).hasSize(1);
        config.addJwtCredentials(ClientJwtCredential.parse("[{\"iss\":\"http://localhost:8080/uaa\",\"sub\":\"client_with_jwks_trust\"}]"));
        assertThat(config.getClientJwtCredentials()).hasSize(1);
        assertThat(config.hasConfiguration()).isTrue();
        ClientJwtConfiguration mergeConfig = ClientJwtConfiguration.merge(config, config, true);
        mergeConfig = ClientJwtConfiguration.delete(mergeConfig, config);
        assertThat(ClientJwtConfiguration.delete(mergeConfig, config)).isNull();
    }

    @Test
    void invalidJwtCredentials() {
        assertThatThrownBy(() -> new ClientJwtConfiguration(null))
                .isInstanceOf(InvalidClientDetailsException.class);
        ClientJwtConfiguration config = new ClientJwtConfiguration(ClientJwtCredential.parse("[{\"iss\":\"http://localhost:8080/uaa\",\"sub\":\"client_with_jwks_trust\"}]"));
        assertThatThrownBy(() -> config.addJwtCredentials(List.of(new ClientJwtCredential("subject", null, null))))
                .isInstanceOf(IllegalArgumentException.class);

        for (int i = 0; i < 9; i++) {
            config.addJwtCredentials(List.of(new ClientJwtCredential("subject" + i, "issuer" + i, "audience")));
        }
        assertThatThrownBy(() -> config.addJwtCredentials(List.of(new ClientJwtCredential("subject-max", "issuer-max", "audience"))))
                .isInstanceOf(InvalidClientDetailsException.class);
    }

    @Test
    void getCleanConfigInvalid() {
        JsonWebKeySet<JsonWebKey> mockedKey = mock(JsonWebKeySet.class);
        List<JsonWebKey> keyList = ClientJwtConfiguration.parse(jsonJwkSet).getJwkSet().getKeys();
        when(mockedKey.getKeys()).thenReturn(keyList);
        ClientJwtConfiguration privateKey = new ClientJwtConfiguration(null, mockedKey);
        when(mockedKey.getKeySetMap()).thenThrow(new IllegalStateException("error"));
        assertThatExceptionOfType(InvalidClientDetailsException.class).isThrownBy(privateKey::hasConfiguration);
        ClientJwtConfiguration privateKey2 = new ClientJwtConfiguration("hello", null);
        assertThat(privateKey2.hasConfiguration()).isFalse();
    }

    @Test
    void jwtSetValidate() {
        JsonWebKeySet<JsonWebKey> mockedKey = mock(JsonWebKeySet.class);
        List<JsonWebKey> keyList = ClientJwtConfiguration.parse(jsonJwkSet).getJwkSet().getKeys();
        when(mockedKey.getKeys()).thenReturn(Arrays.asList(keyList.getFirst(), keyList.getFirst()));
        assertThatExceptionOfType(InvalidClientDetailsException.class).isThrownBy(() -> new ClientJwtConfiguration(null, mockedKey));
    }

    @Test
    void configMerge() {
        ClientJwtConfiguration configuration = ClientJwtConfiguration.parse(jsonJwkSet);
        assertThat(configuration.getJwkSet().getKeys()).hasSize(1);
        ClientJwtConfiguration addKey = ClientJwtConfiguration.parse(jsonWebKey2);
        configuration = ClientJwtConfiguration.merge(configuration, addKey, false);
        assertThat(configuration.getJwkSet().getKeys()).hasSize(2);
        assertThat(configuration.getJwkSet().getKeys().getFirst().getKeyProperties()).containsEntry("n", nValue);
        assertThat(configuration.getJwkSet().getKeys().get(1).getKeyProperties()).containsEntry("n", nValue);

        configuration = ClientJwtConfiguration.merge(configuration, addKey, true);
        assertThat(configuration.getJwkSet().getKeys()).hasSize(2);

        configuration = ClientJwtConfiguration.parse(jsonJwkSet);
        assertThat(configuration.getJwkSet().getKeys()).hasSize(1);
        assertThat(configuration.getJwkSet().getKeys().getFirst().getKeyProperties()).containsEntry("n", nValue);

        configuration = ClientJwtConfiguration.merge(ClientJwtConfiguration.parse(jsonJwkSet), ClientJwtConfiguration.parse(jsonWebKeyDifferentValue), true);
        assertThat(configuration.getJwkSet().getKeys()).hasSize(1);
        assertThat(configuration.getJwkSet().getKeys().getFirst().getKeyProperties()).containsEntry("n", "new");

        configuration = ClientJwtConfiguration.merge(ClientJwtConfiguration.parse(jsonJwkSet), ClientJwtConfiguration.parse(jsonWebKeyDifferentValue), false);
        assertThat(configuration.getJwkSet().getKeys()).hasSize(1);
        assertThat(configuration.getJwkSet().getKeys().getFirst().getKeyProperties()).containsEntry("n", nValue);
    }

    @Test
    void configMergeDifferentType() {
        ClientJwtConfiguration configuration = ClientJwtConfiguration.parse(jsonJwkSet);
        assertThat(configuration.getJwkSet().getKeys()).hasSize(1);
        assertThat(configuration.getJwksUri()).isNull();
        configuration = ClientJwtConfiguration.merge(configuration, ClientJwtConfiguration.parse("https://any/jwks-uri"), false);
        assertThat(configuration.getJwkSet().getKeys()).hasSize(1);
        assertThat(configuration.getJwksUri()).isEqualTo("https://any/jwks-uri");

        configuration = ClientJwtConfiguration.merge(configuration, ClientJwtConfiguration.parse("https://any/jwks-uri"), true);
        assertThat(configuration.getJwkSet()).isNull();
        assertThat(configuration.getJwksUri()).isNotNull();

        configuration = ClientJwtConfiguration.merge(ClientJwtConfiguration.parse("https://any/jwks-uri"), ClientJwtConfiguration.parse("https://new/jwks-uri"), false);
        assertThat(configuration.getJwkSet()).isNull();
        assertThat(configuration.getJwksUri()).isEqualTo("https://any/jwks-uri");

        configuration = ClientJwtConfiguration.merge(ClientJwtConfiguration.parse("https://any/jwks-uri"), ClientJwtConfiguration.parse("https://new/jwks-uri"), true);
        assertThat(configuration.getJwkSet()).isNull();
        assertThat(configuration.getJwksUri()).isEqualTo("https://new/jwks-uri");

        configuration = ClientJwtConfiguration.merge(ClientJwtConfiguration.parse("https://any/jwks-uri"), ClientJwtConfiguration.parse(jsonJwkSet), false);
        assertThat(configuration.getJwkSet()).isNotNull();
        assertThat(configuration.getJwkSet().getKeys()).hasSize(1);
        assertThat(configuration.getJwksUri()).isEqualTo("https://any/jwks-uri");

        configuration = ClientJwtConfiguration.merge(ClientJwtConfiguration.parse("https://any/jwks-uri"), ClientJwtConfiguration.parse(jsonJwkSet), true);
        assertThat(configuration.getJwksUri()).isNull();
        assertThat(configuration.getJwkSet().getKeys()).hasSize(1);
        assertThat(configuration.getJwkSet().getKeys().getFirst().getKeyProperties()).containsEntry("n", nValue);
    }

    @Test
    void configMergeNulls() {
        ClientJwtConfiguration configuration = ClientJwtConfiguration.parse(jsonJwkSet);
        ClientJwtConfiguration existingKeyConfig = ClientJwtConfiguration.merge(configuration, null, true);
        assertThat(existingKeyConfig).isEqualTo(configuration);

        ClientJwtConfiguration newKeyConfig = ClientJwtConfiguration.parse("https://any/jwks-uri");
        configuration = ClientJwtConfiguration.merge(null, newKeyConfig, true);
        assertThat(newKeyConfig).isEqualTo(configuration);
    }

    @Test
    void configDelete() {
        ClientJwtConfiguration configuration = ClientJwtConfiguration.parse(jsonJwkSet);
        assertThat(configuration.getJwkSet().getKeys()).hasSize(1);
        assertThat(configuration.getJwksUri()).isNull();
        ClientJwtConfiguration addKey = ClientJwtConfiguration.parse(jsonWebKey2);
        configuration = ClientJwtConfiguration.merge(configuration, addKey, false);
        assertThat(configuration.getJwkSet().getKeys()).hasSize(2);
        configuration = ClientJwtConfiguration.delete(configuration, addKey);
        assertThat(configuration.getJwkSet().getKeys()).hasSize(1);
        configuration = ClientJwtConfiguration.delete(configuration, addKey);
        configuration = ClientJwtConfiguration.delete(configuration, addKey);
        assertThat(configuration.getJwkSet().getKeys()).hasSize(1);
        configuration = ClientJwtConfiguration.merge(configuration, addKey, false);
        configuration = ClientJwtConfiguration.delete(configuration, addKey);
        assertThat(configuration.getJwkSet().getKeys()).hasSize(1);
        configuration = ClientJwtConfiguration.merge(configuration, addKey, false);
        configuration = ClientJwtConfiguration.delete(configuration, new ClientJwtConfiguration("key-2", null));
        configuration = ClientJwtConfiguration.delete(configuration, new ClientJwtConfiguration("key-1", null));
        assertThat(configuration).isNull();
        configuration = ClientJwtConfiguration.delete(ClientJwtConfiguration.parse(jsonJwkSet), ClientJwtConfiguration.parse(jsonWebKey));
        assertThat(configuration).isNull();

        configuration = ClientJwtConfiguration.delete(ClientJwtConfiguration.parse("https://any/jwks-uri"), ClientJwtConfiguration.parse("https://any/jwks-uri"));
        assertThat(configuration).isNull();
        configuration = ClientJwtConfiguration.delete(ClientJwtConfiguration.parse("https://any/jwks-uri"), ClientJwtConfiguration.parse("https://other/jwks-uri"));
        assertThat(configuration).isNotNull();
    }

    @Test
    void configDeleteFederated() {
        ClientJwtCredential existingKey1 = new ClientJwtCredential("subject1", "issuer1", "audience1");
        ClientJwtCredential existingKey2 = new ClientJwtCredential("subject2", "issuer2", "audience2");
        ClientJwtConfiguration existingConfiguration = new ClientJwtConfiguration(List.of(existingKey1, existingKey2));
        assertThat(ClientJwtConfiguration.delete(existingConfiguration, new ClientJwtConfiguration(List.of(new ClientJwtCredential("not-existing", "not-existing", null))))).isEqualTo(existingConfiguration);
        assertThat(ClientJwtConfiguration.delete(existingConfiguration, new ClientJwtConfiguration(List.of(existingKey1)))).isEqualTo(new ClientJwtConfiguration(List.of(existingKey2)));
        existingConfiguration = new ClientJwtConfiguration(List.of(existingKey1, existingKey2));
        assertThat(ClientJwtConfiguration.delete(existingConfiguration, existingConfiguration)).isNull();
        assertThat(ClientJwtConfiguration.delete(new ClientJwtConfiguration(List.of(existingKey1, existingKey2)), new ClientJwtConfiguration(List.of(new ClientJwtCredential("*", "*", null))))).isNull();
        assertThat(ClientJwtConfiguration.delete(new ClientJwtConfiguration(List.of(existingKey1, existingKey2)), new ClientJwtConfiguration(List.of(new ClientJwtCredential("*", "*", "*"))))).isNull();
    }

    @Test
    void configDeleteMixedJwtConfiguration() {
        ClientJwtCredential existingKey1 = new ClientJwtCredential("subject1", "issuer1", "audience1");
        ClientJwtCredential existingKey2 = new ClientJwtCredential("subject2", "issuer2", "audience2");
        ClientJwtConfiguration existingConfiguration = ClientJwtConfiguration.parse("https://other/jwks-uri");
        existingConfiguration.setClientJwtCredentials(List.of(existingKey1, existingKey2));
        assertThat(ClientJwtConfiguration.delete(existingConfiguration, new ClientJwtConfiguration(List.of(new ClientJwtCredential("not-existing", "not-existing", null))))).isEqualTo(existingConfiguration);
        assertThat(ClientJwtConfiguration.delete(existingConfiguration, new ClientJwtConfiguration(List.of(existingKey1))).getClientJwtCredentials()).hasSize(1);
        assertThat(ClientJwtConfiguration.delete(existingConfiguration, new ClientJwtConfiguration(List.of(existingKey1, existingKey2))).getClientJwtCredentials()).isNull();
        // complex deletion - given
        existingConfiguration = new ClientJwtConfiguration(List.of(existingKey1, existingKey2));
        existingConfiguration = ClientJwtConfiguration.merge(existingConfiguration, ClientJwtConfiguration.parse("https://other/jwks-uri"), false);
        // When
        existingConfiguration = ClientJwtConfiguration.delete(existingConfiguration, ClientJwtConfiguration.parse("https://other/jwks-uri"));
        // Then
        assertThat(existingConfiguration).isEqualTo(new ClientJwtConfiguration(List.of(existingKey1, existingKey2)));
    }

    @Test
    void configDeleteNull() {
        assertThat(ClientJwtConfiguration.delete(null, ClientJwtConfiguration.parse("https://other/jwks-uri"))).isNull();
        assertThat(ClientJwtConfiguration.delete(ClientJwtConfiguration.parse("https://any/jwks-uri"), null)).isNotNull();
    }

    @Test
    void testHashCode() {
        ClientJwtConfiguration key1 = ClientJwtConfiguration.parse("http://localhost:8080/uaa");
        ClientJwtConfiguration key2 = ClientJwtConfiguration.parse("http://localhost:8080/uaa");
        assertThat(key2.hashCode()).isNotEqualTo(key1.hashCode());
        assertThat(key1).hasSameHashCodeAs(key1);
        assertThat(key2).hasSameHashCodeAs(key2);
        assertThat(new ClientJwtCredential("subject", "issuer", "audience")).hasSameHashCodeAs(new ClientJwtCredential("subject", "issuer", "audience"));
    }

    @Test
    void equals() throws CloneNotSupportedException {
        ClientJwtConfiguration key1 = ClientJwtConfiguration.parse("http://localhost:8080/uaa");
        ClientJwtConfiguration key2 = (ClientJwtConfiguration) key1.clone();
        assertThat(key2).isEqualTo(key1);
    }

    @Test
    void serializableObjectCalls() throws CloneNotSupportedException {
        ClientJwtConfiguration key1 = JsonUtils.readValue(defaultJsonUri, ClientJwtConfiguration.class);
        ClientJwtConfiguration key2 = (ClientJwtConfiguration) key1.clone();
        assertThat(key2).isEqualTo(key1);

        key1 = JsonUtils.readValue(defaultJsonKey, ClientJwtConfiguration.class);
        key2 = (ClientJwtConfiguration) key1.clone();
        assertThat(key2).isEqualTo(key1);
    }

    @Test
    void configuration() {
        ClientJwtConfiguration configUri = JsonUtils.readValue(defaultJsonUri, ClientJwtConfiguration.class);
        ClientJwtConfiguration configKey = JsonUtils.readValue(defaultJsonKey, ClientJwtConfiguration.class);
        UaaClientDetails uaaClientDetails = new UaaClientDetails();
        uaaClientDetails.setClientJwtConfig(JsonUtils.writeValueAsString(configUri));

        configUri.writeValue(uaaClientDetails);
        ClientJwtConfiguration readUriConfig = ClientJwtConfiguration.readValue(uaaClientDetails);
        assertThat(readUriConfig).isEqualTo(configUri);

        ClientJwtConfiguration.resetConfiguration(uaaClientDetails);
        assertThat(ClientJwtConfiguration.readValue(uaaClientDetails)).isNull();
        configKey.writeValue(uaaClientDetails);
        ClientJwtConfiguration readKeyConfig = ClientJwtConfiguration.readValue(uaaClientDetails);
        assertThat(readKeyConfig).isEqualTo(configKey);
    }
}

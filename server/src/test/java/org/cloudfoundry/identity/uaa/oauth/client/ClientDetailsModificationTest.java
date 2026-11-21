package org.cloudfoundry.identity.uaa.oauth.client;

import org.cloudfoundry.identity.uaa.client.ClientJwtConfiguration;
import org.cloudfoundry.identity.uaa.client.InvalidClientDetailsException;
import org.cloudfoundry.identity.uaa.client.UaaClientDetails;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ClientDetailsModificationTest {

    @Test
    void constructor_exposesMergedJwtCredsAndOmitsRawAdditionalKeys() {
        UaaClientDetails d = new UaaClientDetails();
        d.setClientId("x");
        d.setClientSecret("s");
        d.setAuthorizedGrantTypes(List.of("client_credentials"));
        d.setAuthorities(List.of(new SimpleGrantedAuthority("uaa.none")));
        d.addAdditionalInformation(ClientJwtConfiguration.JWT_CREDS, JsonUtils.readValue(
                "[{\"iss\":\"http://u\",\"sub\":\"s\"}]", List.class));

        ClientDetailsModification m = new ClientDetailsModification(d);
        assertThat(m.getClientJwtCredentials()).hasSize(1);
        assertThat(m.getAdditionalInformation()).doesNotContainKey(ClientJwtConfiguration.JWT_CREDS);
        assertThat(m.getAdditionalInformation()).doesNotContainKey("client_jwt_config");
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "not json",
            "{\"jwks\":{\"keys\":[{\"kty\":\"RSA\",\"kid\":\"incomplete\"}]}}",
            "{\"jwks\":{\"keys\":[{\"kid\":\"missing-key-type\"}]}}",
            "{\"jwks\":{\"keys\":[{\"kty\":\"EC\",\"kid\":\"incomplete\",\"crv\":\"P-256\"}]}}",
            "{\"jwks\":42}",
            "{\"jwt_creds\":[]}",
            "{\"jwt_creds\":[{\"iss\":\"https://issuer.example.com\",\"sub\":\"\"}]}"
    })
    void constructor_withUnreadableJwtConfiguration_preservesRawValueAndSerializes(String stored) {
        UaaClientDetails client = new UaaClientDetails("client", null, "openid", "client_credentials", "uaa.none");
        client.setClientJwtConfig(stored);
        // Check that each fixture actually fails JWT parsing or key materialization.
        assertThatThrownBy(() -> ClientJwtConfiguration.readValue(stored).hasConfiguration())
                .isInstanceOfAny(JsonUtils.JsonUtilException.class, InvalidClientDetailsException.class);

        ClientDetailsModification response = new ClientDetailsModification(client);

        assertThat(JsonUtils.readValueAsMap(JsonUtils.writeValueAsString(response)))
                .containsEntry("client_id", "client")
                .containsEntry("client_jwt_config", stored)
                .doesNotContainKeys("jwks", "jwks_uri", "jwt_creds");
        assertThat(client.getClientJwtConfig()).isEqualTo(stored);
    }
}

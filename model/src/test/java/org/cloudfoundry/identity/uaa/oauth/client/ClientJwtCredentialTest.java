package org.cloudfoundry.identity.uaa.oauth.client;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;


class ClientJwtCredentialTest {

    @Test
    void parse() {
        assertThat(ClientJwtCredential.parse("[{\"iss\":\"http://localhost:8080/uaa\",\"sub\":\"client_with_jwks_trust\"}]")).isInstanceOf(List.class);
        List<ClientJwtCredential> federationList = ClientJwtCredential.parse("[{\"iss\":\"http://localhost:8080/uaa\",\"sub\":\"client_with_jwks_trust\"},{\"iss\":\"http://localhost:8080/uaa\", \"sub\":\"another_client\"}]");
        assertThat(federationList).hasSize(2);
    }

    @Test
    void constructor() {
        ClientJwtCredential jwtCredential = new ClientJwtCredential("subject", "issuer", "audience");
        assertThat(jwtCredential.getSubject()).isEqualTo("subject");
        assertThat(jwtCredential.getIssuer()).isEqualTo("issuer");
        assertThat(jwtCredential.getAudience()).isEqualTo("audience");
    }

    @Test
    void deserializerConstructorException() {
        assertThatThrownBy(() -> ClientJwtCredential.parse("[{\"iss\":\"http://localhost:8080/uaa\",\"sub\":\"client_with_jwks_trust\"},{\"iss\":\"http://localhost:8080/uaa\"}]"))
                .isInstanceOf(IllegalArgumentException.class).hasMessage("Client jwt configuration cannot be parsed");
        assertThatThrownBy(() -> ClientJwtCredential.parse("[{\"sub\":\"client_with_jwks_trust\"}]"))
                .isInstanceOf(IllegalArgumentException.class).hasMessage("Client jwt configuration cannot be parsed");
        assertThatThrownBy(() -> ClientJwtCredential.parse("[{\"unknown\":\"client_with_jwks_trust\"}]"))
                .isInstanceOf(IllegalArgumentException.class).hasMessage("Client jwt configuration cannot be parsed");
    }

    @Test
    void deserializerParserException() {
        assertThatThrownBy(() -> ClientJwtCredential.parse("[\"iss\":\"issuer\"]"))
                .isInstanceOf(IllegalArgumentException.class).hasMessage("Client jwt configuration cannot be parsed");
    }

    @Test
    void testHashCode() {
        assertThat(new ClientJwtCredential("subject", "issuer", "audience")).hasSameHashCodeAs(new ClientJwtCredential("subject", "issuer", "audience"));
        assertThat(new ClientJwtCredential("subject", "issuer", "audience")).doesNotHaveSameHashCodeAs(new ClientJwtCredential("subject", "issuer", null));
    }

    @Test
    void equals() {
        assertThat(new ClientJwtCredential("subject", "issuer", "audience")).isEqualTo(new ClientJwtCredential("subject", "issuer", "audience"));
        assertThat(new ClientJwtCredential("subject", "issuer", "audience")).isNotEqualTo(new ClientJwtCredential("subject", "issuer", null));
    }
}

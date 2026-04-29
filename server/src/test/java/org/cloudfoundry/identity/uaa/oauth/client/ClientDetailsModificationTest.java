package org.cloudfoundry.identity.uaa.oauth.client;

import org.cloudfoundry.identity.uaa.client.ClientJwtConfiguration;
import org.cloudfoundry.identity.uaa.client.UaaClientDetails;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

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
        assertThat(m.getClientJwtCredentials()).isNotNull().hasSize(1);
        assertThat(m.getAdditionalInformation()).doesNotContainKey(ClientJwtConfiguration.JWT_CREDS);
        assertThat(m.getAdditionalInformation()).doesNotContainKey("client_jwt_config");
    }
}

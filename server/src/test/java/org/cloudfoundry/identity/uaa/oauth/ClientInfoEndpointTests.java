package org.cloudfoundry.identity.uaa.oauth;

import org.cloudfoundry.identity.uaa.client.ClientInfoEndpoint;
import org.cloudfoundry.identity.uaa.client.UaaClientDetails;
import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetails;
import org.cloudfoundry.identity.uaa.zone.MultitenantClientServices;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;

import java.util.Collections;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_AUTHORIZATION_CODE;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class ClientInfoEndpointTests {

    @Mock
    private MultitenantClientServices mockMultitenantClientServices;

    @Mock
    private IdentityZoneManager mockIdentityZoneManager;

    @InjectMocks
    private ClientInfoEndpoint endpoint;

    private String clientId;

    @BeforeEach
    void setUp() {
        clientId = "clientId-" + UUID.randomUUID().toString();
        UaaClientDetails baseClientDetails = new UaaClientDetails(clientId, "none", "read,write", GRANT_TYPE_AUTHORIZATION_CODE, "uaa.none");
        baseClientDetails.setClientSecret("bar");
        baseClientDetails.setAdditionalInformation(Collections.singletonMap("key", "value"));

        final var currentZoneId = "currentZoneId-" + UUID.randomUUID().toString();
        when(mockIdentityZoneManager.getCurrentIdentityZoneId()).thenReturn(currentZoneId);

        when(mockMultitenantClientServices.loadClientByClientId(clientId, currentZoneId)).thenReturn(baseClientDetails);
    }

    @Test
    void clientinfo() {
        ClientDetails clientDetails = endpoint.clientinfo(new UsernamePasswordAuthenticationToken(clientId, "<NONE>"));

        assertThat(clientDetails.getClientId()).isEqualTo(clientId);
        assertThat(clientDetails.getClientSecret()).isNull();
        assertThat(clientDetails.getAdditionalInformation()).isEmpty();
    }

}

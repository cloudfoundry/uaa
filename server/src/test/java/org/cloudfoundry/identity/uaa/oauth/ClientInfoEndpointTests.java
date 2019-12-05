package org.cloudfoundry.identity.uaa.oauth;

import org.cloudfoundry.identity.uaa.client.ClientInfoEndpoint;
import org.cloudfoundry.identity.uaa.extensions.PollutionPreventionExtension;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.MultitenantClientServices;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;

import java.util.Collections;

import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_AUTHORIZATION_CODE;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@ExtendWith(MockitoExtension.class)
@ExtendWith(PollutionPreventionExtension.class)
class ClientInfoEndpointTests {

    @Mock
    private MultitenantClientServices mockMultitenantClientServices;

    @InjectMocks
    private ClientInfoEndpoint endpoint;

    @BeforeEach
    void setUp() {
        BaseClientDetails baseClientDetails = new BaseClientDetails("foo", "none", "read,write", GRANT_TYPE_AUTHORIZATION_CODE, "uaa.none");
        baseClientDetails.setClientSecret("bar");
        baseClientDetails.setAdditionalInformation(Collections.singletonMap("key", "value"));
        Mockito.when(mockMultitenantClientServices.loadClientByClientId("foo", IdentityZoneHolder.get().getId())).thenReturn(baseClientDetails);
    }

    @Test
    void clientinfo() {
        ClientDetails clientDetails = endpoint.clientinfo(new UsernamePasswordAuthenticationToken("foo", "<NONE>"));

        assertEquals("foo", clientDetails.getClientId());
        assertNull(clientDetails.getClientSecret());
        assertTrue(clientDetails.getAdditionalInformation().isEmpty());
    }

}

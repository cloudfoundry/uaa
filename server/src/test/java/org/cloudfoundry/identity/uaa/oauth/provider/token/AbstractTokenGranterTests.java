package org.cloudfoundry.identity.uaa.oauth.provider.token;

import org.cloudfoundry.identity.uaa.client.UaaClientDetails;
import org.cloudfoundry.identity.uaa.oauth.common.OAuth2AccessToken;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.InvalidClientException;
import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetails;
import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetailsService;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Request;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2RequestFactory;
import org.cloudfoundry.identity.uaa.oauth.provider.TokenRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class AbstractTokenGranterTests {

    private static final String GRANT_TYPE = "test_grant";

    private AuthorizationServerTokenServices tokenServices;
    private ClientDetailsService clientDetailsService;
    private TokenRequest tokenRequest;
    private OAuth2AccessToken token;
    private AbstractTokenGranter granter;

    @BeforeEach
    void setUp() {
        tokenServices = mock(AuthorizationServerTokenServices.class);
        clientDetailsService = mock(ClientDetailsService.class);
        OAuth2RequestFactory requestFactory = mock(OAuth2RequestFactory.class);
        tokenRequest = mock(TokenRequest.class);
        token = mock(OAuth2AccessToken.class);
        when(requestFactory.createOAuth2Request(any(), any())).thenReturn(mock(OAuth2Request.class));
        when(tokenServices.createAccessToken(any())).thenReturn(token);
        granter = new AbstractTokenGranter(tokenServices, clientDetailsService, requestFactory, GRANT_TYPE) {
        };
    }

    @Test
    void grant_whenClientHasGrantType_returnsToken() {
        UaaClientDetails client = new UaaClientDetails();
        client.setAuthorizedGrantTypes(Set.of(GRANT_TYPE));
        when(clientDetailsService.loadClientByClientId(any())).thenReturn(client);

        assertThat(granter.grant(GRANT_TYPE, tokenRequest)).isSameAs(token);
    }

    @Test
    void grant_whenClientLacksGrantType_isRejected() {
        UaaClientDetails client = new UaaClientDetails();
        client.setAuthorizedGrantTypes(Set.of("client_credentials"));
        when(clientDetailsService.loadClientByClientId(any())).thenReturn(client);

        assertThatThrownBy(() -> granter.grant(GRANT_TYPE, tokenRequest))
                .isInstanceOf(InvalidClientException.class)
                .hasMessage("Unauthorized grant type");
        verify(tokenServices, never()).createAccessToken(any());
    }

    @Test
    void grant_whenClientHasEmptyGrantTypes_isRejected() {
        UaaClientDetails client = new UaaClientDetails();
        client.setAuthorizedGrantTypes(Collections.emptySet());
        when(clientDetailsService.loadClientByClientId(any())).thenReturn(client);

        assertThatThrownBy(() -> granter.grant(GRANT_TYPE, tokenRequest))
                .isInstanceOf(InvalidClientException.class)
                .hasMessage("Unauthorized grant type");
        verify(tokenServices, never()).createAccessToken(any());
    }

    @Test
    void grant_whenClientHasNullGrantTypes_isRejected() {
        ClientDetails client = mock(ClientDetails.class);
        when(client.getAuthorizedGrantTypes()).thenReturn(null);
        when(clientDetailsService.loadClientByClientId(any())).thenReturn(client);

        assertThatThrownBy(() -> granter.grant(GRANT_TYPE, tokenRequest))
                .isInstanceOf(InvalidClientException.class)
                .hasMessage("Unauthorized grant type");
        verify(tokenServices, never()).createAccessToken(any());
    }

    @Test
    void grant_whenClientBuiltWithNoArgConstructor_isRejected() {
        when(clientDetailsService.loadClientByClientId(any())).thenReturn(new UaaClientDetails());

        assertThatThrownBy(() -> granter.grant(GRANT_TYPE, tokenRequest))
                .isInstanceOf(InvalidClientException.class)
                .hasMessage("Unauthorized grant type");
        verify(tokenServices, never()).createAccessToken(any());
    }
}

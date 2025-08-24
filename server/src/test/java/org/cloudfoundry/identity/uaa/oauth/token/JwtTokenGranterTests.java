package org.cloudfoundry.identity.uaa.oauth.token;

import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.client.UaaClientDetails;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.oauth.UaaOauth2Authentication;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.InvalidGrantException;
import org.cloudfoundry.identity.uaa.oauth.common.util.OAuth2Utils;
import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetails;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Authentication;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Request;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2RequestFactory;
import org.cloudfoundry.identity.uaa.oauth.provider.TokenRequest;
import org.cloudfoundry.identity.uaa.oauth.provider.token.AuthorizationServerTokenServices;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.MultitenantClientServices;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.cloudfoundry.identity.uaa.oauth.common.util.OAuth2Utils.GRANT_TYPE;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_JWT_BEARER;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.same;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class JwtTokenGranterTests {

    private JwtTokenGranter granter;
    private TokenRequest tokenRequest;
    private ClientDetails client;
    private UaaOauth2Authentication authentication;
    private UaaAuthentication uaaAuthentication;
    private AuthorizationServerTokenServices tokenServices;
    private MultitenantClientServices clientDetailsService;
    private OAuth2RequestFactory requestFactory;
    private Map<String, String> requestParameters;

    @BeforeEach
    void setUp() {
        tokenServices = mock(AuthorizationServerTokenServices.class);
        clientDetailsService = mock(MultitenantClientServices.class);
        requestFactory = mock(OAuth2RequestFactory.class);
        granter = spy(new JwtTokenGranter(tokenServices, clientDetailsService, requestFactory));
        tokenRequest = new TokenRequest(Collections.emptyMap(), "client_ID", Collections.emptySet(), GRANT_TYPE_JWT_BEARER);

        authentication = mock(UaaOauth2Authentication.class);
        UaaUser user = new UaaUser("id",
                "username",
                null,
                "user@user.org",
                Collections.emptyList(),
                "Firstname",
                "lastName",
                new Date(),
                new Date(),
                OriginKeys.OIDC10,
                null,
                true,
                IdentityZoneHolder.get().getId(),
                "salt",
                new Date()
        );
        uaaAuthentication = new UaaAuthentication(
                new UaaPrincipal(user), Collections.emptyList(), null
        );
        SecurityContextHolder.getContext().setAuthentication(authentication);

        client = new UaaClientDetails("clientID", null, "uaa.user", GRANT_TYPE_JWT_BEARER, null);
        when(clientDetailsService.loadClientByClientId(eq(client.getClientId()), anyString())).thenReturn(client);
        requestParameters = new HashMap<>();
        requestParameters.put(OAuth2Utils.CLIENT_ID, client.getClientId());
        requestParameters.put(GRANT_TYPE, GRANT_TYPE_JWT_BEARER);
        tokenRequest.setRequestParameters(requestParameters);
    }

    @AfterEach
    void tearDown() {
        IdentityZoneHolder.clear();
        SecurityContextHolder.clearContext();
    }

    @Test
    void non_authentication_validates_correctly() {
        SecurityContextHolder.clearContext();
        assertThatThrownBy(() -> granter.validateRequest(tokenRequest))
                .isInstanceOf(InvalidGrantException.class)
                .hasMessageContaining("User authentication not found");
    }

    @Test
    void client_authentication_only() {
        when(authentication.isClientOnly()).thenReturn(true);
        SecurityContextHolder.getContext().setAuthentication(authentication);
        assertThatThrownBy(() -> granter.validateRequest(tokenRequest))
                .isInstanceOf(InvalidGrantException.class)
                .hasMessageContaining("User authentication not found");
    }

    @Test
    void missing_token_request() {
        SecurityContextHolder.getContext().setAuthentication(uaaAuthentication);
        assertThatThrownBy(() -> granter.validateRequest(null))
                .isInstanceOf(InvalidGrantException.class)
                .hasMessageContaining("Missing token request object");
    }

    @Test
    void missing_request_parameters() {
        SecurityContextHolder.getContext().setAuthentication(uaaAuthentication);
        tokenRequest.setRequestParameters(Collections.emptyMap());
        assertThatThrownBy(() -> granter.validateRequest(tokenRequest))
                .isInstanceOf(InvalidGrantException.class)
                .hasMessageContaining("Missing token request object");
    }

    @Test
    void missing_grant_type() {
        SecurityContextHolder.getContext().setAuthentication(uaaAuthentication);
        requestParameters.remove(GRANT_TYPE);
        tokenRequest.setRequestParameters(requestParameters);
        assertThatThrownBy(() -> granter.validateRequest(tokenRequest))
                .isInstanceOf(InvalidGrantException.class)
                .hasMessageContaining("Missing grant type");
    }

    @Test
    void invalid_grant_type() {
        SecurityContextHolder.getContext().setAuthentication(uaaAuthentication);
        requestParameters.put(GRANT_TYPE, "password");
        tokenRequest.setRequestParameters(requestParameters);
        assertThatThrownBy(() -> granter.validateRequest(tokenRequest))
                .isInstanceOf(InvalidGrantException.class)
                .hasMessageContaining("Invalid grant type");
    }

    @Test
    void get_oauth2_authentication_validates_request() {
        SecurityContextHolder.clearContext();
        assertThatThrownBy(() -> granter.getOAuth2Authentication(client, tokenRequest))
                .isInstanceOf(InvalidGrantException.class)
                .hasMessageContaining("User authentication not found");
        verify(granter, times(1)).validateRequest(same(tokenRequest));
    }

    @Test
    void get_oauth2_authentication() {
        SecurityContextHolder.getContext().setAuthentication(uaaAuthentication);
        OAuth2Request request = mock(OAuth2Request.class);
        when(requestFactory.createOAuth2Request(same(client), same(tokenRequest))).thenReturn(request);
        OAuth2Authentication result = granter.getOAuth2Authentication(client, tokenRequest);
        assertThat(result.getOAuth2Request()).isSameAs(request);
        assertThat(result.getUserAuthentication()).isSameAs(uaaAuthentication);
    }
}
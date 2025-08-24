package org.cloudfoundry.identity.uaa.oauth.provider.request;

import org.cloudfoundry.identity.uaa.oauth.common.exceptions.InvalidClientException;
import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetails;
import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetailsService;
import org.cloudfoundry.identity.uaa.security.beans.DefaultSecurityContextAccessor;
import org.cloudfoundry.identity.uaa.security.beans.SecurityContextAccessor;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;

import java.util.Collection;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatExceptionOfType;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Moved test class of from spring-security-oauth2 into UAA
 * Scope: Test class
 */
class DefaultOAuth2RequestFactoryTests {

    private DefaultOAuth2RequestFactory defaultOAuth2RequestFactory;
    private ClientDetails clientDetails;
    private Map<String, String> requestParameters;

    @BeforeEach
    void setUp() throws Exception {
        clientDetails = mock(ClientDetails.class);
        ClientDetailsService clientDetailsService = mock(ClientDetailsService.class);
        when(clientDetailsService.loadClientByClientId(any())).thenReturn(clientDetails);
        defaultOAuth2RequestFactory = new DefaultOAuth2RequestFactory(clientDetailsService);
        requestParameters = Map.of("client_id", "id");
    }

    @Test
    void setSecurityContextAccessor() {
        defaultOAuth2RequestFactory.setSecurityContextAccessor(new DefaultSecurityContextAccessor());
        assertThat(defaultOAuth2RequestFactory).isNotNull();
    }

    @Test
    void setCheckUserScopes() {
        defaultOAuth2RequestFactory.setCheckUserScopes(true);
        assertThat(defaultOAuth2RequestFactory).isNotNull();
    }

    @Test
    void createAuthorizationRequest() {
        assertThat(defaultOAuth2RequestFactory.createAuthorizationRequest(requestParameters)).isNotNull();
    }

    @Test
    void createOAuth2Request() {
        assertThat(defaultOAuth2RequestFactory.createOAuth2Request(defaultOAuth2RequestFactory.createAuthorizationRequest(requestParameters))).isNotNull();
    }

    @Test
    void createTokenRequest() {
        assertThat(defaultOAuth2RequestFactory.createTokenRequest(defaultOAuth2RequestFactory.createAuthorizationRequest(requestParameters), "")).isNotNull();
    }

    @Test
    void testCreateTokenRequest() {
        when(clientDetails.getClientId()).thenReturn("id");
        assertThat(defaultOAuth2RequestFactory.createTokenRequest(requestParameters, clientDetails)).isNotNull();
    }

    @Test
    void createTokenRequestDifferentClientId() {
        when(clientDetails.getClientId()).thenReturn("my-client-id");
        assertThatExceptionOfType(InvalidClientException.class).isThrownBy(() ->
                defaultOAuth2RequestFactory.createTokenRequest(requestParameters, clientDetails));
    }

    @Test
    void testCreateOAuth2Request() {
        when(clientDetails.getClientId()).thenReturn("id");
        assertThat(defaultOAuth2RequestFactory.createOAuth2Request(clientDetails,
                defaultOAuth2RequestFactory.createTokenRequest(defaultOAuth2RequestFactory.createAuthorizationRequest(requestParameters), ""))).isNotNull();
    }

    @Test
    void createOAuth2RequestNoClientInRequest() {
        when(clientDetails.getClientId()).thenReturn("id");
        assertThat(defaultOAuth2RequestFactory.createTokenRequest(Map.of(), clientDetails)).isNotNull();
    }

    @Test
    void createOAuth2RequestWithUserCheck() {
        defaultOAuth2RequestFactory.setCheckUserScopes(true);
        assertThat(defaultOAuth2RequestFactory.createOAuth2Request(defaultOAuth2RequestFactory.createAuthorizationRequest(requestParameters))).isNotNull();
        SecurityContextAccessor securityContextAccessor = mock(SecurityContextAccessor.class);
        defaultOAuth2RequestFactory.setSecurityContextAccessor(securityContextAccessor);
        when(securityContextAccessor.isUser()).thenReturn(true);
        assertThat(defaultOAuth2RequestFactory.createOAuth2Request(defaultOAuth2RequestFactory.createAuthorizationRequest(requestParameters))).isNotNull();
    }

    @Test
    void createOAuth2RequestWithUserCheckAndScopes() {
        SecurityContextAccessor securityContextAccessor = mock(SecurityContextAccessor.class);
        defaultOAuth2RequestFactory.setSecurityContextAccessor(securityContextAccessor);
        defaultOAuth2RequestFactory.setCheckUserScopes(true);
        when(securityContextAccessor.isUser()).thenReturn(true);
        when(clientDetails.getScope()).thenReturn(Set.of("read", "uaa", "admin"));
        Collection<? extends GrantedAuthority> authorities = AuthorityUtils.commaSeparatedStringToAuthorityList("read,write");
        doReturn(authorities).when(securityContextAccessor).getAuthorities();
        assertThat(defaultOAuth2RequestFactory.createOAuth2Request(defaultOAuth2RequestFactory.createAuthorizationRequest(requestParameters))).isNotNull();
    }
}

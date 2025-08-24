package org.cloudfoundry.identity.uaa.oauth.provider.password;

import org.cloudfoundry.identity.uaa.client.UaaClientDetails;
import org.cloudfoundry.identity.uaa.oauth.common.OAuth2AccessToken;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.InvalidClientException;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.InvalidGrantException;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.OAuth2Exception;
import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetails;
import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetailsService;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Authentication;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2RequestFactory;
import org.cloudfoundry.identity.uaa.oauth.provider.TokenRequest;
import org.cloudfoundry.identity.uaa.oauth.provider.request.DefaultOAuth2RequestFactory;
import org.cloudfoundry.identity.uaa.oauth.provider.token.DefaultTokenServices;
import org.cloudfoundry.identity.uaa.oauth.provider.token.InMemoryTokenStore;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatExceptionOfType;

/**
 * Moved test class of from spring-security-oauth2 into UAA
 * Scope: Test class
 */
class ResourceOwnerPasswordTokenGranterTests {

    private Authentication validUser = new UsernamePasswordAuthenticationToken("foo", "bar",
            List.of(new SimpleGrantedAuthority("ROLE_USER")));

    private final UaaClientDetails client = new UaaClientDetails("foo", "resource", "scope", "password", "ROLE_USER");

    private AuthenticationManager authenticationManager = new AuthenticationManager() {
        public Authentication authenticate(Authentication authentication) throws AuthenticationException {
            return validUser;
        }
    };

    private final DefaultTokenServices providerTokenServices = new DefaultTokenServices();

    private final ClientDetailsService clientDetailsService = new ClientDetailsService() {
        public ClientDetails loadClientByClientId(String clientId) throws OAuth2Exception {
            return client;
        }
    };

    private final OAuth2RequestFactory requestFactory = new DefaultOAuth2RequestFactory(clientDetailsService);

    private final TokenRequest tokenRequest;

    public ResourceOwnerPasswordTokenGranterTests() {
        String clientId = "client";
        UaaClientDetails clientDetails = new UaaClientDetails();
        clientDetails.setClientId(clientId);

        providerTokenServices.setTokenStore(new InMemoryTokenStore());
        Map<String, String> parameters = new HashMap<>();
        parameters.put("username", "foo");
        parameters.put("password", "bar");
        parameters.put("client_id", clientId);

        tokenRequest = requestFactory.createTokenRequest(parameters, clientDetails);
    }

    @Test
    @Disabled("since 2024-05-08")
    void testSunnyDay() {
        ResourceOwnerPasswordTokenGranter granter = new ResourceOwnerPasswordTokenGranter(authenticationManager,
                providerTokenServices, clientDetailsService, requestFactory);
        OAuth2AccessToken token = granter.grant("password", tokenRequest);
        OAuth2Authentication authentication = providerTokenServices.loadAuthentication(token.getValue());
        assertThat(authentication.isAuthenticated()).isTrue();
    }

    @Test
    @Disabled("since 2024-05-08")
    void testPasswordRemoved() {
        ResourceOwnerPasswordTokenGranter granter = new ResourceOwnerPasswordTokenGranter(authenticationManager,
                providerTokenServices, clientDetailsService, requestFactory);
        OAuth2AccessToken token = granter.grant("password", tokenRequest);
        OAuth2Authentication authentication = providerTokenServices.loadAuthentication(token.getValue());
        assertThat(authentication.getOAuth2Request().getRequestParameters()).containsKey("username")
                .doesNotContainKey("password");
    }

    @Test
    void extraParameters() {
        authenticationManager = new AuthenticationManager() {
            @Override
            public Authentication authenticate(Authentication authentication) throws AuthenticationException {
                if (authentication instanceof UsernamePasswordAuthenticationToken user) {
                    user = new UsernamePasswordAuthenticationToken(user.getPrincipal(), "N/A",
                            AuthorityUtils.commaSeparatedStringToAuthorityList("ROLE_USER"));
                    @SuppressWarnings("unchecked")
                    Map<String, String> details = (Map<String, String>) authentication.getDetails();
                    assertThat(details.get("password")).isNull();
                    return user;
                }
                return authentication;
            }
        };
        ResourceOwnerPasswordTokenGranter granter = new ResourceOwnerPasswordTokenGranter(authenticationManager,
                providerTokenServices, clientDetailsService, requestFactory);
        assertThatExceptionOfType(NullPointerException.class).isThrownBy(() ->
                granter.grant("password", tokenRequest));
    }

    @Test
    void badCredentials() {
        ResourceOwnerPasswordTokenGranter granter = new ResourceOwnerPasswordTokenGranter(new AuthenticationManager() {
            public Authentication authenticate(Authentication authentication) throws AuthenticationException {
                throw new BadCredentialsException("test");
            }
        }, providerTokenServices, clientDetailsService, requestFactory);
        assertThatExceptionOfType(InvalidGrantException.class).isThrownBy(() ->
                granter.grant("password", tokenRequest));
    }

    @Test
    void grantTypeNotSupported() {
        ResourceOwnerPasswordTokenGranter granter = new ResourceOwnerPasswordTokenGranter(authenticationManager,
                providerTokenServices, clientDetailsService, requestFactory);
        client.setAuthorizedGrantTypes(Collections.singleton("client_credentials"));
        assertThatExceptionOfType(InvalidClientException.class).isThrownBy(() ->
                granter.grant("password", tokenRequest));
    }

    @Test
    void accountLocked() {
        ResourceOwnerPasswordTokenGranter granter = new ResourceOwnerPasswordTokenGranter(new AuthenticationManager() {
            public Authentication authenticate(Authentication authentication) throws AuthenticationException {
                throw new LockedException("test");
            }
        }, providerTokenServices, clientDetailsService, requestFactory);
        assertThatExceptionOfType(InvalidGrantException.class).isThrownBy(() ->
                granter.grant("password", tokenRequest));
    }

    @Test
    void unauthenticated() {
        validUser = new UsernamePasswordAuthenticationToken("foo", "bar");
        ResourceOwnerPasswordTokenGranter granter = new ResourceOwnerPasswordTokenGranter(authenticationManager,
                providerTokenServices, clientDetailsService, requestFactory);
        assertThatExceptionOfType(InvalidGrantException.class).isThrownBy(() ->
                granter.grant("password", tokenRequest));
    }

    @Test
    void usernameNotFound() {
        ResourceOwnerPasswordTokenGranter granter = new ResourceOwnerPasswordTokenGranter(new AuthenticationManager() {
            @Override
            public Authentication authenticate(final Authentication authentication) throws AuthenticationException {
                throw new UsernameNotFoundException("test");
            }
        }, providerTokenServices, clientDetailsService, requestFactory);
        assertThatExceptionOfType(InvalidGrantException.class).isThrownBy(() ->
                granter.grant("password", tokenRequest));
    }
}

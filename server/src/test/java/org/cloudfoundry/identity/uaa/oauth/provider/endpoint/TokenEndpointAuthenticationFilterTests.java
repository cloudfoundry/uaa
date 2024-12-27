package org.cloudfoundry.identity.uaa.oauth.provider.endpoint;

import org.cloudfoundry.identity.uaa.client.UaaClientDetails;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.OAuth2Exception;
import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetails;
import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetailsService;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Authentication;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2RequestFactory;
import org.cloudfoundry.identity.uaa.oauth.provider.error.OAuth2AuthenticationEntryPoint;
import org.cloudfoundry.identity.uaa.oauth.provider.request.DefaultOAuth2RequestFactory;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

/**
 * Moved test class of from spring-security-oauth2 into UAA
 * Scope: Test class
 */
public class TokenEndpointAuthenticationFilterTests {

    private final MockHttpServletRequest request = new MockHttpServletRequest();

    private final MockHttpServletResponse response = new MockHttpServletResponse();

    private final MockFilterChain chain = new MockFilterChain();

    private final AuthenticationManager authenticationManager = Mockito.mock(AuthenticationManager.class);

    private final UaaClientDetails client = new UaaClientDetails("foo", "resource", "scope", "authorization_code",
            "ROLE_CLIENT");

    private final ClientDetailsService clientDetailsService = new ClientDetailsService() {
        public ClientDetails loadClientByClientId(String clientId) throws OAuth2Exception {
            return client;
        }
    };

    private final OAuth2RequestFactory oAuth2RequestFactory = new DefaultOAuth2RequestFactory(clientDetailsService);

    @Before
    public void init() {
        SecurityContextHolder.clearContext();
        SecurityContextHolder.getContext().setAuthentication(
                new UsernamePasswordAuthenticationToken("client", "secret", AuthorityUtils
                        .commaSeparatedStringToAuthorityList("ROLE_CLIENT")));
    }

    @After
    public void close() {
        SecurityContextHolder.clearContext();
    }

    @Test
    public void testPasswordGrant() throws Exception {
        request.setParameter("grant_type", "password");
        request.setParameter("client_id", "foo");
        when(authenticationManager.authenticate(Mockito.any())).thenReturn(
                new UsernamePasswordAuthenticationToken("foo", "bar", AuthorityUtils
                        .commaSeparatedStringToAuthorityList("ROLE_USER")));
        TokenEndpointAuthenticationFilter filter = new TokenEndpointAuthenticationFilter(authenticationManager, oAuth2RequestFactory);
        filter.doFilter(request, response, chain);
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        assertTrue(authentication instanceof OAuth2Authentication);
        assertTrue(authentication.isAuthenticated());
    }

    @Test
    public void testPasswordGrantWithUnAuthenticatedClient() throws Exception {
        SecurityContextHolder.getContext().setAuthentication(
                new UsernamePasswordAuthenticationToken("client", "secret"));
        request.setParameter("grant_type", "password");
        when(authenticationManager.authenticate(Mockito.any())).thenReturn(
                new UsernamePasswordAuthenticationToken("foo", "bar", AuthorityUtils
                        .commaSeparatedStringToAuthorityList("ROLE_USER")));
        TokenEndpointAuthenticationFilter filter = new TokenEndpointAuthenticationFilter(authenticationManager, oAuth2RequestFactory);
        filter.doFilter(request, response, chain);
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        assertTrue(authentication instanceof OAuth2Authentication);
        assertFalse(authentication.isAuthenticated());
    }

    @Test
    public void testNoGrantType() throws Exception {
        TokenEndpointAuthenticationFilter filter = new TokenEndpointAuthenticationFilter(authenticationManager, oAuth2RequestFactory);
        filter.doFilter(request, response, chain);
        // Just the client
        assertTrue(SecurityContextHolder.getContext().getAuthentication() instanceof UsernamePasswordAuthenticationToken);
    }

    @Test
    public void testFilterException() throws Exception {
        SecurityContextHolder.getContext().setAuthentication(
                new UsernamePasswordAuthenticationToken("client", "secret"));
        request.setParameter("grant_type", "password");
        TokenEndpointAuthenticationFilter filter = new TokenEndpointAuthenticationFilter(authenticationManager, oAuth2RequestFactory);
        filter.setAuthenticationDetailsSource(new WebAuthenticationDetailsSource());
        filter.setAuthenticationEntryPoint(new OAuth2AuthenticationEntryPoint());
        when(authenticationManager.authenticate(any())).thenThrow(new BadCredentialsException(""));
        filter.doFilter(request, response, chain);
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        assertNull(authentication);
    }
}

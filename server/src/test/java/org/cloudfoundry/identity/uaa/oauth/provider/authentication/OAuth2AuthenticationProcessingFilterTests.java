package org.cloudfoundry.identity.uaa.oauth.provider.authentication;

import org.cloudfoundry.identity.uaa.oauth.common.OAuth2AccessToken;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.InvalidTokenException;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Authentication;
import org.cloudfoundry.identity.uaa.oauth.provider.RequestTokenFactory;
import org.cloudfoundry.identity.uaa.oauth.provider.error.OAuth2AuthenticationEntryPoint;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.AuthenticationEventPublisher;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;

import jakarta.servlet.FilterChain;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Moved test class of from spring-security-oauth2 into UAA
 * Scope: Test class
 */
class OAuth2AuthenticationProcessingFilterTests {

    private final OAuth2AuthenticationProcessingFilter filter = new OAuth2AuthenticationProcessingFilter();

    private final MockHttpServletRequest request = new MockHttpServletRequest();

    private final MockHttpServletResponse response = new MockHttpServletResponse();

    private final Authentication userAuthentication = new UsernamePasswordAuthenticationToken("marissa", "koala");

    private final OAuth2Authentication authentication = new OAuth2Authentication(RequestTokenFactory.createOAuth2Request(
            null, "foo", null, false, null, null, null, null, null), userAuthentication);

    private final FilterChain chain = Mockito.mock(FilterChain.class);

    {
        filter.setAuthenticationManager(new AuthenticationManager() {

            public Authentication authenticate(Authentication request) throws AuthenticationException {
                if ("BAD".equals(request.getPrincipal())) {
                    throw new InvalidTokenException("Invalid token");
                }
                authentication.setDetails(request.getDetails());
                return authentication;
            }
        });
    }

    @AfterEach
    void clear() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void detailsAdded() throws Exception {
        request.addHeader("Authorization", "Bearer FOO");
        filter.doFilter(request, null, chain);
        assertThat(request.getAttribute(OAuth2AuthenticationDetails.ACCESS_TOKEN_VALUE)).isNotNull();
        assertThat(request.getAttribute(OAuth2AuthenticationDetails.ACCESS_TOKEN_TYPE)).isEqualTo("Bearer");
        Authentication result = SecurityContextHolder.getContext().getAuthentication();
        assertThat(result).isEqualTo(authentication);
        assertThat(result.getDetails()).isNotNull();
    }

    @Test
    void detailsSetter() {
        filter.setAuthenticationEntryPoint(new OAuth2AuthenticationEntryPoint());
        filter.setAuthenticationDetailsSource(new OAuth2AuthenticationDetailsSource());
        filter.setTokenExtractor(new BearerTokenExtractor());
        filter.afterPropertiesSet();
        assertThat(filter.getClass()).isNotNull();
    }

    @Test
    void detailsAddedWithForm() throws Exception {
        request.addParameter("access_token", "FOO");
        filter.doFilter(request, null, chain);
        assertThat(request.getAttribute(OAuth2AuthenticationDetails.ACCESS_TOKEN_VALUE)).isNotNull();
        assertThat(request.getAttribute(OAuth2AuthenticationDetails.ACCESS_TOKEN_TYPE)).isEqualTo(OAuth2AccessToken.BEARER_TYPE);
        Authentication result = SecurityContextHolder.getContext().getAuthentication();
        assertThat(result).isEqualTo(authentication);
        assertThat(result.getDetails()).isNotNull();
    }

    @Test
    void stateless() throws Exception {
        SecurityContextHolder.getContext().setAuthentication(
                new UsernamePasswordAuthenticationToken("FOO", "foo", AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS")));
        filter.doFilter(request, null, chain);
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
    }

    @Test
    void statelessPreservesAnonymous() throws Exception {
        SecurityContextHolder.getContext().setAuthentication(
                new AnonymousAuthenticationToken("FOO", "foo", AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS")));
        filter.doFilter(request, null, chain);
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNotNull();
    }

    @Test
    void stateful() throws Exception {
        filter.setStateless(false);
        SecurityContextHolder.getContext().setAuthentication(
                new UsernamePasswordAuthenticationToken("FOO", "foo", AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS")));
        filter.doFilter(request, null, chain);
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNotNull();
    }

    @Test
    void noEventsPublishedWithNoToken() throws Exception {
        AuthenticationEventPublisher eventPublisher = Mockito.mock(AuthenticationEventPublisher.class);
        filter.setAuthenticationEventPublisher(eventPublisher);
        filter.doFilter(request, null, chain);
        Mockito.verify(eventPublisher, Mockito.never()).publishAuthenticationFailure(Mockito.any(AuthenticationException.class), Mockito.any(Authentication.class));
        Mockito.verify(eventPublisher, Mockito.never()).publishAuthenticationSuccess(Mockito.any(Authentication.class));
    }

    @Test
    void successEventsPublishedWithToken() throws Exception {
        request.addHeader("Authorization", "Bearer FOO");
        AuthenticationEventPublisher eventPublisher = Mockito.mock(AuthenticationEventPublisher.class);
        filter.setAuthenticationEventPublisher(eventPublisher);
        filter.doFilter(request, null, chain);
        Mockito.verify(eventPublisher, Mockito.never()).publishAuthenticationFailure(Mockito.any(AuthenticationException.class), Mockito.any(Authentication.class));
        Mockito.verify(eventPublisher).publishAuthenticationSuccess(Mockito.any(Authentication.class));
    }

    @Test
    void failureEventsPublishedWithBadToken() throws Exception {
        request.addHeader("Authorization", "Bearer BAD");
        filter.doFilter(request, response, chain);
        AuthenticationEventPublisher eventPublisher = Mockito.mock(AuthenticationEventPublisher.class);
        filter.setAuthenticationEventPublisher(eventPublisher);
        filter.doFilter(request, response, chain);
        Mockito.verify(eventPublisher).publishAuthenticationFailure(Mockito.any(AuthenticationException.class), Mockito.any(Authentication.class));
        Mockito.verify(eventPublisher, Mockito.never()).publishAuthenticationSuccess(Mockito.any(Authentication.class));
    }
}

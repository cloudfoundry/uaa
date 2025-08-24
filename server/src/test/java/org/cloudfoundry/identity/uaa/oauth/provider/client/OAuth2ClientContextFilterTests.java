package org.cloudfoundry.identity.uaa.oauth.provider.client;

import org.cloudfoundry.identity.uaa.oauth.client.resource.UserRedirectRequiredException;
import org.cloudfoundry.identity.uaa.oauth.provider.error.DefaultThrowableAnalyzer;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.web.RedirectStrategy;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import java.io.IOException;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatExceptionOfType;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;

/**
 * Moved test class of from spring-security-oauth2 into UAA
 * Scope: Test class
 */
class OAuth2ClientContextFilterTests {

    @Test
    void testdoFilter() throws Exception {
        OAuth2ClientContextFilter filter = new OAuth2ClientContextFilter();
        RedirectStrategy redirectStrategy = mock(RedirectStrategy.class);
        filter.setRedirectStrategy(redirectStrategy);
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        filter.doFilter(request, response, mock(FilterChain.class));
    }

    @Test
    void testdoFilterIOException() throws Exception {
        OAuth2ClientContextFilter filter = new OAuth2ClientContextFilter();
        RedirectStrategy redirectStrategy = mock(RedirectStrategy.class);
        filter.setRedirectStrategy(redirectStrategy);
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain filterChain = mock(FilterChain.class);
        doThrow(new IOException("")).when(filterChain).doFilter(any(), any());
        filter.setThrowableAnalyzer(new DefaultThrowableAnalyzer());
        filter.afterPropertiesSet();
        assertThatExceptionOfType(IOException.class).isThrownBy(() ->
                filter.doFilter(request, response, filterChain));
    }

    @Test
    void testdoFilterException() throws Exception {
        OAuth2ClientContextFilter filter = new OAuth2ClientContextFilter();
        RedirectStrategy redirectStrategy = mock(RedirectStrategy.class);
        filter.setRedirectStrategy(redirectStrategy);
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain filterChain = mock(FilterChain.class);
        doThrow(new IllegalArgumentException("")).when(filterChain).doFilter(any(), any());
        filter.setThrowableAnalyzer(new DefaultThrowableAnalyzer());
        filter.afterPropertiesSet();
        assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() ->
                filter.doFilter(request, response, filterChain));
    }

    @Test
    void testdoFilterServletException() throws Exception {
        OAuth2ClientContextFilter filter = new OAuth2ClientContextFilter();
        RedirectStrategy redirectStrategy = mock(RedirectStrategy.class);
        filter.setRedirectStrategy(redirectStrategy);
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain filterChain = mock(FilterChain.class);
        doThrow(new ServletException("")).when(filterChain).doFilter(any(), any());
        filter.setThrowableAnalyzer(new DefaultThrowableAnalyzer());
        filter.afterPropertiesSet();
        assertThatExceptionOfType(ServletException.class).isThrownBy(() ->
                filter.doFilter(request, response, filterChain));
    }

    @Test
    void testdoFilterUserRedirectRequiredException() throws Exception {
        OAuth2ClientContextFilter filter = new OAuth2ClientContextFilter();
        RedirectStrategy redirectStrategy = mock(RedirectStrategy.class);
        filter.setRedirectStrategy(redirectStrategy);
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain filterChain = mock(FilterChain.class);
        String redirect = "https://example.com/authorize";
        Map<String, String> params = new LinkedHashMap<>();
        params.put("foo", "bar");
        params.put("scope", "spam");
        UserRedirectRequiredException exception = new UserRedirectRequiredException(
                redirect, params);
        exception.setStateKey("state");
        doThrow(exception).when(filterChain).doFilter(any(), any());
        filter.setThrowableAnalyzer(new DefaultThrowableAnalyzer());
        filter.afterPropertiesSet();
        filter.doFilter(request, response, filterChain);
        Mockito.verify(redirectStrategy)
                .sendRedirect(request, response, redirect + "?foo=bar&scope=spam&state=state");
    }

    @Test
    void vanillaRedirectUri() throws Exception {
        String redirect = "https://example.com/authorize";
        Map<String, String> params = new LinkedHashMap<>();
        params.put("foo", "bar");
        params.put("scope", "spam");
        testRedirectUri(redirect, params, redirect + "?foo=bar&scope=spam");
    }

    @Test
    void twoScopesRedirectUri() throws Exception {
        String redirect = "https://example.com/authorize";
        Map<String, String> params = new LinkedHashMap<>();
        params.put("foo", "bar");
        params.put("scope", "spam scope2");
        testRedirectUri(redirect, params, redirect + "?foo=bar&scope=spam%20scope2");
    }

    @Test
    void redirectUriWithUrlInParams() throws Exception {
        String redirect = "https://example.com/authorize";
        Map<String, String> params = Collections.singletonMap("redirect",
                "https://foo/bar");
        testRedirectUri(redirect, params, redirect + "?redirect=https://foo/bar");
    }

    @Test
    void redirectUriWithQuery() throws Exception {
        String redirect = "https://example.com/authorize?foo=bar";
        Map<String, String> params = Collections.singletonMap("spam",
                "bucket");
        testRedirectUri(redirect, params, redirect + "&spam=bucket");
    }

    public void testRedirectUri(String redirect, Map<String, String> params,
                                String result) throws Exception {
        OAuth2ClientContextFilter filter = new OAuth2ClientContextFilter();
        RedirectStrategy redirectStrategy = mock(RedirectStrategy.class);
        filter.setRedirectStrategy(redirectStrategy);
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        UserRedirectRequiredException exception = new UserRedirectRequiredException(
                redirect, params);
        filter.redirectUser(exception, request, response);
        Mockito.verify(redirectStrategy)
                .sendRedirect(request, response, result);
    }

    @Test
    void vanillaCurrentUri() {
        OAuth2ClientContextFilter filter = new OAuth2ClientContextFilter();
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setQueryString("foo=bar");
        assertThat(filter.calculateCurrentUri(request)).isEqualTo("http://localhost?foo=bar");
    }

    @Test
    void currentUriWithLegalSpaces() {
        OAuth2ClientContextFilter filter = new OAuth2ClientContextFilter();
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setQueryString("foo=bar%20spam");
        assertThat(filter.calculateCurrentUri(request)).isEqualTo("http://localhost?foo=bar%20spam");
    }

    @Test
    void currentUriWithNoQuery() {
        OAuth2ClientContextFilter filter = new OAuth2ClientContextFilter();
        MockHttpServletRequest request = new MockHttpServletRequest();
        assertThat(filter.calculateCurrentUri(request)).isEqualTo("http://localhost");
    }

    @Test
    void currentUriWithIllegalSpaces() {
        OAuth2ClientContextFilter filter = new OAuth2ClientContextFilter();
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setQueryString("foo=bar+spam");
        assertThat(filter.calculateCurrentUri(request)).isEqualTo("http://localhost?foo=bar+spam");
    }

    @Test
    void currentUriRemovingCode() {
        OAuth2ClientContextFilter filter = new OAuth2ClientContextFilter();
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setQueryString("code=XXXX&foo=bar");
        assertThat(filter.calculateCurrentUri(request)).isEqualTo("http://localhost?foo=bar");
    }

    @Test
    void currentUriRemovingCodeInSecond() {
        OAuth2ClientContextFilter filter = new OAuth2ClientContextFilter();
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setQueryString("foo=bar&code=XXXX");
        assertThat(filter.calculateCurrentUri(request)).isEqualTo("http://localhost?foo=bar");
    }

    @Test
    void currentUriWithInvalidQueryString() {
        OAuth2ClientContextFilter filter = new OAuth2ClientContextFilter();
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setQueryString("foo=bar&code=XXXX&parm=%xx");
        try {
            assertThat(filter.calculateCurrentUri(request)).isNull();
        } catch (IllegalStateException ex) {
            // OAuth2ClientContextFilter.calculateCurrentUri() internally uses
            // ServletUriComponentsBuilder.fromRequest(), which behaves differently in Spring Framework 5
            // and throws an IllegalStateException for a malformed URI.
            // Previously to Spring Framework 5, 'null' would be returned by OAuth2ClientContextFilter.calculateCurrentUri()
            // instead of the thrown IllegalStateException.
        }
    }
}

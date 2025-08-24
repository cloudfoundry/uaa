package org.cloudfoundry.identity.uaa.oauth.provider.endpoint;

import org.cloudfoundry.identity.uaa.client.UaaClientDetails;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.InvalidGrantException;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.InvalidRequestException;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.RedirectMismatchException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatExceptionOfType;

/**
 * Moved test class of from spring-security-oauth2 into UAA
 * Scope: Test class
 */
class DefaultRedirectResolverTests {

    private DefaultRedirectResolver resolver;

    private UaaClientDetails client;

    @BeforeEach
    void setup() {
        client = new UaaClientDetails();
        client.setAuthorizedGrantTypes(Collections.singleton("authorization_code"));
        resolver = new DefaultRedirectResolver();
    }

    @Test
    void redirectMatchesRegisteredValue() {
        Set<String> redirectUris = new HashSet<>(List.of("https://anywhere.com"));
        client.setRegisteredRedirectUri(redirectUris);
        String requestedRedirect = "https://anywhere.com";
        assertThat(resolver.resolveRedirect(requestedRedirect, client)).isEqualTo(requestedRedirect);
    }

    @Test
    void redirectWithNoRegisteredValue() {
        String requestedRedirect = "https://anywhere.com/myendpoint";
        assertThatExceptionOfType(InvalidRequestException.class).isThrownBy(() ->
                resolver.resolveRedirect(requestedRedirect, client));
    }

    // If only one redirect has been registered, then we should use it
    @Test
    void redirectWithNoRequestedValue() {
        Set<String> redirectUris = new HashSet<>(List.of("https://anywhere.com"));
        client.setRegisteredRedirectUri(redirectUris);
        resolver.resolveRedirect(null, client);
    }

    // If multiple redirects registered, then we should get an exception
    @Test
    void redirectWithNoRequestedValueAndMultipleRegistered() {
        Set<String> redirectUris = new HashSet<>(List.of("https://anywhere.com", "https://nowhere.com"));
        client.setRegisteredRedirectUri(redirectUris);
        assertThatExceptionOfType(RedirectMismatchException.class).isThrownBy(() ->
                resolver.resolveRedirect(null, client));
    }

    @Test
    void noGrantType() {
        Set<String> redirectUris = new HashSet<>(List.of("https://anywhere.com", "https://nowhere.com"));
        client.setRegisteredRedirectUri(redirectUris);
        client.setAuthorizedGrantTypes(Collections.<String>emptyList());
        assertThatExceptionOfType(InvalidGrantException.class).isThrownBy(() ->
                resolver.resolveRedirect(null, client));
    }

    @Test
    void wrongGrantType() {
        Set<String> redirectUris = new HashSet<>(List.of("https://anywhere.com", "https://nowhere.com"));
        client.setRegisteredRedirectUri(redirectUris);
        client.setAuthorizedGrantTypes(Collections.singleton("client_credentials"));
        assertThatExceptionOfType(InvalidGrantException.class).isThrownBy(() ->
                resolver.resolveRedirect(null, client));
    }

    @Test
    void wrongCustomGrantType() {
        resolver.setRedirectGrantTypes(Collections.singleton("foo"));
        Set<String> redirectUris = new HashSet<>(List.of("https://anywhere.com", "https://nowhere.com"));
        client.setRegisteredRedirectUri(redirectUris);
        assertThatExceptionOfType(InvalidGrantException.class).isThrownBy(() ->
                resolver.resolveRedirect(null, client));
    }

    @Test
    void redirectNotMatching() {
        Set<String> redirectUris = new HashSet<>(List.of("https://nowhere.com"));
        String requestedRedirect = "https://anywhere.com/myendpoint";
        client.setRegisteredRedirectUri(redirectUris);
        assertThatExceptionOfType(RedirectMismatchException.class).isThrownBy(() ->
                assertThat(resolver.resolveRedirect(requestedRedirect, client)).isEqualTo(redirectUris.iterator().next()));
    }

    @Test
    void redirectNotMatchingWithTraversal() {
        Set<String> redirectUris = new HashSet<>(List.of("https://anywhere.com/foo"));
        String requestedRedirect = "https://anywhere.com/foo/../bar";
        client.setRegisteredRedirectUri(redirectUris);
        assertThatExceptionOfType(RedirectMismatchException.class).isThrownBy(() ->
                assertThat(resolver.resolveRedirect(requestedRedirect, client)).isEqualTo(redirectUris.iterator().next()));
    }

    // gh-1331
    @Test
    void redirectNotMatchingWithHexEncodedTraversal() {
        Set<String> redirectUris = new HashSet<>(List.of("https://anywhere.com/foo"));
        client.setRegisteredRedirectUri(redirectUris);
        String requestedRedirect = "https://anywhere.com/foo/%2E%2E";
        assertThatExceptionOfType(RedirectMismatchException.class).isThrownBy(() ->    // hexadecimal encoding of '..' represents '%2E%2E'
                resolver.resolveRedirect(requestedRedirect, client));
    }

    // gh-747
    @Test
    void redirectNotMatchingSubdomain() {
        Set<String> redirectUris = new HashSet<>(List.of("https://anywhere.com/foo"));
        client.setRegisteredRedirectUri(redirectUris);
        assertThatExceptionOfType(RedirectMismatchException.class).isThrownBy(() ->
                resolver.resolveRedirect("https://2anywhere.com/foo", client));
    }

    // gh-747
    // gh-747
    @Test
    void redirectMatchingSubdomain() {
        resolver.setMatchSubdomains(true);
        Set<String> redirectUris = new HashSet<>(List.of("https://anywhere.com/foo"));
        String requestedRedirect = "https://2.anywhere.com/foo";
        client.setRegisteredRedirectUri(redirectUris);
        assertThat(resolver.resolveRedirect(requestedRedirect, client)).isEqualTo(requestedRedirect);
    }

    @Test
    void redirectMatchSubdomainsDefaultsFalse() {
        Set<String> redirectUris = new HashSet<>(List.of("https://anywhere.com"));
        client.setRegisteredRedirectUri(redirectUris);
        assertThatExceptionOfType(RedirectMismatchException.class).isThrownBy(() ->
                resolver.resolveRedirect("https://2.anywhere.com", client));
    }

    // gh-746
    @Test
    void redirectNotMatchingPort() {
        Set<String> redirectUris = new HashSet<>(List.of("https://anywhere.com:90"));
        client.setRegisteredRedirectUri(redirectUris);
        assertThatExceptionOfType(RedirectMismatchException.class).isThrownBy(() ->
                resolver.resolveRedirect("https://anywhere.com:91/foo", client));
    }

    // gh-746
    @Test
    void redirectMatchingPort() {
        Set<String> redirectUris = new HashSet<>(List.of("https://anywhere.com:90"));
        client.setRegisteredRedirectUri(redirectUris);
        String requestedRedirect = "https://anywhere.com:90";
        assertThat(resolver.resolveRedirect(requestedRedirect, client)).isEqualTo(requestedRedirect);
    }

    // gh-746
    @Test
    void redirectRegisteredPortSetRequestedPortNotSet() {
        Set<String> redirectUris = new HashSet<>(List.of("https://anywhere.com:90"));
        client.setRegisteredRedirectUri(redirectUris);
        assertThatExceptionOfType(RedirectMismatchException.class).isThrownBy(() ->
                resolver.resolveRedirect("https://anywhere.com/foo", client));
    }

    // gh-746
    @Test
    void redirectRegisteredPortNotSetRequestedPortSet() {
        Set<String> redirectUris = new HashSet<>(List.of("https://anywhere.com"));
        client.setRegisteredRedirectUri(redirectUris);
        assertThatExceptionOfType(RedirectMismatchException.class).isThrownBy(() ->
                resolver.resolveRedirect("https://anywhere.com:8443/foo", client));
    }

    // gh-746
    @Test
    void redirectMatchPortsFalse() {
        resolver.setMatchPorts(false);
        Set<String> redirectUris = new HashSet<>(List.of("https://anywhere.com:90"));
        client.setRegisteredRedirectUri(redirectUris);
        String requestedRedirect = "https://anywhere.com:90";
        assertThat(resolver.resolveRedirect(requestedRedirect, client)).isEqualTo(requestedRedirect);
    }

    // gh-1386
    @Test
    void redirectNotMatchingReturnsGenericErrorMessage() {
        Set<String> redirectUris = new HashSet<>(List.of("https://nowhere.com"));
        String requestedRedirect = "https://anywhere.com/myendpoint";
        client.setRegisteredRedirectUri(redirectUris);
        try {
            resolver.resolveRedirect(requestedRedirect, client);
            fail("");
        } catch (RedirectMismatchException ex) {
            assertThat(ex.getMessage()).isEqualTo("Invalid redirect uri does not match one of the registered values.");
        }
    }

    // gh-1566
    @Test
    void redirectRegisteredUserInfoNotMatching() {
        Set<String> redirectUris = new HashSet<>(List.of("https://userinfo@anywhere.com"));
        client.setRegisteredRedirectUri(redirectUris);
        assertThatExceptionOfType(RedirectMismatchException.class).isThrownBy(() ->
                resolver.resolveRedirect("https://otheruserinfo@anywhere.com", client));
    }

    // gh-1566
    @Test
    void redirectRegisteredNoUserInfoNotMatching() {
        Set<String> redirectUris = new HashSet<>(List.of("https://userinfo@anywhere.com"));
        client.setRegisteredRedirectUri(redirectUris);
        assertThatExceptionOfType(RedirectMismatchException.class).isThrownBy(() ->
                resolver.resolveRedirect("https://anywhere.com", client));
    }

    // gh-1566
    @Test
    void redirectRegisteredUserInfoMatching() {
        Set<String> redirectUris = new HashSet<>(List.of("https://userinfo@anywhere.com"));
        client.setRegisteredRedirectUri(redirectUris);
        String requestedRedirect = "https://userinfo@anywhere.com";
        assertThat(resolver.resolveRedirect(requestedRedirect, client)).isEqualTo(requestedRedirect);
    }

    // gh-1566
    @Test
    void redirectRegisteredFragmentIgnoredAndStripped() {
        Set<String> redirectUris = new HashSet<>(List.of("https://userinfo@anywhere.com/foo/bar#baz"));
        client.setRegisteredRedirectUri(redirectUris);
        String requestedRedirect = "https://userinfo@anywhere.com/foo/bar";
        assertThat(resolver.resolveRedirect(requestedRedirect + "#bar", client)).isEqualTo(requestedRedirect);
    }

    // gh-1566
    @Test
    void redirectRegisteredQueryParamsMatching() {
        Set<String> redirectUris = new HashSet<>(List.of("https://anywhere.com/?p1=v1&p2=v2"));
        client.setRegisteredRedirectUri(redirectUris);
        String requestedRedirect = "https://anywhere.com/?p1=v1&p2=v2";
        assertThat(resolver.resolveRedirect(requestedRedirect, client)).isEqualTo(requestedRedirect);
    }

    // gh-1566
    @Test
    void redirectRegisteredQueryParamsMatchingIgnoringAdditionalParams() {
        Set<String> redirectUris = new HashSet<>(List.of("https://anywhere.com/?p1=v1&p2=v2"));
        client.setRegisteredRedirectUri(redirectUris);
        String requestedRedirect = "https://anywhere.com/?p1=v1&p2=v2&p3=v3";
        assertThat(resolver.resolveRedirect(requestedRedirect, client)).isEqualTo(requestedRedirect);
    }

    // gh-1566
    @Test
    void redirectRegisteredQueryParamsMatchingDifferentOrder() {
        Set<String> redirectUris = new HashSet<>(List.of("https://anywhere.com/?p1=v1&p2=v2"));
        client.setRegisteredRedirectUri(redirectUris);
        String requestedRedirect = "https://anywhere.com/?p2=v2&p1=v1";
        assertThat(resolver.resolveRedirect(requestedRedirect, client)).isEqualTo(requestedRedirect);
    }

    // gh-1566
    @Test
    void redirectRegisteredQueryParamsWithDifferentValues() {
        Set<String> redirectUris = new HashSet<>(List.of("https://anywhere.com/?p1=v1&p2=v2"));
        client.setRegisteredRedirectUri(redirectUris);
        assertThatExceptionOfType(RedirectMismatchException.class).isThrownBy(() ->
                resolver.resolveRedirect("https://anywhere.com/?p1=v1&p2=v3", client));
    }

    // gh-1566
    @Test
    void redirectRegisteredQueryParamsNotMatching() {
        Set<String> redirectUris = new HashSet<>(List.of("https://anywhere.com/?p1=v1"));
        client.setRegisteredRedirectUri(redirectUris);
        assertThatExceptionOfType(RedirectMismatchException.class).isThrownBy(() ->
                resolver.resolveRedirect("https://anywhere.com/?p2=v2", client));
    }

    // gh-1566
    @Test
    void redirectRegisteredQueryParamsPartiallyMatching() {
        Set<String> redirectUris = new HashSet<>(List.of("https://anywhere.com/?p1=v1&p2=v2"));
        client.setRegisteredRedirectUri(redirectUris);
        assertThatExceptionOfType(RedirectMismatchException.class).isThrownBy(() ->
                resolver.resolveRedirect("https://anywhere.com/?p2=v2&p3=v3", client));
    }

    // gh-1566
    @Test
    void redirectRegisteredQueryParamsMatchingWithMultipleValuesInRegistered() {
        Set<String> redirectUris = new HashSet<>(List.of("https://anywhere.com/?p1=v11&p1=v12"));
        client.setRegisteredRedirectUri(redirectUris);
        String requestedRedirect = "https://anywhere.com/?p1=v11&p1=v12";
        assertThat(resolver.resolveRedirect(requestedRedirect, client)).isEqualTo(requestedRedirect);
    }

    // gh-1566
    @Test
    void redirectRegisteredQueryParamsMatchingWithParamWithNoValue() {
        Set<String> redirectUris = new HashSet<>(List.of("https://anywhere.com/?p1&p2=v2"));
        client.setRegisteredRedirectUri(redirectUris);
        String requestedRedirect = "https://anywhere.com/?p1&p2=v2";
        assertThat(resolver.resolveRedirect(requestedRedirect, client)).isEqualTo(requestedRedirect);
    }

    // gh-1618
    @Test
    void redirectNoHost() {
        Set<String> redirectUris = new HashSet<>(List.of("scheme:/path"));
        client.setRegisteredRedirectUri(redirectUris);
        String requestedRedirect = "scheme:/path";
        assertThat(resolver.resolveRedirect(requestedRedirect, client)).isEqualTo(requestedRedirect);
    }
}

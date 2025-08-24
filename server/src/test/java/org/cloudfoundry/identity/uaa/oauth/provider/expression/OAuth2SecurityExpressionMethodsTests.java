package org.cloudfoundry.identity.uaa.oauth.provider.expression;

import org.cloudfoundry.identity.uaa.client.UaaClientDetails;
import org.cloudfoundry.identity.uaa.oauth.provider.AuthorizationRequest;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Authentication;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Request;
import org.cloudfoundry.identity.uaa.oauth.provider.RequestTokenFactory;
import org.junit.jupiter.api.Test;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatExceptionOfType;

/**
 * Moved test class of from spring-security-oauth2 into UAA
 * Scope: Test class
 */
class OAuth2SecurityExpressionMethodsTests {

    @Test
    void oauthClient() throws Exception {
        AuthorizationRequest request = new AuthorizationRequest("foo",
                Collections.singleton("read"));
        request
                .setResourceIdsAndAuthoritiesFromClientDetails(new UaaClientDetails("foo", "", "", "client_credentials", "ROLE_CLIENT"));
        Authentication userAuthentication = null;

        OAuth2Request clientAuthentication = RequestTokenFactory.createOAuth2Request(request.getRequestParameters(), request.getClientId(), request.getAuthorities(), request.isApproved(), request.getScope(), request.getResourceIds(),
                request.getRedirectUri(), request.getResponseTypes(), request.getExtensions());

        OAuth2Authentication oAuth2Authentication = new OAuth2Authentication(clientAuthentication, userAuthentication);
        assertThat(new OAuth2SecurityExpressionMethods(oAuth2Authentication).clientHasAnyRole("ROLE_CLIENT")).isTrue();
    }

    @Test
    void scopes() {
        OAuth2Request clientAuthentication = RequestTokenFactory.createOAuth2Request("foo", false, Collections.singleton("read"));

        Authentication userAuthentication = null;
        OAuth2Authentication oAuth2Authentication = new OAuth2Authentication(clientAuthentication, userAuthentication);
        OAuth2SecurityExpressionMethods root = new OAuth2SecurityExpressionMethods(oAuth2Authentication);
        assertThat(root.isOAuth()).isTrue();
        assertThat(root.denyOAuthClient()).isFalse();
        assertThat(root.clientHasRole("read")).isFalse();
        assertThat(root.hasAnyScope("read")).isTrue();
        assertThat(root.hasScope("read")).isTrue();
    }

    @Test
    void scopesFalse() throws Exception {
        OAuth2Request clientAuthentication = RequestTokenFactory.createOAuth2Request("foo", false, Collections.singleton("read"));

        Authentication userAuthentication = null;
        OAuth2Authentication oAuth2Authentication = new OAuth2Authentication(clientAuthentication, userAuthentication);
        OAuth2SecurityExpressionMethods root = new OAuth2SecurityExpressionMethods(oAuth2Authentication);
        assertThat(root.hasAnyScope("write")).isFalse();
    }

    @Test
    void scopesWithException() {
        OAuth2Request clientAuthentication = RequestTokenFactory.createOAuth2Request("foo", false, Collections.singleton("read"));
        Authentication userAuthentication = null;
        OAuth2Authentication oAuth2Authentication = new OAuth2Authentication(clientAuthentication, userAuthentication);
        OAuth2SecurityExpressionMethods root = new OAuth2SecurityExpressionMethods(oAuth2Authentication);
        boolean hasAnyScope = root.hasAnyScope("foo");
        assertThatExceptionOfType(AccessDeniedException.class).isThrownBy(() ->
                assertThat(root.throwOnError(hasAnyScope)).isFalse());
    }

    @Test
    void insufficientScope() {
        OAuth2Request clientAuthentication = RequestTokenFactory.createOAuth2Request("foo", false, Collections.singleton("read"));
        Authentication userAuthentication = null;
        OAuth2Authentication oAuth2Authentication = new OAuth2Authentication(clientAuthentication, userAuthentication);
        OAuth2SecurityExpressionMethods root = new OAuth2SecurityExpressionMethods(oAuth2Authentication);
        boolean hasAnyScope = root.hasAnyScope("foo");
        assertThatExceptionOfType(AccessDeniedException.class).isThrownBy(() ->
                root.throwOnError(hasAnyScope));
    }

    @Test
    void sufficientScope() throws Exception {
        OAuth2Request clientAuthentication = RequestTokenFactory.createOAuth2Request("foo", false, Collections.singleton("read"));

        Authentication userAuthentication = null;
        OAuth2Authentication oAuth2Authentication = new OAuth2Authentication(clientAuthentication, userAuthentication);
        assertThat(new OAuth2SecurityExpressionMethods(oAuth2Authentication).hasAnyScope("read")).isTrue();
        assertThat(new OAuth2SecurityExpressionMethods(oAuth2Authentication).throwOnError(true)).isTrue();
    }

    @Test
    void sufficientScopeWithNoPreviousScopeDecision() throws Exception {
        OAuth2Request clientAuthentication = RequestTokenFactory.createOAuth2Request("foo", true, Collections.singleton("read"));

        Authentication userAuthentication = null;
        OAuth2Authentication oAuth2Authentication = new OAuth2Authentication(clientAuthentication, userAuthentication);
        assertThat(new OAuth2SecurityExpressionMethods(oAuth2Authentication).isClient()).isTrue();
        assertThat(new OAuth2SecurityExpressionMethods(oAuth2Authentication).throwOnError(false)).isFalse();
    }

    @Test
    void nonOauthClient() throws Exception {
        Authentication clientAuthentication = new UsernamePasswordAuthenticationToken("foo", "bar");
        assertThat(new OAuth2SecurityExpressionMethods(clientAuthentication).clientHasAnyRole("ROLE_USER")).isFalse();
    }

    @Test
    void clientOnly() throws Exception {
        OAuth2Request request = RequestTokenFactory.createOAuth2Request("foo", true, Collections.singleton("read"));

        Authentication userAuthentication = new UsernamePasswordAuthenticationToken("foo", "bar",
                Collections.singleton(new SimpleGrantedAuthority("ROLE_USER")));
        OAuth2Authentication oAuth2Authentication = new OAuth2Authentication(request, userAuthentication);
        assertThat(new OAuth2SecurityExpressionMethods(oAuth2Authentication).isClient()).isFalse();
        assertThat(new OAuth2SecurityExpressionMethods(new OAuth2Authentication(request, null)).isClient()).isTrue();
    }

    @Test
    void oAuthUser() throws Exception {
        OAuth2Request clientAuthentication = RequestTokenFactory.createOAuth2Request("foo", true, Collections.singleton("read"));

        Authentication userAuthentication = new UsernamePasswordAuthenticationToken("foo", "bar",
                Collections.singleton(new SimpleGrantedAuthority("ROLE_USER")));
        OAuth2Authentication oAuth2Authentication = new OAuth2Authentication(clientAuthentication, userAuthentication);
        assertThat(new OAuth2SecurityExpressionMethods(oAuth2Authentication).isUser()).isTrue();
        assertThat(new OAuth2SecurityExpressionMethods(new OAuth2Authentication(clientAuthentication, null)).isUser()).isFalse();
    }

    @Test
    void expressionUtils() {
        assertThat(OAuth2ExpressionUtils.isOAuthUserAuth(null)).isFalse();
        assertThat(OAuth2ExpressionUtils.isOAuthClientAuth(null)).isFalse();
        assertThat(OAuth2ExpressionUtils.isOAuth(null)).isFalse();
    }
}

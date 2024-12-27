package org.cloudfoundry.identity.uaa.oauth.provider.expression;

import org.cloudfoundry.identity.uaa.client.UaaClientDetails;
import org.cloudfoundry.identity.uaa.oauth.provider.AuthorizationRequest;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Authentication;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Request;
import org.cloudfoundry.identity.uaa.oauth.provider.RequestTokenFactory;
import org.junit.Test;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Collections;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * Moved test class of from spring-security-oauth2 into UAA
 * Scope: Test class
 */
public class OAuth2SecurityExpressionMethodsTests {

    @Test
    public void testOauthClient() throws Exception {
        AuthorizationRequest request = new AuthorizationRequest("foo",
                Collections.singleton("read"));
        request
                .setResourceIdsAndAuthoritiesFromClientDetails(new UaaClientDetails("foo", "", "", "client_credentials", "ROLE_CLIENT"));
        Authentication userAuthentication = null;

        OAuth2Request clientAuthentication = RequestTokenFactory.createOAuth2Request(request.getRequestParameters(), request.getClientId(), request.getAuthorities(), request.isApproved(), request.getScope(), request.getResourceIds(),
                request.getRedirectUri(), request.getResponseTypes(), request.getExtensions());

        OAuth2Authentication oAuth2Authentication = new OAuth2Authentication(clientAuthentication, userAuthentication);
        assertTrue(new OAuth2SecurityExpressionMethods(oAuth2Authentication).clientHasAnyRole("ROLE_CLIENT"));
    }

    @Test
    public void testScopes() {
        OAuth2Request clientAuthentication = RequestTokenFactory.createOAuth2Request("foo", false, Collections.singleton("read"));

        Authentication userAuthentication = null;
        OAuth2Authentication oAuth2Authentication = new OAuth2Authentication(clientAuthentication, userAuthentication);
        OAuth2SecurityExpressionMethods root = new OAuth2SecurityExpressionMethods(oAuth2Authentication);
        assertTrue(root.isOAuth());
        assertFalse(root.denyOAuthClient());
        assertFalse(root.clientHasRole("read"));
        assertTrue(root.hasAnyScope("read"));
        assertTrue(root.hasScope("read"));
    }

    @Test
    public void testScopesFalse() throws Exception {
        OAuth2Request clientAuthentication = RequestTokenFactory.createOAuth2Request("foo", false, Collections.singleton("read"));

        Authentication userAuthentication = null;
        OAuth2Authentication oAuth2Authentication = new OAuth2Authentication(clientAuthentication, userAuthentication);
        OAuth2SecurityExpressionMethods root = new OAuth2SecurityExpressionMethods(oAuth2Authentication);
        assertFalse(root.hasAnyScope("write"));
    }

    @Test(expected = AccessDeniedException.class)
    public void testScopesWithException() throws Exception {
        OAuth2Request clientAuthentication = RequestTokenFactory.createOAuth2Request("foo", false, Collections.singleton("read"));

        Authentication userAuthentication = null;
        OAuth2Authentication oAuth2Authentication = new OAuth2Authentication(clientAuthentication, userAuthentication);
        OAuth2SecurityExpressionMethods root = new OAuth2SecurityExpressionMethods(oAuth2Authentication);
        boolean hasAnyScope = root.hasAnyScope("foo");
        assertFalse(root.throwOnError(hasAnyScope));
    }

    @Test(expected = AccessDeniedException.class)
    public void testInsufficientScope() throws Exception {
        OAuth2Request clientAuthentication = RequestTokenFactory.createOAuth2Request("foo", false, Collections.singleton("read"));

        Authentication userAuthentication = null;
        OAuth2Authentication oAuth2Authentication = new OAuth2Authentication(clientAuthentication, userAuthentication);
        OAuth2SecurityExpressionMethods root = new OAuth2SecurityExpressionMethods(oAuth2Authentication);
        boolean hasAnyScope = root.hasAnyScope("foo");
        root.throwOnError(hasAnyScope);
    }

    @Test
    public void testSufficientScope() throws Exception {
        OAuth2Request clientAuthentication = RequestTokenFactory.createOAuth2Request("foo", false, Collections.singleton("read"));

        Authentication userAuthentication = null;
        OAuth2Authentication oAuth2Authentication = new OAuth2Authentication(clientAuthentication, userAuthentication);
        assertTrue(new OAuth2SecurityExpressionMethods(oAuth2Authentication).hasAnyScope("read"));
        assertTrue(new OAuth2SecurityExpressionMethods(oAuth2Authentication).throwOnError(true));
    }

    @Test
    public void testSufficientScopeWithNoPreviousScopeDecision() throws Exception {
        OAuth2Request clientAuthentication = RequestTokenFactory.createOAuth2Request("foo", true, Collections.singleton("read"));

        Authentication userAuthentication = null;
        OAuth2Authentication oAuth2Authentication = new OAuth2Authentication(clientAuthentication, userAuthentication);
        assertTrue(new OAuth2SecurityExpressionMethods(oAuth2Authentication).isClient());
        assertFalse(new OAuth2SecurityExpressionMethods(oAuth2Authentication).throwOnError(false));
    }

    @Test
    public void testNonOauthClient() throws Exception {
        Authentication clientAuthentication = new UsernamePasswordAuthenticationToken("foo", "bar");
        assertFalse(new OAuth2SecurityExpressionMethods(clientAuthentication).clientHasAnyRole("ROLE_USER"));
    }

    @Test
    public void testClientOnly() throws Exception {
        OAuth2Request request = RequestTokenFactory.createOAuth2Request("foo", true, Collections.singleton("read"));

        Authentication userAuthentication = new UsernamePasswordAuthenticationToken("foo", "bar",
                Collections.singleton(new SimpleGrantedAuthority("ROLE_USER")));
        OAuth2Authentication oAuth2Authentication = new OAuth2Authentication(request, userAuthentication);
        assertFalse(new OAuth2SecurityExpressionMethods(oAuth2Authentication).isClient());
        assertTrue(new OAuth2SecurityExpressionMethods(new OAuth2Authentication(request, null)).isClient());
    }

    @Test
    public void testOAuthUser() throws Exception {
        OAuth2Request clientAuthentication = RequestTokenFactory.createOAuth2Request("foo", true, Collections.singleton("read"));

        Authentication userAuthentication = new UsernamePasswordAuthenticationToken("foo", "bar",
                Collections.singleton(new SimpleGrantedAuthority("ROLE_USER")));
        OAuth2Authentication oAuth2Authentication = new OAuth2Authentication(clientAuthentication, userAuthentication);
        assertTrue(new OAuth2SecurityExpressionMethods(oAuth2Authentication).isUser());
        assertFalse(new OAuth2SecurityExpressionMethods(new OAuth2Authentication(clientAuthentication, null)).isUser());
    }

    @Test
    public void testExpressionUtils() {
        assertFalse(OAuth2ExpressionUtils.isOAuthUserAuth(null));
        assertFalse(OAuth2ExpressionUtils.isOAuthClientAuth(null));
        assertFalse(OAuth2ExpressionUtils.isOAuth(null));
    }
}

package org.cloudfoundry.identity.uaa.oauth.client.token.grant;

import org.cloudfoundry.identity.uaa.oauth.client.grant.ResourceOwnerPasswordAccessTokenProvider;
import org.cloudfoundry.identity.uaa.oauth.client.resource.AuthorizationCodeResourceDetails;
import org.cloudfoundry.identity.uaa.oauth.client.resource.OAuth2ProtectedResourceDetails;
import org.cloudfoundry.identity.uaa.oauth.client.resource.ResourceOwnerPasswordResourceDetails;
import org.cloudfoundry.identity.uaa.oauth.common.DefaultOAuth2AccessToken;
import org.cloudfoundry.identity.uaa.oauth.common.DefaultOAuth2RefreshToken;
import org.cloudfoundry.identity.uaa.oauth.common.OAuth2AccessToken;
import org.cloudfoundry.identity.uaa.oauth.token.AccessTokenRequest;
import org.cloudfoundry.identity.uaa.oauth.token.DefaultAccessTokenRequest;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.springframework.http.HttpHeaders;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import java.util.Collections;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

/**
 * Moved test class of from spring-security-oauth2 into UAA
 * Scope: Test class
 */
public class ResourceOwnerPasswordAccessTokenProviderTests {

    @Rule
    public ExpectedException expected = ExpectedException.none();

    private final MultiValueMap<String, String> params = new LinkedMultiValueMap<>();

    private final ResourceOwnerPasswordAccessTokenProvider provider = new ResourceOwnerPasswordAccessTokenProvider() {
        @Override
        protected OAuth2AccessToken retrieveToken(AccessTokenRequest request, OAuth2ProtectedResourceDetails resource,
                MultiValueMap<String, String> form, HttpHeaders headers) {
            params.putAll(form);
            if (!form.containsKey("username") || form.getFirst("username") == null) {
                throw new IllegalArgumentException();
            }
            // Only the map parts of the AccessTokenRequest are sent as form values
            if (form.containsKey("current_uri") || form.containsKey("currentUri")) {
                throw new IllegalArgumentException();
            }
            return new DefaultOAuth2AccessToken("FOO");
        }
    };

    private final ResourceOwnerPasswordResourceDetails resource = new ResourceOwnerPasswordResourceDetails();

    @Test
    public void supportsResource() {
        assertTrue(provider.supportsResource(new ResourceOwnerPasswordResourceDetails()));
    }

    @Test
    public void supportsRefresh() {
        assertFalse(provider.supportsRefresh(new AuthorizationCodeResourceDetails()));
    }

    @Test
    public void refreshAccessToken() {
        expected.expect(IllegalArgumentException.class);
        assertNull(provider.refreshAccessToken(new AuthorizationCodeResourceDetails(), new DefaultOAuth2RefreshToken(""), new DefaultAccessTokenRequest(
                Collections.emptyMap())));
    }

    @Test
    public void testGetAccessToken() throws Exception {
        AccessTokenRequest request = new DefaultAccessTokenRequest();
        resource.setAccessTokenUri("http://localhost/oauth/token");
        resource.setUsername("foo");
        resource.setPassword("bar");
        assertEquals("FOO", provider.obtainAccessToken(resource, request).getValue());
    }

    @Test
    public void testGetAccessTokenWithDynamicCredentials() throws Exception {
        AccessTokenRequest request = new DefaultAccessTokenRequest();
        request.set("username", "foo");
        request.set("password", "bar");
        resource.setAccessTokenUri("http://localhost/oauth/token");
        assertEquals("FOO", provider.obtainAccessToken(resource, request).getValue());
    }

    @Test
    public void testCurrentUriNotUsed() throws Exception {
        AccessTokenRequest request = new DefaultAccessTokenRequest();
        request.set("username", "foo");
        request.setCurrentUri("urn:foo:bar");
        resource.setAccessTokenUri("http://localhost/oauth/token");
        assertEquals("FOO", provider.obtainAccessToken(resource, request).getValue());
    }

}

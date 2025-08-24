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
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatExceptionOfType;

/**
 * Moved test class of from spring-security-oauth2 into UAA
 * Scope: Test class
 */
class ResourceOwnerPasswordAccessTokenProviderTests {

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
    void supportsResource() {
        assertThat(provider.supportsResource(new ResourceOwnerPasswordResourceDetails())).isTrue();
    }

    @Test
    void supportsRefresh() {
        assertThat(provider.supportsRefresh(new AuthorizationCodeResourceDetails())).isFalse();
    }

    @Test
    void refreshAccessToken() {
        assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() ->
                assertThat(provider.refreshAccessToken(new AuthorizationCodeResourceDetails(), new DefaultOAuth2RefreshToken(""), new DefaultAccessTokenRequest(
                        Collections.emptyMap()))).isNull());
    }

    @Test
    void getAccessToken() throws Exception {
        AccessTokenRequest request = new DefaultAccessTokenRequest();
        resource.setAccessTokenUri("http://localhost/oauth/token");
        resource.setUsername("foo");
        resource.setPassword("bar");
        assertThat(provider.obtainAccessToken(resource, request).getValue()).isEqualTo("FOO");
    }

    @Test
    void getAccessTokenWithDynamicCredentials() throws Exception {
        AccessTokenRequest request = new DefaultAccessTokenRequest();
        request.set("username", "foo");
        request.set("password", "bar");
        resource.setAccessTokenUri("http://localhost/oauth/token");
        assertThat(provider.obtainAccessToken(resource, request).getValue()).isEqualTo("FOO");
    }

    @Test
    void currentUriNotUsed() throws Exception {
        AccessTokenRequest request = new DefaultAccessTokenRequest();
        request.set("username", "foo");
        request.setCurrentUri("urn:foo:bar");
        resource.setAccessTokenUri("http://localhost/oauth/token");
        assertThat(provider.obtainAccessToken(resource, request).getValue()).isEqualTo("FOO");
    }

}

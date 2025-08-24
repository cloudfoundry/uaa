package org.cloudfoundry.identity.uaa.oauth.client.token.grant;

import org.cloudfoundry.identity.uaa.oauth.client.grant.ImplicitAccessTokenProvider;
import org.cloudfoundry.identity.uaa.oauth.client.resource.ImplicitResourceDetails;
import org.cloudfoundry.identity.uaa.oauth.client.resource.OAuth2ProtectedResourceDetails;
import org.cloudfoundry.identity.uaa.oauth.common.DefaultOAuth2AccessToken;
import org.cloudfoundry.identity.uaa.oauth.common.DefaultOAuth2RefreshToken;
import org.cloudfoundry.identity.uaa.oauth.common.OAuth2AccessToken;
import org.cloudfoundry.identity.uaa.oauth.token.AccessTokenRequest;
import org.cloudfoundry.identity.uaa.oauth.token.DefaultAccessTokenRequest;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.http.client.MockClientHttpResponse;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import java.io.IOException;
import java.util.Collections;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatExceptionOfType;

/**
 * Moved test class of from spring-security-oauth2 into UAA
 * Scope: Test class
 */
class ImplicitAccessTokenProviderTests {

    private final MultiValueMap<String, String> params = new LinkedMultiValueMap<>();

    private final ImplicitAccessTokenProvider provider = new ImplicitAccessTokenProvider() {
        @Override
        protected OAuth2AccessToken retrieveToken(AccessTokenRequest request, OAuth2ProtectedResourceDetails resource,
                                                  MultiValueMap<String, String> form, HttpHeaders headers) {
            params.putAll(form);
            return new DefaultOAuth2AccessToken("FOO");
        }
    };

    private final ImplicitResourceDetails resource = new ImplicitResourceDetails();

    @Test
    void redirectNotSpecified() {
        AccessTokenRequest request = new DefaultAccessTokenRequest();
        assertThatExceptionOfType(IllegalStateException.class).isThrownBy(() ->
                provider.obtainAccessToken(resource, request));
    }

    @Test
    void supportsResource() {
        assertThat(provider.supportsResource(new ImplicitResourceDetails())).isTrue();
    }

    @Test
    void supportsRefresh() {
        assertThat(provider.supportsRefresh(new ImplicitResourceDetails())).isFalse();
    }

    @Test
    void refreshAccessToken() {
        assertThat(provider.refreshAccessToken(new ImplicitResourceDetails(), new DefaultOAuth2RefreshToken(""), new DefaultAccessTokenRequest(
                Collections.emptyMap()))).isNull();
    }

    @Test
    void implicitResponseExtractor() throws IOException {
        assertThat(provider.getResponseExtractor().extractData(new MockClientHttpResponse(new byte[0], 200))).isNull();
    }

    @Test
    void obtainAccessToken() {
        ImplicitResourceDetails details = new ImplicitResourceDetails();
        details.setScope(Set.of("openid").stream().toList());
        assertThat(details.isClientOnly()).isFalse();
        assertThat(provider.obtainAccessToken(details, new DefaultAccessTokenRequest(Map.of("scope", new String[]{"x"}, "redirect_uri",
                new String[]{"x"}, "client_id", new String[]{"x"})))).isNotNull();
    }

    @Test
    void obtainAccessTokenNoRecdirect() {
        ImplicitResourceDetails details = new ImplicitResourceDetails();
        details.setScope(Set.of("openid").stream().toList());
        assertThat(details.isClientOnly()).isFalse();
        assertThatExceptionOfType(IllegalStateException.class).isThrownBy(() ->
                assertThat(provider.obtainAccessToken(details, new DefaultAccessTokenRequest(Map.of("scope", new String[]{"x"}, "client_id", new String[]{"x"})))).isNotNull());
    }

    @Test
    void getAccessTokenRequest() {
        AccessTokenRequest request = new DefaultAccessTokenRequest();
        resource.setClientId("foo");
        resource.setAccessTokenUri("http://localhost/oauth/authorize");
        resource.setPreEstablishedRedirectUri("https://anywhere.com");
        assertThat(provider.obtainAccessToken(resource, request).getValue()).isEqualTo("FOO");
        assertThat(params.getFirst("client_id")).isEqualTo("foo");
        assertThat(params.getFirst("response_type")).isEqualTo("token");
        assertThat(params.getFirst("redirect_uri")).isEqualTo("https://anywhere.com");
    }

}

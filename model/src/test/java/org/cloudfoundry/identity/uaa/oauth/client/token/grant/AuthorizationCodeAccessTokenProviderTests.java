package org.cloudfoundry.identity.uaa.oauth.client.token.grant;

import org.cloudfoundry.identity.uaa.oauth.client.grant.AuthorizationCodeAccessTokenProvider;
import org.cloudfoundry.identity.uaa.oauth.client.resource.AuthorizationCodeResourceDetails;
import org.cloudfoundry.identity.uaa.oauth.client.resource.OAuth2ProtectedResourceDetails;
import org.cloudfoundry.identity.uaa.oauth.client.resource.UserRedirectRequiredException;
import org.cloudfoundry.identity.uaa.oauth.common.DefaultOAuth2AccessToken;
import org.cloudfoundry.identity.uaa.oauth.common.DefaultOAuth2RefreshToken;
import org.cloudfoundry.identity.uaa.oauth.common.OAuth2AccessToken;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.InvalidRequestException;
import org.cloudfoundry.identity.uaa.oauth.token.AccessTokenRequest;
import org.cloudfoundry.identity.uaa.oauth.token.DefaultAccessTokenRequest;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatExceptionOfType;

/**
 * Moved test class of from spring-security-oauth2 into UAA
 * Scope: Test class
 */
class AuthorizationCodeAccessTokenProviderTests {

    private final MultiValueMap<String, String> params = new LinkedMultiValueMap<>();

    private final AuthorizationCodeAccessTokenProvider provider = new AuthorizationCodeAccessTokenProvider() {
        @Override
        protected OAuth2AccessToken retrieveToken(AccessTokenRequest request, OAuth2ProtectedResourceDetails resource,
                                                  MultiValueMap<String, String> form, HttpHeaders headers) {
            params.putAll(form);
            return new DefaultOAuth2AccessToken("FOO");
        }
    };

    private final AuthorizationCodeResourceDetails resource = new AuthorizationCodeResourceDetails();

    @Test
    void supportsResource() {
        assertThat(provider.supportsResource(new AuthorizationCodeResourceDetails())).isTrue();
    }

    @Test
    void getUserApproval() {
        assertThat(provider.getUserApprovalSignal(new AuthorizationCodeResourceDetails())).isNotNull();
    }

    @Test
    void supportsRefresh() {
        assertThat(provider.supportsRefresh(new AuthorizationCodeResourceDetails())).isTrue();
    }

    @Test
    void refreshAccessToken() {
        assertThat(provider.refreshAccessToken(new AuthorizationCodeResourceDetails(), new DefaultOAuth2RefreshToken(""), new DefaultAccessTokenRequest(
                Collections.emptyMap())).getValue()).isEqualTo("FOO");
    }

    @Test
    void getAccessToken() {
        AccessTokenRequest request = new DefaultAccessTokenRequest();
        request.setAuthorizationCode("foo");
        request.setPreservedState(new Object());
        resource.setAccessTokenUri("http://localhost/oauth/token");
        assertThat(provider.obtainAccessToken(resource, request).getValue()).isEqualTo("FOO");
    }

    @Test
    void getCode() {
        AccessTokenRequest request = new DefaultAccessTokenRequest();
        request.setAuthorizationCode(null);
        request.setPreservedState(new Object());
        request.setStateKey("key");
        resource.setAccessTokenUri("http://localhost/oauth/token");
        assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() ->
                assertThat(provider.obtainAccessToken(resource, request).getValue()).isEqualTo("FOO"));
    }

    @Test
    void getAccessTokenFailsWithNoState() {
        AccessTokenRequest request = new DefaultAccessTokenRequest();
        request.setAuthorizationCode("foo");
        resource.setAccessTokenUri("http://localhost/oauth/token");
        assertThatExceptionOfType(InvalidRequestException.class).isThrownBy(() ->
                assertThat(provider.obtainAccessToken(resource, request).getValue()).isEqualTo("FOO"));
    }

    @Test
    void redirectToAuthorizationEndpoint() {
        AccessTokenRequest request = new DefaultAccessTokenRequest();
        request.setCurrentUri("/come/back/soon");
        resource.setUserAuthorizationUri("http://localhost/oauth/authorize");
        try {
            provider.obtainAccessToken(resource, request);
            fail("Expected UserRedirectRequiredException");
        } catch (UserRedirectRequiredException e) {
            assertThat(e.getRedirectUri()).isEqualTo("http://localhost/oauth/authorize");
            assertThat(e.getStateToPreserve()).isEqualTo("/come/back/soon");
        }
    }

    // A missing redirect just means the server has to deal with it
    @Test
    void redirectNotSpecified() {
        AccessTokenRequest request = new DefaultAccessTokenRequest();
        resource.setUserAuthorizationUri("http://localhost/oauth/authorize");
        assertThatExceptionOfType(UserRedirectRequiredException.class).isThrownBy(() ->
                provider.obtainAccessToken(resource, request));
    }

    @Test
    void getAccessTokenRequest() {
        AccessTokenRequest request = new DefaultAccessTokenRequest();
        request.setAuthorizationCode("foo");
        request.setStateKey("bar");
        request.setPreservedState(new Object());
        resource.setAccessTokenUri("http://localhost/oauth/token");
        resource.setPreEstablishedRedirectUri("https://anywhere.com");
        assertThat(provider.obtainAccessToken(resource, request).getValue()).isEqualTo("FOO");
        // System.err.println(params);
        assertThat(params.getFirst("grant_type")).isEqualTo("authorization_code");
        assertThat(params.getFirst("code")).isEqualTo("foo");
        assertThat(params.getFirst("redirect_uri")).isEqualTo("https://anywhere.com");
        // State is not set in token request
        assertThat(params.getFirst("state")).isNull();
    }
}

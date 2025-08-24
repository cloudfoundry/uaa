package org.cloudfoundry.identity.uaa.oauth.client;

import org.cloudfoundry.identity.uaa.oauth.client.http.AccessTokenRequiredException;
import org.cloudfoundry.identity.uaa.oauth.client.resource.BaseOAuth2ProtectedResourceDetails;
import org.cloudfoundry.identity.uaa.oauth.common.DefaultOAuth2AccessToken;
import org.cloudfoundry.identity.uaa.oauth.common.OAuth2AccessToken;
import org.junit.jupiter.api.Test;
import org.springframework.mock.http.client.MockClientHttpRequest;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatExceptionOfType;

/**
 * Moved test class of from spring-security-oauth2 into UAA
 * Scope: Test class
 */
class DefaultOAuth2RequestAuthenticatorTests {

    private final DefaultOAuth2RequestAuthenticator authenticator = new DefaultOAuth2RequestAuthenticator();

    private final MockClientHttpRequest request = new MockClientHttpRequest();

    private final DefaultOAuth2ClientContext context = new DefaultOAuth2ClientContext();

    @Test
    void missingAccessToken() {
        BaseOAuth2ProtectedResourceDetails resource = new BaseOAuth2ProtectedResourceDetails();
        assertThatExceptionOfType(AccessTokenRequiredException.class).isThrownBy(() ->
                authenticator.authenticate(resource, new DefaultOAuth2ClientContext(), request));
    }

    @Test
    void addsAccessToken() {
        context.setAccessToken(new DefaultOAuth2AccessToken("FOO"));
        BaseOAuth2ProtectedResourceDetails resource = new BaseOAuth2ProtectedResourceDetails();
        authenticator.authenticate(resource, context, request);
        String header = request.getHeaders().getFirst("Authorization");
        assertThat(header).isEqualTo("Bearer FOO");
    }

    // gh-1346
    @Test
    void authenticateWhenTokenTypeBearerUppercaseThenUseBearer() {
        DefaultOAuth2AccessToken accessToken = new DefaultOAuth2AccessToken("FOO");
        accessToken.setTokenType(OAuth2AccessToken.BEARER_TYPE.toUpperCase());
        context.setAccessToken(accessToken);
        BaseOAuth2ProtectedResourceDetails resource = new BaseOAuth2ProtectedResourceDetails();
        authenticator.authenticate(resource, context, request);
        String header = request.getHeaders().getFirst("Authorization");
        assertThat(header).isEqualTo("Bearer FOO");
    }

    // gh-1346
    @Test
    void authenticateWhenTokenTypeBearerLowercaseThenUseBearer() {
        DefaultOAuth2AccessToken accessToken = new DefaultOAuth2AccessToken("FOO");
        accessToken.setTokenType(OAuth2AccessToken.BEARER_TYPE.toLowerCase());
        context.setAccessToken(accessToken);
        BaseOAuth2ProtectedResourceDetails resource = new BaseOAuth2ProtectedResourceDetails();
        authenticator.authenticate(resource, context, request);
        String header = request.getHeaders().getFirst("Authorization");
        assertThat(header).isEqualTo("Bearer FOO");
    }

    // gh-1346
    @Test
    void authenticateWhenTokenTypeBearerMixcaseThenUseBearer() {
        DefaultOAuth2AccessToken accessToken = new DefaultOAuth2AccessToken("FOO");
        accessToken.setTokenType("BeaRer");
        context.setAccessToken(accessToken);
        BaseOAuth2ProtectedResourceDetails resource = new BaseOAuth2ProtectedResourceDetails();
        authenticator.authenticate(resource, context, request);
        String header = request.getHeaders().getFirst("Authorization");
        assertThat(header).isEqualTo("Bearer FOO");
    }

    // gh-1346
    @Test
    void authenticateWhenTokenTypeMACThenUseMAC() {
        DefaultOAuth2AccessToken accessToken = new DefaultOAuth2AccessToken("FOO");
        accessToken.setTokenType("MAC");
        context.setAccessToken(accessToken);
        BaseOAuth2ProtectedResourceDetails resource = new BaseOAuth2ProtectedResourceDetails();
        authenticator.authenticate(resource, context, request);
        String header = request.getHeaders().getFirst("Authorization");
        assertThat(header).isEqualTo("MAC FOO");
    }
}
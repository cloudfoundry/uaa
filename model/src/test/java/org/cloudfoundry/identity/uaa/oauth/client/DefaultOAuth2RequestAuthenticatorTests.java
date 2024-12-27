package org.cloudfoundry.identity.uaa.oauth.client;

import org.cloudfoundry.identity.uaa.oauth.client.http.AccessTokenRequiredException;
import org.cloudfoundry.identity.uaa.oauth.client.resource.BaseOAuth2ProtectedResourceDetails;
import org.cloudfoundry.identity.uaa.oauth.common.DefaultOAuth2AccessToken;
import org.cloudfoundry.identity.uaa.oauth.common.OAuth2AccessToken;
import org.junit.Test;
import org.springframework.mock.http.client.MockClientHttpRequest;

import static org.junit.Assert.assertEquals;

/**
 * Moved test class of from spring-security-oauth2 into UAA
 * Scope: Test class
 */
public class DefaultOAuth2RequestAuthenticatorTests {

    private final DefaultOAuth2RequestAuthenticator authenticator = new DefaultOAuth2RequestAuthenticator();

    private final MockClientHttpRequest request = new MockClientHttpRequest();

    private final DefaultOAuth2ClientContext context = new DefaultOAuth2ClientContext();

    @Test(expected = AccessTokenRequiredException.class)
    public void missingAccessToken() {
        BaseOAuth2ProtectedResourceDetails resource = new BaseOAuth2ProtectedResourceDetails();
        authenticator.authenticate(resource, new DefaultOAuth2ClientContext(), request);
    }

    @Test
    public void addsAccessToken() {
        context.setAccessToken(new DefaultOAuth2AccessToken("FOO"));
        BaseOAuth2ProtectedResourceDetails resource = new BaseOAuth2ProtectedResourceDetails();
        authenticator.authenticate(resource, context, request);
        String header = request.getHeaders().getFirst("Authorization");
        assertEquals("Bearer FOO", header);
    }

    // gh-1346
    @Test
    public void authenticateWhenTokenTypeBearerUppercaseThenUseBearer() {
        DefaultOAuth2AccessToken accessToken = new DefaultOAuth2AccessToken("FOO");
        accessToken.setTokenType(OAuth2AccessToken.BEARER_TYPE.toUpperCase());
        context.setAccessToken(accessToken);
        BaseOAuth2ProtectedResourceDetails resource = new BaseOAuth2ProtectedResourceDetails();
        authenticator.authenticate(resource, context, request);
        String header = request.getHeaders().getFirst("Authorization");
        assertEquals("Bearer FOO", header);
    }

    // gh-1346
    @Test
    public void authenticateWhenTokenTypeBearerLowercaseThenUseBearer() {
        DefaultOAuth2AccessToken accessToken = new DefaultOAuth2AccessToken("FOO");
        accessToken.setTokenType(OAuth2AccessToken.BEARER_TYPE.toLowerCase());
        context.setAccessToken(accessToken);
        BaseOAuth2ProtectedResourceDetails resource = new BaseOAuth2ProtectedResourceDetails();
        authenticator.authenticate(resource, context, request);
        String header = request.getHeaders().getFirst("Authorization");
        assertEquals("Bearer FOO", header);
    }

    // gh-1346
    @Test
    public void authenticateWhenTokenTypeBearerMixcaseThenUseBearer() {
        DefaultOAuth2AccessToken accessToken = new DefaultOAuth2AccessToken("FOO");
        accessToken.setTokenType("BeaRer");
        context.setAccessToken(accessToken);
        BaseOAuth2ProtectedResourceDetails resource = new BaseOAuth2ProtectedResourceDetails();
        authenticator.authenticate(resource, context, request);
        String header = request.getHeaders().getFirst("Authorization");
        assertEquals("Bearer FOO", header);
    }

    // gh-1346
    @Test
    public void authenticateWhenTokenTypeMACThenUseMAC() {
        DefaultOAuth2AccessToken accessToken = new DefaultOAuth2AccessToken("FOO");
        accessToken.setTokenType("MAC");
        context.setAccessToken(accessToken);
        BaseOAuth2ProtectedResourceDetails resource = new BaseOAuth2ProtectedResourceDetails();
        authenticator.authenticate(resource, context, request);
        String header = request.getHeaders().getFirst("Authorization");
        assertEquals("MAC FOO", header);
    }
}
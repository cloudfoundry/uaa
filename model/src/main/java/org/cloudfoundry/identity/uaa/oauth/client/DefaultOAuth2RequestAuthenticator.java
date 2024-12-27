package org.cloudfoundry.identity.uaa.oauth.client;

import org.cloudfoundry.identity.uaa.oauth.client.http.AccessTokenRequiredException;
import org.cloudfoundry.identity.uaa.oauth.client.resource.OAuth2ProtectedResourceDetails;
import org.cloudfoundry.identity.uaa.oauth.common.OAuth2AccessToken;
import org.springframework.http.client.ClientHttpRequest;
import org.springframework.util.StringUtils;

/**
 * Moved class implementation of from spring-security-oauth2 into UAA
 *
 * The class was taken over from the legacy project with minor refactorings
 * based on sonar.
 *
 * Scope: OAuth2 client
 */
public class DefaultOAuth2RequestAuthenticator implements OAuth2RequestAuthenticator {

    @Override
    public void authenticate(OAuth2ProtectedResourceDetails resource, OAuth2ClientContext clientContext,
            ClientHttpRequest request) {
        OAuth2AccessToken accessToken = clientContext.getAccessToken();
        if (accessToken == null) {
            throw new AccessTokenRequiredException(resource);
        }
        String tokenType = accessToken.getTokenType();
        if (!StringUtils.hasText(tokenType) || tokenType.equalsIgnoreCase(OAuth2AccessToken.BEARER_TYPE)) {
            tokenType = OAuth2AccessToken.BEARER_TYPE;
        }
        request.getHeaders().set("Authorization", "%s %s".formatted(tokenType, accessToken.getValue()));
    }

}

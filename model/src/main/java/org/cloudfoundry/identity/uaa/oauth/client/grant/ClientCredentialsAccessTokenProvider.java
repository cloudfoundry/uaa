package org.cloudfoundry.identity.uaa.oauth.client.grant;

import org.cloudfoundry.identity.uaa.oauth.client.resource.ClientCredentialsResourceDetails;
import org.cloudfoundry.identity.uaa.oauth.client.resource.OAuth2AccessDeniedException;
import org.cloudfoundry.identity.uaa.oauth.client.resource.OAuth2ProtectedResourceDetails;
import org.cloudfoundry.identity.uaa.oauth.client.resource.UserRedirectRequiredException;
import org.cloudfoundry.identity.uaa.oauth.common.OAuth2AccessToken;
import org.cloudfoundry.identity.uaa.oauth.common.OAuth2RefreshToken;
import org.cloudfoundry.identity.uaa.oauth.common.util.OAuth2Utils;
import org.cloudfoundry.identity.uaa.oauth.token.AccessTokenProvider;
import org.cloudfoundry.identity.uaa.oauth.token.AccessTokenRequest;
import org.cloudfoundry.identity.uaa.oauth.token.OAuth2AccessTokenSupport;
import org.springframework.http.HttpHeaders;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

/**
 * Moved class implementation of from spring-security-oauth2 into UAA
 *
 * The class was taken over from the legacy project with minor refactorings
 * based on sonar.
 *
 * Scope: OAuth2 client
 */
public class ClientCredentialsAccessTokenProvider extends OAuth2AccessTokenSupport implements AccessTokenProvider {

    public boolean supportsResource(OAuth2ProtectedResourceDetails resource) {
        return resource instanceof ClientCredentialsResourceDetails
                && "client_credentials".equals(resource.getGrantType());
    }

    public boolean supportsRefresh(OAuth2ProtectedResourceDetails resource) {
        return false;
    }

    public OAuth2AccessToken refreshAccessToken(OAuth2ProtectedResourceDetails resource,
            OAuth2RefreshToken refreshToken, AccessTokenRequest request) throws UserRedirectRequiredException {
        return null;
    }

    public OAuth2AccessToken obtainAccessToken(OAuth2ProtectedResourceDetails details, AccessTokenRequest request)
            throws UserRedirectRequiredException, AccessDeniedException, OAuth2AccessDeniedException {

        ClientCredentialsResourceDetails resource = (ClientCredentialsResourceDetails) details;
        return retrieveToken(request, resource, getParametersForTokenRequest(resource), new HttpHeaders());

    }

    private MultiValueMap<String, String> getParametersForTokenRequest(ClientCredentialsResourceDetails resource) {

        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.set(OAuth2Utils.GRANT_TYPE, "client_credentials");

        if (resource.isScoped()) {
            form.set(OAuth2Utils.SCOPE, getScopeString(resource));
        }

        return form;

    }

}

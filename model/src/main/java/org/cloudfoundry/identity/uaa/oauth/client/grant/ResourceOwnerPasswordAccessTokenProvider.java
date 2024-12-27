package org.cloudfoundry.identity.uaa.oauth.client.grant;

import org.cloudfoundry.identity.uaa.oauth.client.resource.OAuth2AccessDeniedException;
import org.cloudfoundry.identity.uaa.oauth.client.resource.OAuth2ProtectedResourceDetails;
import org.cloudfoundry.identity.uaa.oauth.client.resource.ResourceOwnerPasswordResourceDetails;
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
public class ResourceOwnerPasswordAccessTokenProvider extends OAuth2AccessTokenSupport implements AccessTokenProvider {

    private static final String PASSWORD = "password";

    public boolean supportsResource(OAuth2ProtectedResourceDetails resource) {
        return resource instanceof ResourceOwnerPasswordResourceDetails && PASSWORD.equals(resource.getGrantType());
    }

    public boolean supportsRefresh(OAuth2ProtectedResourceDetails resource) {
        return supportsResource(resource);
    }

    public OAuth2AccessToken refreshAccessToken(OAuth2ProtectedResourceDetails resource,
            OAuth2RefreshToken refreshToken, AccessTokenRequest request) throws UserRedirectRequiredException, OAuth2AccessDeniedException {
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add(OAuth2Utils.GRANT_TYPE, "refresh_token");
        form.add("refresh_token", refreshToken.getValue());
        return retrieveToken(request, resource, form, new HttpHeaders());
    }

    public OAuth2AccessToken obtainAccessToken(OAuth2ProtectedResourceDetails details, AccessTokenRequest request)
            throws UserRedirectRequiredException, AccessDeniedException, OAuth2AccessDeniedException {

        ResourceOwnerPasswordResourceDetails resource = (ResourceOwnerPasswordResourceDetails) details;
        return retrieveToken(request, resource, getParametersForTokenRequest(resource, request), new HttpHeaders());

    }

    private MultiValueMap<String, String> getParametersForTokenRequest(ResourceOwnerPasswordResourceDetails resource, AccessTokenRequest request) {

        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.set(OAuth2Utils.GRANT_TYPE, PASSWORD);

        form.set("username", resource.getUsername());
        form.set(PASSWORD, resource.getPassword());
        form.putAll(request);

        if (resource.isScoped()) {
            form.set(OAuth2Utils.SCOPE, getScopeString(resource));
        }

        return form;

    }

}

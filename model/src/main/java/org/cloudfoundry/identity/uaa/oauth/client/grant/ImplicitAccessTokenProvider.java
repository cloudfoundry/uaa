package org.cloudfoundry.identity.uaa.oauth.client.grant;

import org.cloudfoundry.identity.uaa.oauth.client.resource.ImplicitResourceDetails;
import org.cloudfoundry.identity.uaa.oauth.client.resource.OAuth2AccessDeniedException;
import org.cloudfoundry.identity.uaa.oauth.client.resource.OAuth2ProtectedResourceDetails;
import org.cloudfoundry.identity.uaa.oauth.client.resource.UserRedirectRequiredException;
import org.cloudfoundry.identity.uaa.oauth.common.DefaultOAuth2AccessToken;
import org.cloudfoundry.identity.uaa.oauth.common.OAuth2AccessToken;
import org.cloudfoundry.identity.uaa.oauth.common.OAuth2RefreshToken;
import org.cloudfoundry.identity.uaa.oauth.common.util.OAuth2Utils;
import org.cloudfoundry.identity.uaa.oauth.token.AccessTokenProvider;
import org.cloudfoundry.identity.uaa.oauth.token.AccessTokenRequest;
import org.cloudfoundry.identity.uaa.oauth.token.OAuth2AccessTokenSupport;
import org.springframework.http.HttpHeaders;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.ResponseExtractor;

import java.io.IOException;
import java.net.URI;
import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * Moved class implementation of from spring-security-oauth2 into UAA
 *
 * The class was taken over from the legacy project with minor refactorings
 * based on sonar.
 *
 * Scope: OAuth2 client
 */
public class ImplicitAccessTokenProvider extends OAuth2AccessTokenSupport implements AccessTokenProvider {

    public boolean supportsResource(OAuth2ProtectedResourceDetails resource) {
        return resource instanceof ImplicitResourceDetails && "implicit".equals(resource.getGrantType());
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

        ImplicitResourceDetails resource = (ImplicitResourceDetails) details;
        try {
            // We can assume here that the request contains all the parameters needed for authentication etc.
            OAuth2AccessToken token = retrieveToken(request,
                    resource, getParametersForTokenRequest(resource, request), getHeadersForTokenRequest(request));
            if (token == null) {
                throw new UserRedirectRequiredException(resource.getUserAuthorizationUri(), request.toSingleValueMap());
            }
            return token;
        }
        catch (UserRedirectRequiredException e) {
            // ... but if it doesn't then capture the request parameters for the redirect
            throw new UserRedirectRequiredException(e.getRedirectUri(), request.toSingleValueMap());
        }

    }

    @Override
    public ResponseExtractor<OAuth2AccessToken> getResponseExtractor() {
        return new ImplicitResponseExtractor();
    }

    private HttpHeaders getHeadersForTokenRequest(AccessTokenRequest request) {
        HttpHeaders headers = new HttpHeaders();
        headers.putAll(request.getHeaders());
        if (request.getCookie() != null) {
            headers.set("Cookie", request.getCookie());
        }
        return headers;
    }

    private MultiValueMap<String, String> getParametersForTokenRequest(ImplicitResourceDetails resource,
            AccessTokenRequest request) {

        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.set("response_type", "token");
        form.set("client_id", resource.getClientId());

        if (resource.isScoped()) {
            form.set(OAuth2Utils.SCOPE, getScopeString(resource));
        }

        for (Map.Entry<String, List<String>> entry : request.entrySet()) {
            form.put(entry.getKey(), entry.getValue());
        }

        String redirectUri = resource.getRedirectUri(request);
        if (redirectUri == null) {
            throw new IllegalStateException("No redirect URI available in request");
        }
        form.set("redirect_uri", redirectUri);

        return form;

    }

    private final class ImplicitResponseExtractor implements ResponseExtractor<OAuth2AccessToken> {
        public OAuth2AccessToken extractData(ClientHttpResponse response) throws IOException {
            URI location = response.getHeaders().getLocation();
            if (location == null) {
                return null;
            }
            String fragment = location.getFragment();
            OAuth2AccessToken accessToken = DefaultOAuth2AccessToken.valueOf(OAuth2Utils.extractMap(fragment));
            if (accessToken.getValue() == null) {
                throw new UserRedirectRequiredException(location.toString(), Collections.<String, String>emptyMap());
            }

            return accessToken;
        }
    }

}

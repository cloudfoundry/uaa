package org.cloudfoundry.identity.uaa.oauth.token.auth;

import org.cloudfoundry.identity.uaa.oauth.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.http.HttpHeaders;
import org.springframework.util.MultiValueMap;

/**
 * Moved class implementation of from spring-security-oauth2 into UAA
 *
 * The class was taken over from the legacy project with minor refactorings
 * based on sonar.
 *
 * Scope: OAuth2 server
 */
public interface ClientAuthenticationHandler {

    /**
     * Authenticate a token request.
     * 
     * @param resource The resource for which to authenticate a request.
     * @param form The form that is being submitted as the token request.
     * @param headers The request headers to be submitted.
     */
    void authenticateTokenRequest(OAuth2ProtectedResourceDetails resource, MultiValueMap<String, String> form,
            HttpHeaders headers);
}

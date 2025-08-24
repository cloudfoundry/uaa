package org.cloudfoundry.identity.uaa.oauth.provider.authentication;

import org.springframework.security.core.Authentication;

import jakarta.servlet.http.HttpServletRequest;

/**
 * Moved class implementation of from spring-security-oauth2 into UAA
 *
 * The class was taken over from the legacy project with minor refactorings
 * based on sonar.
 *
 * Scope: OAuth2 server
 */
public interface TokenExtractor {

    /**
     * Extract a token value from an incoming request without authentication.
     * 
     * @param request the current ServletRequest
     * @return an authentication token whose principal is an access token (or null if there is none)
     */
    Authentication extract(HttpServletRequest request);

}

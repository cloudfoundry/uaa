package org.cloudfoundry.identity.uaa.oauth.provider.endpoint;

import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetails;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.OAuth2Exception;

/**
 * Moved class implementation of from spring-security-oauth2 into UAA
 *
 * The class was taken over from the legacy project with minor refactorings
 * based on sonar.
 *
 * Scope: OAuth2 server token endpoint
 */
public interface RedirectResolver {

    /**
     * Resolve the redirect for the specified client.
     *
     * @param requestedRedirect The redirect that was requested (may not be null).
     * @param client The client for which we're resolving the redirect.
     * @return The resolved redirect URI.
     * @throws OAuth2Exception If the requested redirect is invalid for the specified client.
     */
    String resolveRedirect(String requestedRedirect, ClientDetails client) throws OAuth2Exception;

}

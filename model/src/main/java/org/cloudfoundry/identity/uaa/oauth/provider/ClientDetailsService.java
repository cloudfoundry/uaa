package org.cloudfoundry.identity.uaa.oauth.provider;

import org.cloudfoundry.identity.uaa.provider.ClientRegistrationException;

/**
 * Moved class implementation of from spring-security-oauth2 into UAA
 *
 * The class was taken over from the legacy project with minor refactorings
 * based on sonar.
 *
 * Scope: OAuth2 framework
 */
public interface ClientDetailsService {

    /**
     * Load a client by the client id. This method must not return null.
     *
     * @param clientId The client id.
     * @return The client details (never null).
     * @throws ClientRegistrationException If the client account is locked, expired, disabled, or invalid for any other reason.
     */
    ClientDetails loadClientByClientId(String clientId) throws ClientRegistrationException;

}
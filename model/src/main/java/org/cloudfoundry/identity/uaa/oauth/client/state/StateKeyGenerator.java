package org.cloudfoundry.identity.uaa.oauth.client.state;

import org.cloudfoundry.identity.uaa.oauth.client.resource.OAuth2ProtectedResourceDetails;

/**
 * Moved class implementation of from spring-security-oauth2 into UAA
 *
 * The class was taken over from the legacy project with minor refactorings
 * based on sonar.
 *
 * Scope: OAuth2 client
 */
public interface StateKeyGenerator {

    /**
     * Generate a key.
     * 
     * @param resource the resource to generate the key for
     * @return a unique key for the state.  Never null.
     */
    String generateKey(OAuth2ProtectedResourceDetails resource);

}

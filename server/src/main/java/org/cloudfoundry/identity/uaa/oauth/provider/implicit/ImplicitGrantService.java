package org.cloudfoundry.identity.uaa.oauth.provider.implicit;

import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Request;
import org.cloudfoundry.identity.uaa.oauth.provider.TokenRequest;

/**
 * Moved class implementation of from spring-security-oauth2 into UAA
 *
 * The class was taken over from the legacy project with minor refactorings
 * based on sonar.
 *
 * Scope: OAuth2 server
 */
public interface ImplicitGrantService {

    /**
     * Save an association between an OAuth2Request and a TokenRequest.
     * 
     * @param originalRequest
     * @param tokenRequest
     */
    public void store(OAuth2Request originalRequest, TokenRequest tokenRequest);

    /**
     * Look up and return the OAuth2Request associated with the given TokenRequest.
     * 
     * @param tokenRequest
     * @return
     */
    public OAuth2Request remove(TokenRequest tokenRequest);

}

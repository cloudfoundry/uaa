package org.cloudfoundry.identity.uaa.oauth.provider;

import org.cloudfoundry.identity.uaa.oauth.common.OAuth2AccessToken;

/**
 * Moved class implementation of from spring-security-oauth2 into UAA
 *
 * The class was taken over from the legacy project with minor refactorings
 * based on sonar.
 *
 * Scope: OAuth2 server
 */
public interface TokenGranter {

    OAuth2AccessToken grant(String grantType, TokenRequest tokenRequest);

}

package org.cloudfoundry.identity.uaa.oauth.common;

import java.util.Date;

/**
 * Moved class implementation of from spring-security-oauth2 into UAA
 *
 * The class was taken over from the legacy project with minor refactorings
 * based on sonar.
 *
 * Scope: OAuth2 server
 */
public interface ExpiringOAuth2RefreshToken extends OAuth2RefreshToken {

    Date getExpiration();

}

package org.cloudfoundry.identity.uaa.oauth.provider.token;

/**
 * Moved class implementation of from spring-security-oauth2 into UAA
 *
 * The class was taken over from the legacy project with minor refactorings
 * based on sonar.
 *
 * Scope: OAuth2 server
 */
public interface ConsumerTokenServices {

    boolean revokeToken(String tokenValue);

}

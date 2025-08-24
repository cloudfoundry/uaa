package org.cloudfoundry.identity.uaa.oauth.common.exceptions;

/**
 * Moved class implementation of from spring-security-oauth2 into UAA
 *
 * The class was taken over from the legacy project with minor refactorings
 * based on sonar.
 *
 * Scope: OAuth2 exceptions
 */
@SuppressWarnings("serial")
public class BadClientCredentialsException extends ClientAuthenticationException {

    public BadClientCredentialsException() {
        super("Bad client credentials"); // Don't reveal source of error
    }

    @Override
    public int getHttpErrorCode() {
        return 401;
    }

    @Override
    public String getOAuth2ErrorCode() {
        return INVALID_CLIENT;
    }
}

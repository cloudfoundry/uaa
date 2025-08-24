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
public abstract class ClientAuthenticationException extends OAuth2Exception {

    protected ClientAuthenticationException(String msg, Throwable t) {
        super(msg, t);
    }

    protected ClientAuthenticationException(String msg) {
        super(msg);
    }

    @Override
    public int getHttpErrorCode() {
        // The spec says this is a bad request (not unauthorized)
        return 400;
    }

    @Override
    public abstract String getOAuth2ErrorCode();
}

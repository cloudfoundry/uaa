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
public class UnauthorizedClientException extends ClientAuthenticationException {

    public UnauthorizedClientException(String msg, Throwable t) {
        super(msg, t);
    }

    public UnauthorizedClientException(String msg) {
        super(msg);
    }

    @Override
    public int getHttpErrorCode() {
        // The spec says this can be unauthorized
        return 401;
    }

    @Override
    public String getOAuth2ErrorCode() {
        return UNAUTHORIZED_CLIENT;
    }
}

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
public class UserDeniedAuthorizationException extends OAuth2Exception {

    public UserDeniedAuthorizationException(String msg) {
        super(msg);
    }

    @Override
    public String getOAuth2ErrorCode() {
        return ACCESS_DENIED;
    }

}

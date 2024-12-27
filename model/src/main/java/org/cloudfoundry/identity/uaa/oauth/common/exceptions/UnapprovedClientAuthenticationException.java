package org.cloudfoundry.identity.uaa.oauth.common.exceptions;

import org.springframework.security.authentication.InsufficientAuthenticationException;

/**
 * Moved class implementation of from spring-security-oauth2 into UAA
 *
 * The class was taken over from the legacy project with minor refactorings
 * based on sonar.
 *
 * Scope: OAuth2 exceptions
 */
@SuppressWarnings("serial")
public class UnapprovedClientAuthenticationException extends InsufficientAuthenticationException {
    public UnapprovedClientAuthenticationException(String msg, Throwable t) {
        super(msg, t);
    }
}

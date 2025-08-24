package org.cloudfoundry.identity.uaa.oauth.common.exceptions;

import org.cloudfoundry.identity.uaa.oauth.common.util.OAuth2Utils;

import java.util.Set;

/**
 * Moved class implementation of from spring-security-oauth2 into UAA
 *
 * The class was taken over from the legacy project with minor refactorings
 * based on sonar.
 *
 * Scope: OAuth2 exceptions
 */
@SuppressWarnings("serial")
public class InsufficientScopeException extends OAuth2Exception {

    public InsufficientScopeException(String msg, Set<String> validScope) {
        this(msg);
        addAdditionalInformation("scope", OAuth2Utils.formatParameterList(validScope));
    }

    public InsufficientScopeException(String msg) {
        super(msg);
    }

    @Override
    public int getHttpErrorCode() {
        return 403;
    }

    @Override
    public String getOAuth2ErrorCode() {
        // Not defined in the spec, so not really an OAuth2Exception
        return INSUFFICIENT_SCOPE;
    }

}
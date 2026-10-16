package org.cloudfoundry.identity.uaa.oauth.common.exceptions;

/**
 * RFC 8707 section 2: the error code an authorization server returns when a {@code resource}
 * request parameter is missing, malformed, unknown, or not one the authenticated client is
 * permitted to request.
 */
@SuppressWarnings("serial")
public class InvalidTargetException extends ClientAuthenticationException {

    public InvalidTargetException(String msg) {
        super(msg);
    }

    @Override
    public String getOAuth2ErrorCode() {
        return INVALID_TARGET;
    }
}

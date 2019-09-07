package org.cloudfoundry.identity.uaa.mfa.exception;

import org.springframework.security.core.AuthenticationException;

public class InvalidMfaCodeException extends AuthenticationException {
    public InvalidMfaCodeException(String msg, Throwable t) {
        super(msg, t);
    }

    public InvalidMfaCodeException(String msg) {
        super(msg);
    }
}

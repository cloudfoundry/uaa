package org.cloudfoundry.identity.uaa.mfa.exception;

import org.springframework.security.core.AuthenticationException;

public class MissingMfaCodeException extends AuthenticationException  {
    public MissingMfaCodeException(String explanation) {
        super(explanation);
    }
}

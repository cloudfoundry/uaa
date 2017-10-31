package org.cloudfoundry.identity.uaa.authentication;

import org.springframework.security.core.AuthenticationException;

public class MfaAuthenticationRequiredException extends AuthenticationException {
    private final UaaAuthentication authentication;

    public MfaAuthenticationRequiredException(UaaAuthentication authentication, String msg) {
        super(msg);
        this.authentication = authentication;
    }

    public UaaAuthentication getAuthentication() {
        return authentication;
    }
}

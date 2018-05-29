package org.cloudfoundry.identity.uaa.authentication;

import org.springframework.security.core.AuthenticationException;

public class EmailDomainNotAllowedException extends AuthenticationException {
    public EmailDomainNotAllowedException(String msg, Throwable t) {
        super(msg, t);
    }

    public EmailDomainNotAllowedException(String msg) {
        super(msg);
    }
}

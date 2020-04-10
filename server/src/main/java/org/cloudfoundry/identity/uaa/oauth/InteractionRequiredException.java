package org.cloudfoundry.identity.uaa.oauth;

import org.springframework.security.core.AuthenticationException;

public class InteractionRequiredException extends AuthenticationException {
    public InteractionRequiredException(String msg) {
        super(msg);
    }
}

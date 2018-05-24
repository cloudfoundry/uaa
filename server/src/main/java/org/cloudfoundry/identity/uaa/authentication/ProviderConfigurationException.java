package org.cloudfoundry.identity.uaa.authentication;

import org.springframework.security.core.AuthenticationException;

public class ProviderConfigurationException extends AuthenticationException {
    public ProviderConfigurationException(String msg, Throwable t) {
        super(msg, t);
    }

    public ProviderConfigurationException(String msg) {
        super(msg);
    }
}

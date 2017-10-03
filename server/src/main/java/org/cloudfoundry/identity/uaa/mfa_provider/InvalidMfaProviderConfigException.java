package org.cloudfoundry.identity.uaa.mfa_provider;

public class InvalidMfaProviderConfigException extends Exception {
    public InvalidMfaProviderConfigException(String message) {
        super(message);
    }
}

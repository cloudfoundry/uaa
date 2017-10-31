package org.cloudfoundry.identity.uaa.mfa_provider.exception;

public class InvalidMfaProviderConfigException extends Exception {
    public InvalidMfaProviderConfigException(String message) {
        super(message);
    }
}

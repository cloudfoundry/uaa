package org.cloudfoundry.identity.uaa.mfa.exception;

public class InvalidMfaProviderConfigException extends Exception {
    public InvalidMfaProviderConfigException(String message) {
        super(message);
    }
}

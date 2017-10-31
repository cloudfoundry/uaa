package org.cloudfoundry.identity.uaa.mfa_provider.exception;

public class UserMfaConfigDoesNotExistException extends RuntimeException {
    public UserMfaConfigDoesNotExistException(String message) {
        super(message);
    }
}

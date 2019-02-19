package org.cloudfoundry.identity.uaa.mfa.exception;

public class UserMfaConfigDoesNotExistException extends RuntimeException {
    public UserMfaConfigDoesNotExistException(String message) {
        super(message);
    }
}

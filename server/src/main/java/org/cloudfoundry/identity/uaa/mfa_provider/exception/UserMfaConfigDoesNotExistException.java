package org.cloudfoundry.identity.uaa.mfa_provider.exception;

import org.cloudfoundry.identity.uaa.error.UaaException;

public class UserMfaConfigDoesNotExistException extends RuntimeException {
    public UserMfaConfigDoesNotExistException(String message) {
        super(message);
    }
}

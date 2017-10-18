package org.cloudfoundry.identity.uaa.mfa_provider.exception;

import org.cloudfoundry.identity.uaa.error.UaaException;

public class UserMfaConfigAlreadyExistsException extends RuntimeException {
    public UserMfaConfigAlreadyExistsException(String message) {
        super(message);
    }
}

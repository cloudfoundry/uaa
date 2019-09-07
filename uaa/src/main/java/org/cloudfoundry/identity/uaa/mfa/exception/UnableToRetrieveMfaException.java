package org.cloudfoundry.identity.uaa.mfa.exception;

public class UnableToRetrieveMfaException extends RuntimeException {
    public UnableToRetrieveMfaException(Throwable cause) {
        super(cause);
    }
}

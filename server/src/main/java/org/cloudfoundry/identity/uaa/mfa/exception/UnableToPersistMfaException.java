package org.cloudfoundry.identity.uaa.mfa.exception;

public class UnableToPersistMfaException extends RuntimeException {
    public UnableToPersistMfaException(Throwable cause) {
        super(cause);
    }
}

package org.cloudfoundry.identity.uaa.mfa.exception;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.cloudfoundry.identity.uaa.error.UaaException;
import org.springframework.http.HttpStatus;

public class InvalidMfaProviderException extends UaaException {

    public final Logger logger = LoggerFactory.getLogger(InvalidMfaProviderException.class);
    public InvalidMfaProviderException(String message) {
        super("invalid_mfa_provider", message, HttpStatus.UNPROCESSABLE_ENTITY.value());
        logger.debug("MfaProvider validation error. " + message);
    }
}

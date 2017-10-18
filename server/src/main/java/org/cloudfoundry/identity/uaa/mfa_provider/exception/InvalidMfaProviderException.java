package org.cloudfoundry.identity.uaa.mfa_provider.exception;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.error.UaaException;
import org.springframework.http.HttpStatus;

public class InvalidMfaProviderException extends UaaException {

    public final Log logger = LogFactory.getLog(InvalidMfaProviderException.class);
    public InvalidMfaProviderException(String message) {
        super("invalid_mfa_provider", message, HttpStatus.UNPROCESSABLE_ENTITY.value());
        logger.debug("MfaProvider validation error. " + message);
    }
}

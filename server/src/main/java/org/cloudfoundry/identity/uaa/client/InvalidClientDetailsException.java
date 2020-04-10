
package org.cloudfoundry.identity.uaa.client;

import org.cloudfoundry.identity.uaa.error.UaaException;

/**
 * @author Luke Taylor
 */
public class InvalidClientDetailsException extends UaaException {
    public InvalidClientDetailsException(String message) {
        super("invalid_client", message, 400);
    }

    public InvalidClientDetailsException(String message, Throwable cause) {
        super(cause, "invalid_client", message, 400);
    }

}

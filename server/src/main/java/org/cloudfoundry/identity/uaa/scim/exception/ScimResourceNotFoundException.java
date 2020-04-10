
package org.cloudfoundry.identity.uaa.scim.exception;

import org.springframework.http.HttpStatus;

/**
 * Unchecked exception signalling that a user account could not be found.
 * 
 * @author Dave Syer
 * 
 */
public class ScimResourceNotFoundException extends ScimException {

    /**
     * @param message a message for the caller
     */
    public ScimResourceNotFoundException(String message) {
        super(message, HttpStatus.NOT_FOUND);
    }

}

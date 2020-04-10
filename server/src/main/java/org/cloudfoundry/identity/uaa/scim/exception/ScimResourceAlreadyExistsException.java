
package org.cloudfoundry.identity.uaa.scim.exception;

import org.springframework.http.HttpStatus;

import java.util.Map;

/**
 * Unchecked exception signalling that a user account already exists.
 * 
 * @author Dave Syer
 * 
 */
public class ScimResourceAlreadyExistsException extends ScimException {

    /**
     * @param message a message for the caller
     */
    public ScimResourceAlreadyExistsException(String message) {
        super(message, HttpStatus.CONFLICT);
    }

    public ScimResourceAlreadyExistsException(String message, Map<String,Object> extraInformation) {
        super(message, HttpStatus.CONFLICT, extraInformation);
    }

}

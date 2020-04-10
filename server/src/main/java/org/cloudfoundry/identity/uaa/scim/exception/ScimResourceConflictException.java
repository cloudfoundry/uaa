
package org.cloudfoundry.identity.uaa.scim.exception;

import org.springframework.http.HttpStatus;

/**
 * Unchecked exception to signal that a user has a conflict on update (e.g.
 * optimistic locking).
 * 
 * @author Dave Syer
 * 
 */
public class ScimResourceConflictException extends ScimException {

    /**
     * @param message a message for the caller
     */
    public ScimResourceConflictException(String message) {
        super(message, HttpStatus.CONFLICT);
    }

}

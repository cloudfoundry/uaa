package org.cloudfoundry.identity.uaa.scim.groups;

import org.cloudfoundry.identity.uaa.scim.ScimException;
import org.springframework.http.HttpStatus;

public class InvalidGroupException extends ScimException {

    public InvalidGroupException (String message) {
        super(message, HttpStatus.BAD_REQUEST);
    }
}

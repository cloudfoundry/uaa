package org.cloudfoundry.identity.uaa.scim.groups;

import org.cloudfoundry.identity.uaa.scim.ScimException;
import org.springframework.http.HttpStatus;

public class GroupAlreadyExistsException extends ScimException {

    public GroupAlreadyExistsException (String message) {
        super(message, HttpStatus.CONFLICT);
    }
}

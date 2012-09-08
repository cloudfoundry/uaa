package org.cloudfoundry.identity.uaa.scim.groups;

import org.cloudfoundry.identity.uaa.scim.ScimException;
import org.springframework.http.HttpStatus;

public class GroupNotFoundException extends ScimException {

    public GroupNotFoundException (String message) {
        super(message, HttpStatus.NOT_FOUND);
    }
}

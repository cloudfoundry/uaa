package org.cloudfoundry.identity.uaa.scim.groups;

import org.cloudfoundry.identity.uaa.scim.ScimException;
import org.springframework.http.HttpStatus;

public class MemberAlreadyExistsException extends ScimException {

    public MemberAlreadyExistsException(String message) {
        super(message, HttpStatus.CONFLICT);
    }
}

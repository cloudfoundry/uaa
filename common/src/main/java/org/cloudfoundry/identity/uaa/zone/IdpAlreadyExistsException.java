package org.cloudfoundry.identity.uaa.zone;

import org.cloudfoundry.identity.uaa.error.UaaException;

public class IdpAlreadyExistsException extends UaaException {

    public IdpAlreadyExistsException(String msg) {
        super("zone_exists", msg, 409);
    }
}

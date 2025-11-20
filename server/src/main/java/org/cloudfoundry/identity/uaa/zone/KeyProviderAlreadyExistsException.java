package org.cloudfoundry.identity.uaa.zone;

import org.cloudfoundry.identity.uaa.error.UaaException;

public class KeyProviderAlreadyExistsException extends UaaException{

    public KeyProviderAlreadyExistsException(String msg) {
        super(msg);
    }
}

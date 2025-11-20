package org.cloudfoundry.identity.uaa.zone;

import org.cloudfoundry.identity.uaa.error.UaaException;

public class KeyProviderNotFoundException extends UaaException {

    public KeyProviderNotFoundException(String msg) {
        super(msg);
    }
}

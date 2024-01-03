package org.cloudfoundry.identity.uaa.provider;

import org.cloudfoundry.identity.uaa.error.UaaException;

public class IdpMirroringFailedException extends UaaException {
    public IdpMirroringFailedException(final String msg, final Throwable t) {
        super(msg, t);
    }
}

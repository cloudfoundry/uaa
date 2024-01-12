package org.cloudfoundry.identity.uaa.provider;

import org.cloudfoundry.identity.uaa.error.UaaException;

public class IdpAliasFailedException extends UaaException {
    public IdpAliasFailedException(final String msg, final Throwable t) {
        super(msg, t);
    }
}
